package internal

import (
	"net"
	"strings"
	"testing"

	"ad-cleanser/internal/blacklist"
)

func TestIsSelf(t *testing.T) {
	tests := []struct {
		listen, upstream string
		want             bool
	}{
		{":53", "127.0.0.1:53", true},
		{"0.0.0.0:53", "127.0.0.1:53", true},
		{"[::]:53", "[::1]:53", true},
		{":53", "127.0.0.1:5353", false},
		{"127.0.0.1:53", "127.0.0.1:53", true},
		{"127.0.0.1:53", "8.8.8.8:53", false},
		{":53", "8.8.8.8:53", false},
	}
	for _, tc := range tests {
		l, _ := net.ResolveUDPAddr("udp", tc.listen)
		u, _ := net.ResolveUDPAddr("udp", tc.upstream)
		got, err := isSelf(l, u)
		if err != nil || got != tc.want {
			t.Errorf("isSelf(%s,%s)=%v,%v want %v", tc.listen, tc.upstream, got, err, tc.want)
		}
	}
}

func dnsQuery(id byte, flags byte, name string) []byte {
	q := []byte{0, id, flags, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func rcode(b []byte) byte { return b[3] & 0xF }

func TestResolve(t *testing.T) {
	// Mock upstream: echoes the query with QR set.
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, a, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			r := append([]byte{}, buf[:n]...)
			r[2] |= 0x80
			up.WriteTo(r, a)
		}
	}()
	dead, err := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()

	mk := func(u net.PacketConn) *Cleanser {
		return &Cleanser{upstream: u.LocalAddr().(*net.UDPAddr), blacklist: blacklist.New([]string{"ads.example.com"}, nil)}
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	good := dnsQuery(1, 0x01, "ok.example.com")

	tests := []struct {
		name     string
		c        *Cleanser
		query    []byte
		wantNil  bool
		wantCode int
		wantEcho bool
	}{
		{"malformed", mk(up), []byte{1, 2, 3}, true, 0, false}, // too short for any reply
		{"response packet", mk(up), dnsQuery(2, 0x81, "ok.example.com"), true, 0, false},
		{"bad opcode", mk(up), dnsQuery(3, 0x09, "ok.example.com"), false, 4, false},
		{"blocked", mk(up), dnsQuery(4, 0x01, "ads.example.com"), false, 3, false},
		{"forward", mk(up), good, false, 0, true},
		{"bad question", mk(up), []byte{0, 9, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 1, 0, 1}, false, 1, false},
		{"timeout", mk(dead), good, false, 2, false},
	}
	for _, tc := range tests {
		resp := tc.c.resolve(tc.query, peer, func(q []byte) ([]byte, error) { return exchangeUDP(tc.c.upstream, q) })
		if (resp == nil) != tc.wantNil {
			t.Errorf("%s: resp nil=%v want %v", tc.name, resp == nil, tc.wantNil)
			continue
		}
		if resp == nil {
			continue
		}
		if int(rcode(resp)) != tc.wantCode {
			t.Errorf("%s: rcode=%d want %d", tc.name, rcode(resp), tc.wantCode)
		}
		if tc.wantEcho && resp[2]&0x80 == 0 {
			t.Errorf("%s: forwarded reply lacks QR", tc.name)
		}
	}
}

func TestForwardUDPTruncatedRetriesTCP(t *testing.T) {
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	addr := up.LocalAddr().(*net.UDPAddr)
	go func() { // always replies truncated
		buf := make([]byte, 512)
		for {
			n, a, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			r := append([]byte{}, buf[:n]...)
			r[2] |= 0x82 // QR + TC
			up.WriteTo(r, a)
		}
	}()
	c := &Cleanser{upstream: addr, upstreamTCP: addr.String()}
	query := dnsQuery(7, 0x01, "big.example.com")

	// No TCP listener yet: the truncated reply is returned.
	resp, err := c.forwardUDP(query)
	if err != nil || resp[2]&0x02 == 0 {
		t.Fatalf("fallback: err=%v resp=%v", err, resp)
	}

	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		t.Skipf("tcp port unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		q, err := readFrame(conn)
		if err != nil {
			return
		}
		writeFrame(conn, withFlags(q, 0x80)) // full reply, no TC
	}()
	resp, err = c.forwardUDP(query)
	if err != nil || resp[2]&0x02 != 0 || resp[2]&0x80 == 0 {
		t.Fatalf("retry: err=%v resp=%v", err, resp)
	}
}

// withFlags returns a copy of msg with the given bits set in the first flags byte.
func withFlags(msg []byte, bits byte) []byte {
	r := append([]byte{}, msg...)
	r[2] |= bits
	return r
}

func TestNewCleanserValidatesOpts(t *testing.T) {
	addrs := []string{"8.8.8.8:53"}
	for name, tc := range map[string]struct {
		opts CleanserOpts
		want string
	}{
		"no dns":  {CleanserOpts{Addr: ":0", Workers: 1}, "dns_addresses must not be empty"},
		"workers": {CleanserOpts{Addr: ":0", DNSAddresses: addrs}, "workers must be positive"},
		"valid":   {CleanserOpts{Addr: ":0", DNSAddresses: addrs, Workers: 1}, ""},
	} {
		_, err := NewCleanser(&tc.opts, blacklist.New(nil, nil))
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || err.Error() != tc.want) {
			t.Errorf("%s: got %v want %q", name, err, tc.want)
		}
	}
}
