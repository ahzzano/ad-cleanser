package internal

import (
	"bytes"
	"net"
	"testing"
	"time"

	"ad-cleanser/internal/blacklist"
)

// bigUpstream answers every query (UDP and TCP, same port) with a size-byte reply without TC:
// the question followed by one NULL record padded to size.
func bigUpstream(t *testing.T, size int) *net.UDPAddr {
	reply := func(q []byte) []byte {
		r := withFlags(q, 0x80)
		r[7] = 1
		pad := size - len(r) - 12
		r = append(r, 0xC0, 12, 0, 10, 0, 1, 0, 0, 0, 0, byte(pad>>8), byte(pad))
		return append(r, make([]byte, pad)...)
	}
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, a, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			up.WriteTo(reply(buf[:n]), a)
		}
	}()
	addr := up.LocalAddr().(*net.UDPAddr)
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					q, err := readFrame(conn)
					if err != nil {
						return
					}
					writeFrame(conn, reply(q))
				}
			}()
		}
	}()
	return addr
}

func withOPT(q []byte, size uint16) []byte {
	q = append([]byte{}, q...)
	q[11] = 1
	return append(q, 0, 0, 41, byte(size>>8), byte(size), 0, 0, 0, 0, 0, 0)
}

func udpExchange(t *testing.T, addr string, q []byte) []byte {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestUDPSizeLimits(t *testing.T) {
	const big, edns = 1500, 4096
	q := dnsQuery(7, 1, "big.example.net")
	for _, tc := range []struct {
		name      string
		upSize    int
		query     []byte
		wantTrunc bool
	}{
		{"no EDNS truncated", big, q, true},
		{"OPT 4096 full", big, withOPT(q, edns), false},
		{"OPT 100 acts as 512", big, withOPT(q, 100), true},
		{"exactly 512 untouched", 512, q, false},
		{"513 truncated", 513, q, true},
		{"exactly OPT size untouched", 1200, withOPT(q, 1200), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, cancel, res := startCleanser(t, bigUpstream(t, tc.upSize), 1)
			defer func() { cancel(); waitRun(t, res) }()
			got := udpExchange(t, addr, tc.query)
			if got[0] != tc.query[0] || got[1] != tc.query[1] || got[2]&0x80 == 0 {
				t.Fatalf("bad header % x", got[:12])
			}
			if tc.wantTrunc {
				if got[2]&0x02 == 0 || !bytes.Equal(got[6:12], make([]byte, 6)) || got[5] != 1 ||
					!bytes.Equal(got[12:], q[12:len(q)]) {
					t.Fatalf("bad truncated reply % x", got)
				}
			} else if got[2]&0x02 != 0 || len(got) != tc.upSize {
				t.Fatalf("len=%d tc=%v want len %d untruncated", len(got), got[2]&0x02 != 0, tc.upSize)
			}
		})
	}
}

func TestUDPSizeBlockedUnaffected(t *testing.T) {
	addr, cancel, res := startCleanserBL(t, bigUpstream(t, 1500), 1, blacklist.New([]string{"ads.example.com"}, nil))
	defer func() { cancel(); waitRun(t, res) }()
	got := udpExchange(t, addr, dnsQuery(9, 1, "ads.example.com"))
	if got[2]&0x02 != 0 || got[2]&0x80 == 0 || len(got) > 512 {
		t.Fatalf("blocked reply altered: % x", got)
	}
}

func TestTCPFullAfterUDPTruncated(t *testing.T) {
	addr, cancel, res := startCleanser(t, bigUpstream(t, 1500), 1)
	defer func() { cancel(); waitRun(t, res) }()
	q := dnsQuery(3, 1, "big.example.net")
	if got := udpExchange(t, addr, q); got[2]&0x02 == 0 {
		t.Fatal("UDP not truncated")
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeFrame(conn, q); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(conn)
	if err != nil || len(got) != 1500 || got[2]&0x02 != 0 {
		t.Fatalf("tcp len=%d err=%v", len(got), err)
	}
}
