package internal

import (
	"net"
	"testing"
	"time"

	"ad-cleanser/internal/blacklist"
)

// silentUpstream reads nothing and answers nothing on UDP; no TCP listener on its port.
func silentUpstream(t *testing.T) *net.UDPAddr {
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	return up.LocalAddr().(*net.UDPAddr)
}

// timedUDP sends q to addr and returns the reply and how long it took.
func timedUDP(t *testing.T, addr string, q []byte) ([]byte, time.Duration) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	start := time.Now()
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n], time.Since(start)
}

func TestFailoverUDPSticksToLiveUpstream(t *testing.T) {
	live := slowUpstream(t, 0, make(chan struct{}, 16))
	addr, cancel, res := startCleanserBL(t, []string{silentUpstream(t).String(), live.String()}, 2, blacklist.New(nil, nil))
	defer func() { cancel(); waitRun(t, res) }()

	got, d := timedUDP(t, addr, dnsQuery(1, 1, "a.example.com"))
	if rcode(got) != 0 || got[2]&0x80 == 0 || d > 3*time.Second {
		t.Fatalf("first: rcode=%d took %s", rcode(got), d)
	}
	got, d = timedUDP(t, addr, dnsQuery(2, 1, "b.example.com"))
	if rcode(got) != 0 || d > 500*time.Millisecond {
		t.Fatalf("second should go straight to live upstream: rcode=%d took %s", rcode(got), d)
	}
}

func TestFailoverTCP(t *testing.T) {
	live := slowUpstream(t, 0, make(chan struct{}, 16))
	addr, cancel, res := startCleanserBL(t, []string{silentUpstream(t).String(), live.String()}, 1, blacklist.New(nil, nil))
	defer func() { cancel(); waitRun(t, res) }()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeFrame(conn, dnsQuery(3, 1, "c.example.com")); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(conn)
	if err != nil || rcode(got) != 0 || got[2]&0x80 == 0 {
		t.Fatalf("tcp failover: err=%v resp=% x", err, got)
	}
}

func TestRetrySingleUpstreamAfterLoss(t *testing.T) {
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() { // drops the first query, echoes the rest
		buf := make([]byte, 512)
		for i := 0; ; i++ {
			n, a, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			if i > 0 {
				up.WriteTo(withFlags(buf[:n], 0x80), a)
			}
		}
	}()
	addr, cancel, res := startCleanser(t, up.LocalAddr().(*net.UDPAddr), 1)
	defer func() { cancel(); waitRun(t, res) }()

	got, d := timedUDP(t, addr, dnsQuery(4, 1, "d.example.com"))
	if rcode(got) != 0 || got[2]&0x80 == 0 || d > 3*time.Second {
		t.Fatalf("retry: rcode=%d took %s", rcode(got), d)
	}
}

func TestAllUpstreamsDeadServFail(t *testing.T) {
	addr, cancel, res := startCleanserBL(t, []string{silentUpstream(t).String(), silentUpstream(t).String()}, 1, blacklist.New(nil, nil))
	defer func() { cancel(); waitRun(t, res) }()

	got, d := timedUDP(t, addr, dnsQuery(5, 1, "e.example.com"))
	if rcode(got) != 2 || d > 4500*time.Millisecond {
		t.Fatalf("want SERVFAIL within 4.5s: rcode=%d took %s", rcode(got), d)
	}
}
