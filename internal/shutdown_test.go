package internal

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	blacklist "ad-cleanser/internal/blacklist"
)

// slowUpstream echoes queries with QR set after delay, over UDP and TCP on one port.
func slowUpstream(t *testing.T, delay time.Duration, got chan<- struct{}) *net.UDPAddr {
	notify := func() {
		select {
		case got <- struct{}{}:
		default:
		}
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
			notify()
			r := withFlags(buf[:n], 0x80)
			go func() { time.Sleep(delay); up.WriteTo(r, a) }()
		}
	}()
	addr := up.LocalAddr().(*net.UDPAddr)
	if ln, err := net.Listen("tcp", addr.String()); err == nil {
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
						notify()
						time.Sleep(delay)
						writeFrame(conn, withFlags(q, 0x80))
					}
				}()
			}
		}()
	}
	return addr
}

// startCleanser runs a Cleanser and returns its address, cancel func and Run's result channel.
func startCleanser(t *testing.T, upstream *net.UDPAddr, workers int) (string, context.CancelFunc, chan error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	c, err := NewCleanser(&CleanserOpts{Addr: addr, DNSAddresses: []string{upstream.String()}, Workers: workers, QueueSize: 16}, blacklist.Blacklist{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan error, 1)
	go func() { res <- c.Run(ctx) }()
	for i := 0; ; i++ { // wait until the TCP listener accepts
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		} else if i > 100 {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr, cancel, res
}

func waitRun(t *testing.T, res chan error) {
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestShutdownUDPAnswersInFlightAndQueued(t *testing.T) {
	got := make(chan struct{}, 16)
	addr, cancel, res := startCleanser(t, slowUpstream(t, 300*time.Millisecond, got), 1)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const n = 3 // 1 worker: one in flight, two queued
	for i := 0; i < n; i++ {
		conn.Write(dnsQuery(byte(i+1), 0x01, "a.example.com"))
	}
	<-got // upstream holds the first query
	cancel()
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 512)
	for i := 0; i < n; i++ {
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
	waitRun(t, res)
}

func TestShutdownTCPInFlightAndIdle(t *testing.T) {
	got := make(chan struct{}, 16)
	addr, cancel, res := startCleanser(t, slowUpstream(t, 300*time.Millisecond, got), 1)
	busy, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	writeFrame(busy, dnsQuery(1, 0x01, "a.example.com"))
	<-got
	start := time.Now()
	cancel()
	busy.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := readFrame(busy); err != nil {
		t.Fatalf("in-flight reply: %v", err)
	}
	if _, err := readFrame(busy); err == nil {
		t.Fatal("connection should close after reply")
	}
	waitRun(t, res)
	if d := time.Since(start); d > tcpIdleTimeout/2 {
		t.Fatalf("shutdown took %v", d)
	}
	if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener still accepting")
	}
}

func TestRunReturnsServerError(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	c := &Cleanser{addr: l.Addr().String()}
	if err := c.Run(context.Background()); err == nil {
		t.Fatal("expected bind error")
	}
}

type failingListener struct{ net.Listener }

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("boom") }

func TestServeTCPReturnsAcceptError(t *testing.T) {
	err := (&Cleanser{}).serveTCP(failingListener{})
	if err == nil || errors.Is(err, errShutdown) {
		t.Fatalf("got %v, want the accept error", err)
	}
}

func TestConnTracker(t *testing.T) {
	var tr connTracker
	a, b := net.Pipe()
	defer b.Close()
	woke := make(chan error, 1)
	started := make(chan struct{})
	go tr.Handle(a, func(c net.Conn) {
		defer a.Close()
		if !tr.ArmIdle(c) {
			t.Error("ArmIdle false before shutdown")
		}
		close(started)
		_, err := c.Read(make([]byte, 1))
		woke <- err
	})
	<-started
	tr.Shutdown()
	select {
	case err := <-woke:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not wake the reader")
	}
	if tr.ArmIdle(a) {
		t.Fatal("ArmIdle true after shutdown")
	}
	// Handle after Shutdown closes conn without calling fn.
	c, d := net.Pipe()
	defer d.Close()
	tr.Handle(c, func(net.Conn) { t.Error("fn called after shutdown") })
	if _, err := c.Write([]byte{0}); err == nil {
		t.Fatal("conn not closed")
	}
	// Eventually unregistered after fn returns.
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for range 100 {
		if len(tr.conns) == 0 {
			return
		}
		tr.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		tr.mu.Lock()
	}
	t.Fatal("conn still registered")
}
