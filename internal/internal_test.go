package internal

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ad-cleanser/internal/blacklist"
)

func TestNewCleanserBlacklist(t *testing.T) {
	cleanser := NewCleanser(&CleanserOpts{}, blocklist.New([]string{"example.ad.com"}))
	if !cleanser.blacklist.IsBlocked("example.ad.com") {
		t.Error("configured blacklist does not block example.ad.com")
	}
	if cleanser.blacklist.IsBlocked("example.com") {
		t.Error("configured blacklist blocks unrelated domain example.com")
	}
}

func TestTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cleanser := NewCleanser(&CleanserOpts{Addr: listener.Addr().String()}, blocklist.New(nil))
	done := make(chan error, 1)
	go func() { done <- cleanser.serveTCP(listener) }()
	t.Cleanup(func() {
		listener.Close()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("TCP shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("TCP listener did not stop")
		}
	})
	if err := checkTCP(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
}

func TestUDP(t *testing.T) {
	upstream := startMockDNS(t, false)
	unused, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer unused.Close()
	address := startUDP(t, []string{upstream.conn.LocalAddr().String(), unused.LocalAddr().String()})
	if err := checkUDP(address); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := exchangeDNS(conn, nil); err != nil {
		t.Fatalf("empty datagram: %v", err)
	}
	requests := upstream.received()
	if len(requests) != 2 || !bytes.Equal(requests[0], dnsPacket(dnsQueryWire)) || len(requests[1]) != 0 {
		t.Fatalf("forwarded datagrams differ: %x", requests)
	}
	if err := unused.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var response [65535]byte
	if _, _, err := unused.ReadFrom(response[:]); err == nil {
		t.Fatal("second DNS endpoint received a datagram")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("second DNS endpoint: %v", err)
	}
}

func TestUDPTwoClients(t *testing.T) {
	upstream := startMockDNS(t, false)
	address := startUDP(t, []string{upstream.conn.LocalAddr().String()})
	var clients [2]net.Conn
	var queries [2][]byte
	for i := range clients {
		conn, err := net.DialTimeout("udp", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		clients[i] = conn
		queries[i] = dnsPacket(dnsQueryWire)
		if i == 1 {
			queries[i][0], queries[i][1] = 0x56, 0x78
		}
		if n, err := conn.Write(queries[i]); err != nil {
			t.Fatal(err)
		} else if n != len(queries[i]) {
			t.Fatal(io.ErrShortWrite)
		}
	}
	var response [65535]byte
	for i, conn := range clients {
		n, err := conn.Read(response[:])
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if err := checkDNSResponse(response[:n], queries[i]); err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
	}
}

func TestUDPInvalidDNSAddresses(t *testing.T) {
	for _, test := range []struct {
		name      string
		addresses []string
	}{
		{name: "empty"},
		{name: "malformed first", addresses: []string{"[invalid", "127.0.0.1:53"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			cleanser := NewCleanser(&CleanserOpts{Addr: conn.LocalAddr().String(), DNSAddresses: test.addresses}, blocklist.New(nil))
			done := make(chan error, 1)
			go func() { done <- cleanser.serveUDP(conn) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expected invalid DNS configuration error")
				}
			case <-time.After(time.Second):
				conn.Close()
				<-done
				t.Fatal("invalid DNS configuration did not fail before client traffic")
			}
		})
	}
}

func TestUDPTimeoutRecovery(t *testing.T) {
	upstream := startMockDNS(t, true)
	address := startUDP(t, []string{upstream.conn.LocalAddr().String()})
	first, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	query := dnsPacket(dnsQueryWire)
	if n, err := first.Write(query); err != nil {
		t.Fatal(err)
	} else if n != len(query) {
		t.Fatal(io.ErrShortWrite)
	}
	var response [65535]byte
	if _, err := first.Read(response[:]); err == nil {
		t.Fatal("dropped upstream request was echoed to the client")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("first client: %v", err)
	}
	second, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	query[0], query[1] = 0x56, 0x78
	if err := exchangeDNS(second, query); err != nil {
		t.Fatalf("query after upstream timeout: %v", err)
	}
	if requests := upstream.received(); len(requests) != 2 {
		t.Fatalf("expected two upstream requests, got %d", len(requests))
	}
}

func startUDP(t *testing.T, addresses []string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cleanser := NewCleanser(&CleanserOpts{Addr: conn.LocalAddr().String(), DNSAddresses: addresses}, blocklist.New(nil))
	done := make(chan error, 1)
	go func() { done <- cleanser.serveUDP(conn) }()
	t.Cleanup(func() {
		conn.Close()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("UDP shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("UDP listener did not stop")
		}
	})
	return conn.LocalAddr().String()
}

const (
	dnsQueryWire    = "123401000001000000000000076578616d706c6503636f6d0000010001"
	dnsResponseWire = "123481800001000100000000076578616d706c6503636f6d0000010001c00c000100010000003c000443434343"
)

func dnsPacket(wire string) []byte {
	packet, err := hex.DecodeString(wire)
	if err != nil {
		panic(err)
	}
	return packet
}

type mockDNS struct {
	conn     net.PacketConn
	mu       sync.Mutex
	requests [][]byte
}

func startMockDNS(t *testing.T, dropFirst bool) *mockDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockDNS{conn: conn}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf [65535]byte
		for {
			n, peer, err := conn.ReadFrom(buf[:])
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("mock DNS read: %v", err)
				}
				return
			}
			mock.mu.Lock()
			mock.requests = append(mock.requests, append([]byte(nil), buf[:n]...))
			drop := dropFirst && len(mock.requests) == 1
			mock.mu.Unlock()
			if drop {
				continue
			}
			response := dnsPacket(dnsResponseWire)
			if n >= 2 {
				copy(response[:2], buf[:2])
			}
			if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Errorf("mock DNS deadline: %v", err)
				return
			}
			if n, err := conn.WriteTo(response, peer); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("mock DNS write: %v", err)
				}
				return
			} else if n != len(response) {
				t.Error("mock DNS: short response write")
				return
			}
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	return mock
}

func (mock *mockDNS) received() [][]byte {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	return append([][]byte(nil), mock.requests...)
}

func TestRunUDPBindFailureClosesTCP(t *testing.T) {
	var udp net.PacketConn
	var address string
	for range 100 {
		var err error
		udp, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = udp.LocalAddr().String()
		probe, err := net.Listen("tcp", address)
		if err != nil {
			udp.Close()
			udp = nil
			continue
		}
		probe.Close()
		break
	}
	if udp == nil {
		t.Fatal("could not find a UDP address with TCP available")
	}
	defer udp.Close()

	cleanser := NewCleanser(&CleanserOpts{Addr: address}, blocklist.New(nil))
	err := cleanser.Run()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Net != "udp" || opErr.Op != "listen" {
		t.Fatalf("expected UDP listen failure, got %v", err)
	}
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("TCP listener was not released: %v", err)
	}
	tcp.Close()
}

func checkTCP(address string) error {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	payload := []byte("hello\x00tcp")
	response := make([]byte, len(payload))
	for range 2 {
		if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, response); err != nil {
			return err
		}
		if !bytes.Equal(response, payload) {
			return errors.New("TCP echo differs from payload")
		}
	}
	return nil
}

func checkUDP(address string) error {
	conn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	return exchangeDNS(conn, dnsPacket(dnsQueryWire))
}

func exchangeDNS(conn net.Conn, query []byte) error {
	if n, err := conn.Write(query); err != nil {
		return err
	} else if n != len(query) {
		return io.ErrShortWrite
	}
	var response [65535]byte
	n, err := conn.Read(response[:])
	if err != nil {
		return err
	}
	return checkDNSResponse(response[:n], query)
}

func checkDNSResponse(response, query []byte) error {
	expected := dnsPacket(dnsResponseWire)
	if len(query) >= 2 {
		copy(expected[:2], query[:2])
	}
	if len(response) != len(expected) {
		return errors.New("unexpected DNS response length")
	}
	if !bytes.Equal(response[:2], expected[:2]) {
		return errors.New("DNS response transaction ID differs from query")
	}
	if !bytes.Equal(response, expected) {
		return errors.New("DNS response differs from fixed mock answer")
	}
	if net.IP(response[len(response)-4:]).String() != "67.67.67.67" {
		return errors.New("DNS response A answer is not 67.67.67.67")
	}
	return nil
}

func TestServerProcess(t *testing.T) {
	if os.Getenv("AD_CLEANSER_TEST_PROCESS") != "1" {
		return
	}
	cleanser := NewCleanser(&CleanserOpts{
		Addr:         "127.0.0.1:15353",
		DNSAddresses: []string{os.Getenv("AD_CLEANSER_TEST_DNS")},
	}, blocklist.New(nil))
	if err := cleanser.Run(); err != nil {
		log.Fatal(err)
	}
}

func TestServerE2E(t *testing.T) {
	upstream := startMockDNS(t, false)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "AD_CLEANSER_TEST_PROCESS=1", "AD_CLEANSER_TEST_DNS="+upstream.conn.LocalAddr().String())
	dir := t.TempDir()

	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(binary, "-test.run=^TestServerProcess$")
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill server: %v", err)
			}
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not exit after cleanup")
		}
		if t.Failed() {
			output, err := os.ReadFile(logPath)
			if err != nil {
				t.Errorf("read server logs: %v", err)
			} else {
				t.Logf("server logs:\n%s", output)
			}
		}
	})

	const address = "127.0.0.1:15353"
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-done:
			t.Fatalf("server exited before readiness: %v (port 15353 must be free)", waitErr)
		default:
		}
		err := checkTCP(address)
		if err == nil {
			err = checkUDP(address)
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not ready: %v", err)
		}
		select {
		case <-done:
			t.Fatalf("server exited before readiness: %v", waitErr)
		case <-time.After(20 * time.Millisecond):
		}
	}

	secondContext, cancelSecond := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSecond()
	second := exec.CommandContext(secondContext, binary, "-test.run=^TestServerProcess$")
	second.Env = env
	output, err := second.CombinedOutput()
	if secondContext.Err() != nil {
		t.Fatalf("second server did not reject occupied port: %v\n%s", secondContext.Err(), output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("second server should fail to bind: %v\n%s", err, output)
	}
	if err := checkTCP(address); err != nil {
		t.Fatalf("TCP after duplicate startup: %v", err)
	}
	if err := checkUDP(address); err != nil {
		t.Fatalf("UDP after duplicate startup: %v", err)
	}
	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read server logs: %v", err)
	}
	if !bytes.Contains(logs, []byte("UDP forward:")) || !bytes.Contains(logs, []byte(upstream.conn.LocalAddr().String())) {
		t.Fatalf("server logs lack forwarding metadata for %s:\n%s", upstream.conn.LocalAddr(), logs)
	}
	select {
	case <-done:
		t.Fatalf("original server exited unexpectedly: %v", waitErr)
	default:
	}
}
