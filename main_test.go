package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveTCP(listener) }()
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
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveUDP(conn) }()
	t.Cleanup(func() {
		conn.Close()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("UDP shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("UDP listener did not stop")
		}
	})
	if err := checkUDP(conn.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
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
	var response [65535]byte
	for _, payload := range [][]byte{[]byte("hello\x00udp"), {}} {
		if n, err := conn.Write(payload); err != nil {
			return err
		} else if n != len(payload) {
			return io.ErrShortWrite
		}
		n, err := conn.Read(response[:])
		if err != nil {
			return err
		}
		if !bytes.Equal(response[:n], payload) {
			return errors.New("UDP echo differs from payload")
		}
	}
	return nil
}

func TestServerE2E(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ad-cleanser")
	buildContext, cancelBuild := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelBuild()
	if output, err := exec.CommandContext(buildContext, "go", "build", "-race", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, output)
	}

	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(binary)
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

	const address = "127.0.0.1:5353"
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-done:
			t.Fatalf("server exited before readiness: %v (port 5353 must be free)", waitErr)
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
	output, err := exec.CommandContext(secondContext, binary).CombinedOutput()
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
	select {
	case <-done:
		t.Fatalf("original server exited unexpectedly: %v", waitErr)
	default:
	}
}
