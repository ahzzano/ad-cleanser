package internal

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestIsTransient(t *testing.T) {
	for err, want := range map[error]bool{
		syscall.EMFILE: true, syscall.ENFILE: true, syscall.ECONNABORTED: true,
		net.ErrClosed: false, os.ErrDeadlineExceeded: false, errors.New("x"): false,
	} {
		if got := isTransient(err); got != want {
			t.Errorf("isTransient(%v)=%v want %v", err, got, want)
		}
	}
}

type seqListener struct {
	net.Listener
	errs []error
}

func (l *seqListener) Accept() (net.Conn, error) {
	e := l.errs[0]
	l.errs = l.errs[1:]
	return nil, e
}

func TestServeTCPSurvivesEMFILE(t *testing.T) {
	l := &seqListener{errs: []error{syscall.EMFILE, net.ErrClosed}}
	if err := (&Cleanser{}).serveTCP(l); !errors.Is(err, errShutdown) {
		t.Fatalf("got %v want errShutdown", err)
	}
}

type seqPacketConn struct {
	net.PacketConn
	errs []error
}

func (c *seqPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	e := c.errs[0]
	c.errs = c.errs[1:]
	return 0, nil, e
}

func TestServeUDPSurvivesTransientRead(t *testing.T) {
	c := &Cleanser{workers: 1}
	conn := &seqPacketConn{errs: []error{syscall.EMFILE, os.ErrDeadlineExceeded}}
	if err := c.serveUDP(conn); !errors.Is(err, errShutdown) {
		t.Fatalf("got %v want errShutdown", err)
	}
}
