package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"ad-cleanser/internal/parser"
)

// shortcut: hardcoded, move to CleanserOpts/config if tuning is needed
const (
	maxTCPConns    = 100
	tcpIdleTimeout = 10 * time.Second
)

const upstreamTimeout = 2 * time.Second

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, errors.New("invalid frame length")
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeFrame sends msg with its 2-byte length prefix in a single Write.
func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errors.New("message too large for TCP frame")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}

func (c *Cleanser) serveTCP(listener net.Listener) error {
	lim := newLimiter(maxTCPConns)
	defer lim.wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return errShutdown
			}
			if isTransient(err) {
				retryTransient("TCP accept", err)
				continue
			}
			return err
		}
		if !lim.tryGo(func() { c.conns.Handle(conn, c.handleTCP) }) {
			log.Print("TCP connection limit reached, rejecting")
			conn.Close()
		}
	}
}

func exchangeTCP(upstream string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", upstream, upstreamTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(upstreamTimeout)); err != nil {
		return nil, err
	}
	if err := writeFrame(conn, query); err != nil {
		return nil, err
	}
	resp, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	if !parser.IsReplyTo(query, resp) {
		return nil, fmt.Errorf("mismatched upstream reply")
	}
	return resp, nil
}

func (c *Cleanser) handleTCP(conn net.Conn) {
	defer conn.Close()
	fwd := func(q []byte) ([]byte, error) { return exchangeTCP(c.upstreamTCP, q) }
	for {
		if !c.conns.ArmIdle(conn) {
			return
		}
		query, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Printf("TCP read %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		resp := c.resolve(query, conn.RemoteAddr(), fwd)
		if resp == nil {
			continue
		}
		if err := conn.SetWriteDeadline(time.Now().Add(upstreamTimeout)); err != nil {
			return
		}
		if err := writeFrame(conn, resp); err != nil {
			log.Printf("TCP write %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

// connTracker tracks open TCP connections so shutdown can wake idle ones.
// The zero value is ready to use.
type connTracker struct {
	mu      sync.Mutex
	closing bool
	conns   map[net.Conn]struct{}
}

// Handle runs fn on conn while it is registered. After Shutdown it closes conn instead.
func (t *connTracker) Handle(conn net.Conn, fn func(net.Conn)) {
	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		conn.Close()
		return
	}
	if t.conns == nil {
		t.conns = map[net.Conn]struct{}{}
	}
	t.conns[conn] = struct{}{}
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		delete(t.conns, conn)
		t.mu.Unlock()
	}()
	fn(conn)
}

// ArmIdle sets the idle read deadline; false means stop serving conn. It shares the
// lock with Shutdown so it can never overwrite the shutdown deadline.
func (t *connTracker) ArmIdle(conn net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.closing && conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout)) == nil
}

// Shutdown wakes idle handlers; handlers mid-query still finish their reply.
func (t *connTracker) Shutdown() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closing = true
	for conn := range t.conns {
		conn.SetReadDeadline(time.Now()) // error ignored: the conn may already be closed
	}
}
