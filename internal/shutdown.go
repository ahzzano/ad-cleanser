package internal

import (
	"errors"
	"net"
	"sync"
	"time"
)

// errShutdown is returned by the serve loops when they stop because Run asked them to.
var errShutdown = errors.New("shutdown")

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
