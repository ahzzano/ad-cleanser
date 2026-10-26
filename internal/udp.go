package internal

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"time"

	"ad-cleanser/internal/parser"
)

func (c *Cleanser) serveUDP(conn net.PacketConn) error {
	lim := newLimiter(c.workers)
	defer lim.wait() // drains in-flight queries before Run closes the socket

	var buf [65535]byte
	for {
		n, peer, err := conn.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) { // only Run sets this, to stop us
				return errShutdown // deferred lim.wait drains queries before the socket closes
			}
			if isTransient(err) {
				retryTransient("UDP read", err)
				continue
			}
			return err
		}

		q := make([]byte, n)
		copy(q, buf[:n])

		if !lim.tryGo(func() { c.handleUDP(conn, peer, q) }) {
			log.Print("UDP busy, dropping request")
		}
	}
}

func (c *Cleanser) handleUDP(conn net.PacketConn, peer net.Addr, query []byte) {
	resp := c.resolve(query, peer, c.forwardUDP)
	if resp == nil {
		return
	}
	if err := writeFull(conn, peer, resp); err != nil {
		log.Printf("UDP write %s: %v", peer, err)
	}
}

// forwardUDP queries upstream over UDP and retries over TCP if the reply is truncated.
// The result is cut to the size the client accepts.
func (c *Cleanser) forwardUDP(q parser.DNSMessage) ([]byte, error) {
	resp, u, err := c.exchange(q, exchangeUDP)
	if err != nil {
		return nil, err
	}
	if parser.IsTruncated(resp) {
		if full, terr := exchangeTCP(u.String(), q); terr != nil {
			log.Printf("TCP retry failed, returning truncated reply: %v", terr)
		} else {
			resp = full
		}
	}
	return parser.TruncateResponse(resp, q.UDPSize()), nil
}

func exchangeUDP(upstreamAddr *net.UDPAddr, q parser.DNSMessage) ([]byte, error) {
	reply := make([]byte, 65535)
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()
	if err := upstreamConn.SetDeadline(time.Now().Add(upstreamTimeout)); err != nil {
		return nil, err
	}
	query := q.Bytes()
	written, err := upstreamConn.Write(query)
	if err != nil {
		return nil, err
	}
	if written != len(query) {
		return nil, io.ErrShortWrite
	}
	for {
		n, err := upstreamConn.Read(reply)
		if err != nil {
			return nil, err
		}
		if q.IsReplyTo(reply[:n]) {
			return reply[:n], nil
		}
		log.Printf("dropping mismatched upstream reply (%d bytes)", n)
	}
}

func writeFull(conn net.PacketConn, peer net.Addr, b []byte) error {
	written, err := conn.WriteTo(b, peer)
	if err != nil {
		return err
	}
	if written != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
