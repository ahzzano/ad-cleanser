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
	pool := NewSocketPool(c.workers, c.queueSize, func(j Job) error {
		return c.handleUDP(conn, j.addr, j.query)
	})
	defer pool.Close()

	var buf [65535]byte
	for {
		n, peer, err := conn.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) { // only Run sets this, to stop us
				return errShutdown // deferred pool.Close drains jobs before the socket closes
			}
			if isTransient(err) {
				retryTransient("UDP read", err)
				continue
			}
			return err
		}

		q := make([]byte, n)
		copy(q, buf[:n])

		if !pool.ProcessRequest(Job{
			addr:  peer,
			query: q,
		}) {
			log.Print("UDP queue is full, dropping request")
		}
	}
}

func (c *Cleanser) handleUDP(conn net.PacketConn, peer net.Addr, query []byte) error {
	resp, err := c.resolve(query, peer, c.forwardUDP)
	if resp != nil {
		if werr := writeFull(conn, peer, resp); err == nil {
			err = werr
		}
	}
	return err
}

// forwardUDP queries upstream over UDP and retries over TCP if the reply is truncated.
func (c *Cleanser) forwardUDP(query []byte) ([]byte, error) {
	resp, err := exchangeUDP(c.upstream, query)
	if err != nil || resp[2]&0x02 == 0 { // 0x02 is the TC flag
		return resp, err
	}
	full, terr := exchangeTCP(c.upstream.String(), query)
	if terr != nil {
		log.Printf("TCP retry failed, returning truncated reply: %v", terr)
		return resp, nil
	}
	return full, nil
}

func exchangeUDP(upstreamAddr *net.UDPAddr, query []byte) ([]byte, error) {
	reply := make([]byte, 65535)
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()
	if err := upstreamConn.SetDeadline(time.Now().Add(upstreamTimeout)); err != nil {
		return nil, err
	}
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
		if parser.IsReplyTo(query, reply[:n]) {
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
