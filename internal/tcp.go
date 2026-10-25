package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	sem := make(chan struct{}, maxTCPConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				c.handleTCP(conn)
			}()
		default:
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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("TCP panic: %v", r)
		}
	}()
	fwd := func(q []byte) ([]byte, error) { return exchangeTCP(c.upstream.String(), q) }
	for {
		if err := conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout)); err != nil {
			return
		}
		query, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("TCP read %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		resp, err := c.resolve(query, conn.RemoteAddr(), fwd)
		if err != nil {
			log.Printf("TCP: %v", err)
		}
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
