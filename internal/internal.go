package internal

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	blacklist "ad-cleanser/internal/blacklist"
	"ad-cleanser/internal/parser"
)

type CleanserOpts struct {
	Addr string
	// DNSAddresses is required for UDP serving; only the first address is used.
	DNSAddresses []string
}

type Cleanser struct {
	addr         string
	dnsAddresses []string
	blacklist    blacklist.Blacklist
}

func NewCleanser(opts *CleanserOpts, blacklist blacklist.Blacklist) *Cleanser {
	return &Cleanser{addr: opts.Addr, dnsAddresses: opts.DNSAddresses, blacklist: blacklist}
}

func (c *Cleanser) Run() error {
	tcp, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", c.addr)
	if err != nil {
		return err
	}
	defer udp.Close()
	log.Printf("listening on TCP and UDP %s", c.addr)
	done := make(chan error, 2)
	go func() { done <- c.serveUDP(udp) }()
	go func() { done <- c.serveTCP(tcp) }()
	return <-done
}

func (c *Cleanser) serveUDP(conn net.PacketConn) error {
	if len(c.dnsAddresses) == 0 {
		return errors.New("no DNS addresses configured")
	}
	address := c.dnsAddresses[0]
	upstreamAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("resolve DNS address %q: %w", address, err)
	}

	var buf, reply [65535]byte
	for {
		n, peer, err := conn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		// shortcut: UDP exchanges are sequential, add bounded concurrency if upstream latency limits throughput
		if err := c.handleUDP(conn, peer, upstreamAddr, buf[:n], reply[:]); err != nil {
			log.Printf("UDP exchange with %s: %v", upstreamAddr, err)
		}
	}
}

func (c *Cleanser) handleUDP(conn net.PacketConn, peer net.Addr, upstreamAddr *net.UDPAddr, query, reply []byte) error {
	msg, err := parser.ParseDNSMessage(query)
	if err != nil {
		return err
	}
	questions, err := msg.Questions()
	if err != nil {
		return err
	}
	for _, q := range questions {
		if c.blacklist.IsBlocked(q.Name) {
			log.Printf("UDP blocked %q from %s", q.Name, peer)
			resp, err := msg.BlockResponse()
			if err != nil {
				return err
			}
			return writeFull(conn, peer, resp)
		}
	}

	resp, err := exchange(upstreamAddr, query, reply)
	if err != nil {
		return err
	}
	log.Printf("UDP forward: %s -> %s (%d bytes)", peer, upstreamAddr, len(query))
	return writeFull(conn, peer, resp)
}

// exchange sends query upstream and reads the answer into reply, which must not alias query.
func exchange(upstreamAddr *net.UDPAddr, query, reply []byte) ([]byte, error) {
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()
	if err := upstreamConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	written, err := upstreamConn.Write(query)
	if err != nil {
		return nil, err
	}
	if written != len(query) {
		return nil, io.ErrShortWrite
	}
	n, err := upstreamConn.Read(reply)
	if err != nil {
		return nil, err
	}
	return reply[:n], nil
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

func (c *Cleanser) serveTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		// shortcut: TCP connections are unbounded, add limits before exposing this server beyond loopback
		go func() {
			defer conn.Close()
			if _, err := io.Copy(conn, conn); err != nil {
				log.Printf("TCP echo: %v", err)
			}
		}()
	}
}
