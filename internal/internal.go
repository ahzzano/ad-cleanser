package internal

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	blacklist "ad-cleanser/internal/blacklist"
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

	var buf [65535]byte
	for {
		n, peer, err := conn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		// shortcut: UDP exchanges are sequential, add bounded concurrency if upstream latency limits throughput
		if err := func() error {
			upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
			if err != nil {
				return err
			}
			defer upstreamConn.Close()
			if err := upstreamConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return err
			}
			written, err := upstreamConn.Write(buf[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
			log.Printf("UDP forward: %s -> %s (%d bytes)", peer, upstreamAddr, n)

			responseLen, err := upstreamConn.Read(buf[:])
			if err != nil {
				return err
			}
			written, err = conn.WriteTo(buf[:responseLen], peer)
			if err != nil {
				return err
			}
			if written != responseLen {
				return io.ErrShortWrite
			}
			return nil
		}(); err != nil {
			log.Printf("UDP exchange with %s: %v", upstreamAddr, err)
		}
	}
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
