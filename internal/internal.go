package internal

import (
	"io"
	"log"
	"net"
)

type CleanserOpts struct {
	Addr string
}

type Cleanser struct {
	addr string
}

func NewCleanser(opts *CleanserOpts) *Cleanser {
	return &Cleanser{addr: opts.Addr}
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
	var buf [65535]byte
	for {
		n, peer, err := conn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		written, err := conn.WriteTo(buf[:n], peer)
		if err != nil {
			log.Printf("UDP reply: %v", err)
		} else if written != n {
			log.Printf("UDP reply: %v", io.ErrShortWrite)
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
