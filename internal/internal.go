package internal

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	blacklist "ad-cleanser/internal/blacklist"
	"ad-cleanser/internal/parser"
)

type CleanserOpts struct {
	Addr string
	// DNSAddresses is required for UDP serving; only the first address is used.
	DNSAddresses []string
	// Workers is the UDP worker count; QueueSize is the pending-queue length.
	Workers   int
	QueueSize int
}

type Cleanser struct {
	addr         string
	dnsAddresses []string
	workers      int
	queueSize    int
	blacklist    blacklist.Blacklist
}

func NewCleanser(opts *CleanserOpts, blacklist blacklist.Blacklist) *Cleanser {
	return &Cleanser{addr: opts.Addr, dnsAddresses: opts.DNSAddresses, workers: opts.Workers, queueSize: opts.QueueSize, blacklist: blacklist}
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
	if c.workers <= 0 {
		return errors.New("workers must be positive")
	}
	if c.queueSize < 0 {
		return errors.New("queue size must not be negative")
	}
	address := c.dnsAddresses[0]
	upstreamAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("resolve DNS address %q: %w", address, err)
	}

	pool := NewSocketPool(c.workers, c.queueSize, func(j Job) error {
		return c.handleUDP(conn, j.addr, upstreamAddr, j.query)
	})
	defer pool.Close()

	var buf [65535]byte
	for {
		n, peer, err := conn.ReadFrom(buf[:])
		if err != nil {
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

func (c *Cleanser) handleUDP(conn net.PacketConn, peer net.Addr, upstreamAddr *net.UDPAddr, query []byte) error {
	msg, err := parser.ParseDNSMessage(query)
	if err != nil {
		if r := parser.ErrorResponse(query, parser.FormErr); r != nil {
			_ = writeFull(conn, peer, r)
		}
		return err
	}
	if msg.IsResponse() {
		return nil
	}
	// fail answers the client with an error rcode, then returns cause.
	fail := func(rcode uint16, cause error) error {
		if r, rerr := msg.Response(rcode); rerr == nil {
			_ = writeFull(conn, peer, r)
		}
		return cause
	}
	if msg.Opcode() != 0 {
		return fail(parser.NotImp, fmt.Errorf("unsupported opcode %d", msg.Opcode()))
	}
	resp, err := c.blockedResponse(msg, peer)
	if err != nil {
		return fail(parser.FormErr, err)
	}
	if resp == nil {
		resp, err = exchange(upstreamAddr, query)
		if err != nil {
			return fail(parser.ServFail, err)
		}
		log.Printf("UDP forward: %s -> %s (%d bytes)", peer, upstreamAddr, len(query))
	}
	return writeFull(conn, peer, resp)
}

// blockedResponse returns the block response if any question is blacklisted, else nil, nil.
func (c *Cleanser) blockedResponse(msg parser.DNSMessage, peer net.Addr) ([]byte, error) {
	questions, err := msg.Questions()
	if err != nil {
		return nil, err
	}
	for _, q := range questions {
		if c.blacklist.IsBlocked(q.Name) {
			log.Printf("UDP blocked %q from %s", q.Name, peer)
			return msg.BlockResponse()
		}
	}
	return nil, nil
}

func exchange(upstreamAddr *net.UDPAddr, query []byte) ([]byte, error) {
	reply := make([]byte, 65535)
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
	for {
		n, err := upstreamConn.Read(reply)
		if err != nil {
			return nil, err
		}
		if matches(query, reply[:n]) {
			return reply[:n], nil
		}
		log.Printf("dropping mismatched upstream reply (%d bytes)", n)
	}
}

// matches reports whether reply is a response to query: same ID, QR set, same question.
func matches(query, reply []byte) bool {
	if len(reply) < 12 || reply[0] != query[0] || reply[1] != query[1] || reply[2]&0x80 == 0 {
		return false
	}
	qm, err := parser.ParseDNSMessage(query)
	if err != nil {
		return false
	}
	rm, err := parser.ParseDNSMessage(reply)
	if err != nil {
		return false
	}
	qs, err := qm.Questions()
	if err != nil {
		return false
	}
	rs, err := rm.Questions()
	if err != nil || len(qs) != len(rs) {
		return false
	}
	for i := range qs {
		if !strings.EqualFold(qs[i].Name, rs[i].Name) || qs[i].Type != rs[i].Type || qs[i].Class != rs[i].Class {
			return false
		}
	}
	return true
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
