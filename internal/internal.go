package internal

import (
	"context"
	"errors"
	"fmt"
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
	// Workers is the UDP worker count.
	Workers int
	// LogQueries logs every forwarded and blocked query; errors are always logged.
	LogQueries bool
}

type Cleanser struct {
	addr        string
	upstream    *net.UDPAddr
	upstreamTCP string
	workers     int
	blacklist   blacklist.Blacklist
	conns       connTracker
	logQueries  bool
}

// NewCleanser resolves the upstream and rejects forwarding loops before anything is bound.
func NewCleanser(opts *CleanserOpts, blacklist blacklist.Blacklist) (*Cleanser, error) {
	switch {
	case len(opts.DNSAddresses) == 0:
		return nil, errors.New("dns_addresses must not be empty")
	case opts.Workers <= 0:
		return nil, errors.New("workers must be positive")
	}
	address := opts.DNSAddresses[0]
	upstream, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve DNS address %q: %w", address, err)
	}
	listen, err := net.ResolveUDPAddr("udp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address %q: %w", opts.Addr, err)
	}
	self, err := isSelf(listen, upstream)
	if err != nil {
		return nil, err
	}
	if self {
		return nil, fmt.Errorf("upstream %s is this server (%s): forwarding loop", upstream, opts.Addr)
	}
	if exposedAddr(listen) {
		log.Printf("warning: listening on %s may expose an open resolver; bind to a LAN or loopback address", opts.Addr)
	}
	return &Cleanser{addr: opts.Addr, upstream: upstream, upstreamTCP: upstream.String(), workers: opts.Workers, blacklist: blacklist, logQueries: opts.LogQueries}, nil
}

// errShutdown is returned by the serve loops when they stop because Run asked them to.
var errShutdown = errors.New("shutdown")

// Run serves until ctx is cancelled or a server fails, then drains in-flight queries.
func (c *Cleanser) Run(ctx context.Context) error {
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	// A server that dies on its own cancels ctx, which stops the other one too.
	go func() { err := c.serveUDP(udp); cancel(); done <- err }()
	go func() { err := c.serveTCP(tcp); cancel(); done <- err }()

	<-ctx.Done()
	log.Print("shutting down")
	c.conns.Shutdown()
	tcp.Close()
	udp.SetReadDeadline(time.Now()) // socket stays open so in-flight queries can still reply

	var errs []error
	for range 2 {
		if err := <-done; !errors.Is(err, errShutdown) {
			errs = append(errs, err)
		}
	}
	log.Print("shutdown complete")
	return errors.Join(errs...)
}

// forwardFunc sends a query upstream over the caller's transport and returns the reply.
type forwardFunc func(query []byte) ([]byte, error)

// resolve decides the reply for a query and logs its own failures; nil means send nothing.
func (c *Cleanser) resolve(query []byte, peer net.Addr, fwd forwardFunc) []byte {
	msg, err := parser.ParseDNSMessage(query)
	if err != nil {
		log.Printf("parse query from %s: %v", peer, err)
		return parser.ErrorResponse(query, parser.FormErr)
	}
	if msg.IsResponse() {
		return nil
	}
	if msg.Opcode() != 0 {
		log.Printf("unsupported opcode %d from %s", msg.Opcode(), peer)
		return msg.Response(parser.NotImp)
	}
	if c.blacklist.IsBlocked(msg.Question.Name) {
		if c.logQueries {
			log.Printf("blocked %q from %s", msg.Question.Name, peer)
		}
		return msg.BlockResponse()
	}
	resp, err := fwd(query)
	if err != nil {
		log.Printf("forward for %s: %v", peer, err)
		return msg.Response(parser.ServFail)
	}
	if c.logQueries {
		log.Printf("forward: %s (%d bytes)", peer, len(query))
	}
	return resp
}
