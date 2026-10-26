package internal

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"ad-cleanser/internal/blacklist"
	"ad-cleanser/internal/parser"
)

type CleanserOpts struct {
	Addr string
	// DNSAddresses must not be empty; addresses are tried in order, failing over on error.
	DNSAddresses []string
	// Workers is the UDP worker count.
	Workers int
	// LogQueries logs every forwarded and blocked query; errors are always logged.
	LogQueries bool
}

type Cleanser struct {
	addr       string
	upstreams  []*net.UDPAddr
	preferred  atomic.Int32 // index of the last upstream that answered
	workers    int
	blacklist  *blacklist.Blacklist
	conns      connTracker
	logQueries bool
}

// NewCleanser resolves the upstream and rejects forwarding loops before anything is bound.
func NewCleanser(opts *CleanserOpts, blacklist *blacklist.Blacklist) (*Cleanser, error) {
	switch {
	case len(opts.DNSAddresses) == 0:
		return nil, errors.New("dns_addresses must not be empty")
	case opts.Workers <= 0:
		return nil, errors.New("workers must be positive")
	}
	listen, err := net.ResolveUDPAddr("udp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address %q: %w", opts.Addr, err)
	}
	upstreams := make([]*net.UDPAddr, 0, len(opts.DNSAddresses))
	for _, address := range opts.DNSAddresses {
		upstream, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, fmt.Errorf("resolve DNS address %q: %w", address, err)
		}
		self, err := isSelf(listen, upstream)
		if err != nil {
			return nil, err
		}
		if self {
			return nil, fmt.Errorf("upstream %s is this server (%s): forwarding loop", upstream, opts.Addr)
		}
		upstreams = append(upstreams, upstream)
	}
	if exposedAddr(listen) {
		log.Printf("warning: listening on %s may expose an open resolver; bind to a LAN or loopback address", opts.Addr)
	}
	return &Cleanser{addr: opts.Addr, upstreams: upstreams, workers: opts.Workers, blacklist: blacklist, logQueries: opts.LogQueries}, nil
}

// Upstream returns the primary upstream address (host:port).
func (c *Cleanser) Upstream() string { return c.upstreams[0].String() }

// shortcut: hardcoded attempt count, make it configurable if anyone asks.
const upstreamAttempts = 2

// exchange runs ex against up to upstreamAttempts upstreams, starting at the last one
// that answered; with a single upstream it retries that one. Only transport errors fail
// over: any valid reply, SERVFAIL included, is returned with the upstream that sent it.
func (c *Cleanser) exchange(q parser.DNSMessage, ex func(*net.UDPAddr, parser.DNSMessage) ([]byte, error)) ([]byte, *net.UDPAddr, error) {
	start := int(c.preferred.Load())
	var errs []error
	for i := range upstreamAttempts {
		idx := (start + i) % len(c.upstreams)
		u := c.upstreams[idx]
		resp, err := ex(u, q)
		if err == nil {
			c.preferred.Store(int32(idx))
			return resp, u, nil
		}
		log.Printf("upstream %s: %v", u, err)
		errs = append(errs, err)
	}
	return nil, nil, errors.Join(errs...)
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
type forwardFunc func(q parser.DNSMessage) ([]byte, error)

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
	resp, err := fwd(msg)
	if err != nil {
		log.Printf("forward for %s: %v", peer, err)
		return msg.Response(parser.ServFail)
	}
	if c.logQueries {
		log.Printf("forward: %s (%d bytes)", peer, len(query))
	}
	return resp
}
