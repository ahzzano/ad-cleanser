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
	// Workers is the UDP worker count; QueueSize is the pending-queue length.
	Workers   int
	QueueSize int
}

type Cleanser struct {
	addr      string
	upstream  *net.UDPAddr
	workers   int
	queueSize int
	blacklist blacklist.Blacklist
	conns     connTracker
}

// NewCleanser resolves the upstream and rejects forwarding loops before anything is bound.
func NewCleanser(opts *CleanserOpts, blacklist blacklist.Blacklist) (*Cleanser, error) {
	switch {
	case len(opts.DNSAddresses) == 0:
		return nil, errors.New("dns_addresses must not be empty")
	case opts.Workers <= 0:
		return nil, errors.New("workers must be positive")
	case opts.QueueSize < 0:
		return nil, errors.New("queue size must not be negative")
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
	if exposedAddr(listen) {
		log.Printf("warning: listening on %s may expose an open resolver; bind to a LAN or loopback address", opts.Addr)
	}
	if self {
		return nil, fmt.Errorf("upstream %s is this server (%s): forwarding loop", upstream, opts.Addr)
	}
	return &Cleanser{addr: opts.Addr, upstream: upstream, workers: opts.Workers, queueSize: opts.QueueSize, blacklist: blacklist}, nil
}

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
	udp.SetReadDeadline(time.Now()) // socket stays open so queued jobs can still reply

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

// resolve decides the reply for a query. A non-nil resp must always be sent, even
// when err != nil (err is for logging); a nil resp means send nothing.
func (c *Cleanser) resolve(query []byte, peer net.Addr, fwd forwardFunc) ([]byte, error) {
	msg, err := parser.ParseDNSMessage(query)
	if err != nil {
		return parser.ErrorResponse(query, parser.FormErr), err
	}
	if msg.IsResponse() {
		return nil, nil
	}
	// fail pairs an error rcode reply with cause.
	fail := func(rcode uint16, cause error) ([]byte, error) {
		r, rerr := msg.Response(rcode)
		if rerr != nil {
			r = nil
		}
		return r, cause
	}
	if msg.Opcode() != 0 {
		return fail(parser.NotImp, fmt.Errorf("unsupported opcode %d", msg.Opcode()))
	}
	resp, err := c.blockedResponse(msg, peer)
	if err != nil {
		return fail(parser.FormErr, err)
	}
	if resp != nil {
		return resp, nil
	}
	resp, err = fwd(query)
	if err != nil {
		return fail(parser.ServFail, err)
	}
	log.Printf("forward: %s (%d bytes)", peer, len(query))
	return resp, nil
}

// blockedResponse returns the block response if any question is blacklisted, else nil, nil.
func (c *Cleanser) blockedResponse(msg parser.DNSMessage, peer net.Addr) ([]byte, error) {
	questions, err := msg.Questions()
	if err != nil {
		return nil, err
	}
	for _, q := range questions {
		if c.blacklist.IsBlocked(q.Name) {
			log.Printf("blocked %q from %s", q.Name, peer)
			return msg.BlockResponse()
		}
	}
	return nil, nil
}

// exposedAddr reports whether listen could be reachable from outside a home network.
func exposedAddr(listen *net.UDPAddr) bool {
	ip := listen.IP
	if len(ip) == 0 || ip.IsUnspecified() {
		return true
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}
