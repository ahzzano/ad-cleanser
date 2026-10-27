package blacklist

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FetchLists downloads hosts-format lists in the background, one goroutine per URL,
// and blocks each domain as soon as its line is parsed. Hostnames are resolved via the
// upstreams in order (first that answers wins), since this process may be the system
// resolver and not be listening yet.
// Once all lists are in, the returned channel delivers nil, or every per-URL failure
// joined (failed lists may have been partially applied), and then closes.
func (b *Blacklist) FetchLists(urls []string, upstreams []string) <-chan error {
	client := upstreamClient(upstreams)
	var wg sync.WaitGroup
	errs := make([]error, len(urls))
	for i, url := range urls {
		wg.Go(func() { errs[i] = fetchList(client, url, b.Block) })
	}
	done := make(chan error, 1)
	go func() {
		wg.Wait()
		log.Printf("blacklist: %d domains blocked in total", b.Len())
		done <- errors.Join(errs...)
		close(done)
	}()
	return done
}

func upstreamClient(upstreams []string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		ips, err := lookup(ctx, upstreams, host)
		if err != nil {
			return nil, err
		}
		var errs []error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dial},
	}
}

// lookup resolves host via each upstream in turn, giving each 3 seconds, and returns the first answer.
func lookup(ctx context.Context, upstreams []string, host string) ([]net.IPAddr, error) {
	var errs []error
	for _, up := range upstreams {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, up)
		}}
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := r.LookupIPAddr(lctx, host)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		errs = append(errs, fmt.Errorf("lookup %s via %s: %w", host, up, err))
	}
	return nil, errors.Join(errs...)
}

// fetchList streams one list into block. A request error, non-200 status, read error,
// or a list with no domains (e.g. an HTML error page) is a failure.
func fetchList(client *http.Client, url string, block func(string)) error {
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("blacklist %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("blacklist %s: %s", url, resp.Status)
	}
	n, err := parseHosts(resp.Body, block)
	if err != nil {
		return fmt.Errorf("blacklist %s: partial: %d domains before error: %w", url, n, err)
	}
	if n == 0 {
		return fmt.Errorf("blacklist %s: no domains", url)
	}
	log.Printf("blacklist %s: loaded %d domains in %s", url, n, time.Since(start).Round(time.Millisecond))
	return nil
}

// hostsJunk are loopback/local names that hosts files map; blocking them breaks local tooling.
var hostsJunk = map[string]struct{}{
	"localhost": {}, "localhost.localdomain": {}, "local": {}, "broadcasthost": {},
	"ip6-localhost": {}, "ip6-loopback": {}, "ip6-localnet": {}, "ip6-mcastprefix": {},
	"ip6-allnodes": {}, "ip6-allrouters": {}, "ip6-allhosts": {},
}

// parseHosts streams domains from "IP domain..." or bare-domain lines; # starts a comment.
func parseHosts(r io.Reader, block func(string)) (int, error) {
	n := 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) > 1 {
			fields = fields[1:] // drop the IP
		}
		for _, f := range fields {
			if _, junk := hostsJunk[strings.ToLower(f)]; junk || net.ParseIP(f) != nil {
				continue
			}
			block(f)
			n++
		}
	}
	return n, sc.Err()
}
