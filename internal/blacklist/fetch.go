package blacklist

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FetchLists downloads hosts-format lists in the background, one goroutine per URL,
// and blocks each domain as soon as its line is parsed. Hostnames are resolved via
// upstream, since this process may be the system resolver and not be listening yet.
// A failed URL is logged and skipped. The returned channel closes once all lists are in.
func (b *Blacklist) FetchLists(urls []string, upstream string) <-chan struct{} {
	client := upstreamClient(upstream)
	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Go(func() { fetchList(client, url, b.Block) })
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		b.mu.RLock()
		n := len(b.blocked)
		b.mu.RUnlock()
		log.Printf("blacklist: %d domains blocked in total", n)
		close(done)
	}()
	return done
}

func upstreamClient(upstream string) *http.Client {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstream)
		},
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: resolver}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext},
	}
}

func fetchList(client *http.Client, url string, block func(string)) {
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("blacklist %s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("blacklist %s: %s", url, resp.Status)
		return
	}
	n, err := parseHosts(resp.Body, block)
	if err != nil {
		log.Printf("blacklist %s: partial: %d domains before error: %v", url, n, err)
		return
	}
	log.Printf("blacklist %s: loaded %d domains in %s", url, n, time.Since(start).Round(time.Millisecond))
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
