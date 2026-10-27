# Ad Cleanser 
An ad blocking DNS in Go

## Current server behavior

Run `go run .` to listen on TCP and UDP at `127.0.0.1:15353`.
Well-formed UDP queries are forwarded unchanged to `1.1.1.1:53`, and one upstream
response is relayed to the originating client. Per-query logs (forwarded and blocked
queries) are off unless `log_queries: true` is set in the config; errors are always logged. TCP remains an echo service, not DNS over TCP.

Bind to a loopback or LAN address. A public bind (`:53`, `0.0.0.0`) lets anyone use the
server for reflection attacks; startup logs a warning in that case.

Programmatic callers pass options and an explicit `blacklist.Blacklist` value to
`internal.NewCleanser(opts, blacklist)`. The `blacklist` package is imported from
`ad-cleanser/internal/blacklist`; use `blacklist.New(nil)` for an empty blacklist.
The constructor stores this dependency, and the command supplies
`blacklist.New([]string{"example.ad.com"})`. A UDP query with exactly one question is required; others are dropped without a reply.
Blacklist matching is case-insensitive and also covers subdomains. The config lists
`domains.blocked` and `domains.allowed`; allowed names (and their subdomains) are exempt,
and the most specific match wins, so allowing `example.com` does not unblock a blocked
`ads.example.com`. A UDP query with a blacklisted
question name is not forwarded; it gets a locally built NXDOMAIN (header plus
question section only, no EDNS OPT record) plus an SOA in the authority section so
clients cache the block for 300 seconds.

Type `r` on stdin to reload the config and blocklists. The new policy is swapped in
atomically only if every list loads (HTTP 200, fully read, at least one domain); otherwise
the current policy is kept and the error is logged.

Configure `internal.CleanserOpts.DNSAddresses` using UDP `host:port` addresses
(bracket IPv6 hosts). The list must be nonempty. Each query gets two attempts
(2s timeout each), starting at the upstream that last answered and failing over to
the next entry on transport errors; with one entry it is retried once. An upstream that points at this server's own listen
endpoint is rejected at startup to avoid a forwarding loop. Treat options and
the blacklist's source slice as immutable after construction.

UDP replies are limited to 512 bytes, or the EDNS0 size the client advertises; larger
replies are returned truncated (TC set, header and question only) so the client retries over TCP.
Limit is max(512, client OPT size); a truncated reply keeps ID, QR/opcode/RD and rcode, and zeroes the
answer/authority/additional counts. EDNS is passthrough only: the proxy never generates or echoes an OPT
record, and queries are forwarded unchanged, so the upstream sees the client's advertised size.
TCP replies are never truncated.

UDP exchanges are sequential with a two-second upstream deadline. A failed
exchange is logged and dropped without echoing the request; later requests can
continue. Malformed queries are logged and dropped without a reply.

Run `go test -race ./...` for deterministic loopback DNS checks, including a
mock A answer of `67.67.67.67`. Subprocess checks require port `15353` to be free;
tests do not contact a public resolver.
