# Ad Cleanser 
An ad blocking DNS in Go

## Current server behavior

Run `go run .` to listen on TCP and UDP at `127.0.0.1:15353`.
UDP datagrams are forwarded unchanged to `1.1.1.1:53`, and one upstream
response is relayed to the originating client. Successful forwards log endpoint
metadata and byte counts, not payloads. TCP remains an echo service, not DNS over TCP.

Programmatic callers pass options and an explicit `blocklist.Blacklist` value to
`internal.NewCleanser(opts, blacklist)`. The `blocklist` package is imported from
`ad-cleanser/internal/blacklist`; use `blocklist.New(nil)` for an empty blacklist.
The constructor stores this dependency, and the command supplies
`blocklist.New([]string{"example.ad.com"})`. The blacklist is not yet used to
filter DNS traffic; UDP forwarding remains unchanged.

Configure `internal.CleanserOpts.DNSAddresses` using UDP `host:port` addresses
(bracket IPv6 hosts). UDP serving requires a nonempty list and uses only its first
entry, with no failover. Treat options and the blacklist's source slice as
immutable after construction.

UDP exchanges are sequential with a two-second upstream deadline. A failed
exchange is logged and dropped without echoing the request; later requests can
continue. There is no DNS filtering or protocol validation in the forwarding path.

Run `go test -race ./...` for deterministic loopback DNS checks, including a
mock A answer of `67.67.67.67`. Subprocess checks require port `15353` to be free;
tests do not contact a public resolver.