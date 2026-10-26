import random
import resource
import socket
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

# raise the soft fd limit up to the hard limit (macOS default soft limit is 256)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(10240, hard), hard))

HOST, PORT = "127.0.0.1", 15353
THREADS, DURATION = 10, 10  # DURATION in seconds
BIG_ANSWERS = 40

# (case name, transport, domain, expected rcode, expected answer count)
CASES = [
    ("udp-allowed", "udp", "youtube.com", dns.rcode.NOERROR, 1),
    ("tcp-allowed", "tcp", "youtube.com", dns.rcode.NOERROR, 1),
    ("udp-blocked", "udp", "example.ad.com", dns.rcode.NXDOMAIN, 0),
    ("tcp-blocked", "tcp", "example.ad.com", dns.rcode.NXDOMAIN, 0),
    # subdomains of a blocked domain are blocked too
    ("udp-blocked-sub", "udp", "s3.example.ad.com", dns.rcode.NXDOMAIN, 0),
    ("tcp-blocked-sub", "tcp", "s3.example.ad.com", dns.rcode.NXDOMAIN, 0),
    # the UDP reply from upstream is truncated, so the proxy must retry over TCP
    ("udp-big", "udp", "big.example.com", dns.rcode.NOERROR, BIG_ANSWERS),
    ("tcp-big", "tcp", "big.example.com", dns.rcode.NOERROR, BIG_ANSWERS),
]
local = threading.local()


def udp_sock():
    if not hasattr(local, "udp"):
        local.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local.udp.settimeout(3)
    return local.udp


def tcp_sock():
    if not hasattr(local, "tcp"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((HOST, PORT))
        except Exception:
            s.close()
            raise
        local.tcp = s
    return local.tcp


def check(resp, rcode, answers):
    if resp.rcode() != rcode:
        return f"rcode {dns.rcode.to_text(resp.rcode())}, want {dns.rcode.to_text(rcode)}"
    if resp.flags & dns.flags.TC:
        return "truncated reply"
    n = sum(len(rrset) for rrset in resp.answer)
    if n != answers:
        return f"{n} answers, want {answers}"
    if rcode == dns.rcode.NXDOMAIN:
        soa = [r for r in resp.authority if r.rdtype == dns.rdatatype.SOA]
        if len(soa) != 1 or soa[0].ttl != 300:
            return f"want one SOA with TTL 300 in authority, got {resp.authority}"
    return None


def hit():
    name, transport, domain, rcode, answers = random.choice(CASES)
    q = dns.message.make_query(domain, dns.rdatatype.A)
    start = time.perf_counter()
    try:
        if transport == "udp":
            resp = dns.query.udp(q, HOST, port=PORT, timeout=3, sock=udp_sock())
        else:
            resp = dns.query.tcp(q, HOST, port=PORT, timeout=3, sock=tcp_sock())
    except Exception as e:
        if transport == "tcp" and hasattr(local, "tcp"):
            # drop the broken connection so the next request reconnects
            local.tcp.close()
            del local.tcp
        return name, repr(e), 0
    return name, check(resp, rcode, answers), time.perf_counter() - start


def worker(deadline):
    res = []
    while time.perf_counter() < deadline:
        res.append(hit())
    return res


t0 = time.perf_counter()
deadline = t0 + DURATION
with ThreadPoolExecutor(THREADS) as ex:
    futures = [ex.submit(worker, deadline) for _ in range(THREADS)]
    out = [r for f in futures for r in f.result()]
elapsed = time.perf_counter() - t0

print(Counter(e for _, e, _ in out))
for name, *_ in CASES:
    errs = Counter(e for n, e, _ in out if n == name)
    print(f"  {name}: {dict(errs)}")
lat = sorted(t for _, e, t in out if e is None)
if lat:
    print(f"{len(out)/elapsed:.0f} req/s, p50={lat[len(lat)//2]*1000:.1f}ms, p99={lat[int(len(lat)*.99)-1]*1000:.1f}ms")
