import random
import resource
import socket
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import dns.message
import dns.query
import dns.rdatatype

# raise the soft fd limit up to the hard limit (macOS default soft limit is 256)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(10240, hard), hard))

TARGETS = ["doubleclick.net", "youtube.com"]
THREADS, DURATION = 10, 10  # DURATION in seconds
local = threading.local()

def hit():
    # one socket per worker thread, reused across requests
    if not hasattr(local, "sock"):
        local.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local.sock.settimeout(3)
        local.sock.connect(("127.0.0.1", 15353))
    q = dns.message.make_query(random.choice(TARGETS), dns.rdatatype.A)
    start = time.perf_counter()
    try:
        dns.query.tcp(q, "127.0.0.1", port=15353, timeout=3, sock=local.sock)
    except Exception as e:
        # drop the broken connection so the next request reconnects
        local.sock.close()
        del local.sock
        return repr(e), 0
    return None, time.perf_counter() - start

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

print(Counter(e for e, _ in out))
lat = sorted(t for e, t in out if e is None)
if lat:
    print(f"{len(out)/elapsed:.0f} req/s, p50={lat[len(lat)//2]*1000:.1f}ms, p99={lat[int(len(lat)*.99)-1]*1000:.1f}ms")
