import socketserver
import struct
import threading

import dns.exception
import dns.flags
import dns.message
import dns.rdatatype
import dns.rrset

PORT = 25565
UDP_LIMIT = 512
BIG_ANSWERS = 40


def build_response(data, limit=None):
    query = dns.message.from_wire(data)
    response = dns.message.make_response(query)
    for q in query.question:
        if q.rdtype != dns.rdatatype.A:
            continue
        # names starting with "big" get a reply too large for plain UDP
        count = BIG_ANSWERS if q.name.labels[0].startswith(b"big") else 1
        for i in range(count):
            response.answer.append(dns.rrset.from_text(q.name, 60, "IN", "A", f"1.2.3.{i + 4}"))
    if limit is None:
        return response.to_wire()
    try:
        return response.to_wire(max_size=limit)
    except dns.exception.TooBig:
        response.flags |= dns.flags.TC
        response.answer.clear()
        return response.to_wire()


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(build_response(data, UDP_LIMIT), self.client_address)


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            hdr = read_exact(self.request, 2)
            if hdr is None:
                return
            data = read_exact(self.request, struct.unpack("!H", hdr)[0])
            if data is None:
                return
            resp = build_response(data)
            self.request.sendall(struct.pack("!H", len(resp)) + resp)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with TCPServer(("127.0.0.1", PORT), TCPHandler) as tcp, \
            socketserver.ThreadingUDPServer(("127.0.0.1", PORT), UDPHandler) as udp:
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        print(f"sample DNS server on 127.0.0.1:{PORT} (udp+tcp)")
        udp.serve_forever()
