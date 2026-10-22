import socketserver

import dns.message
import dns.rdatatype
import dns.rrset

PORT = 25565


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        for q in query.question:
            if q.rdtype == dns.rdatatype.A:
                response.answer.append(dns.rrset.from_text(q.name, 60, "IN", "A", "1.2.3.4"))
        sock.sendto(response.to_wire(), self.client_address)


if __name__ == "__main__":
    with socketserver.UDPServer(("127.0.0.1", PORT), Handler) as server:
        print(f"sample DNS server on 127.0.0.1:{PORT}")
        server.serve_forever()
