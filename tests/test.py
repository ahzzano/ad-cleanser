import dns.message
import dns.query
import dns.rdatatype

request = dns.message.make_query("example.ad.com", dns.rdatatype.A)
print(request)
response = dns.query.udp(request, "127.0.0.1", port=15353, timeout=3)
print(response)