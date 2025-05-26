import socket
import sqlite3
from scapy.layers.dns import DNS, DNSRR
from add_blocked_hosts import DB_NAME


def is_blocked(domain):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM blacklist WHERE domain = ?", (domain,))
    result = cur.fetchone()  # returns None if no rows matched

    conn.close()
    return result is not None


simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 5000))
print("DNS server listening on port: 5000")

while True:
    request, src_address = simple_udp.recvfrom(65535)
    # converitm payload-ul in pachet scapy
    packet = DNS(request)
    dns = packet.getlayer(DNS)
    if dns is not None and dns.opcode == 0: # dns QUERY
        print ("got: ")
        print (packet.summary())
        target_domain = dns.qd.qname.decode().strip('.')
        if target_domain == 'quit':
            break 
        if is_blocked(target_domain):
            resolved_ip = '0.0.0.0'
        else:
            try:
                resolved_ip = socket.gethostbyname(target_domain)
            except socket.gaierror:
                resolved_ip = '0.0.0.0'
        dns_answer = DNSRR(      # DNS Reply
           rrname=dns.qd.qname, # for question
           ttl=330,             # DNS entry Time to Live
           type="A",
           rclass="IN",
           rdata=resolved_ip)     # found at IP: 1.1.1.1 :)
        dns_response = DNS(
          id = packet[DNS].id, # DNS replies must have the same ID as requests
          qr = 1,              # 1 for response, 0 for query
          aa = 1,              # Authoritative Answer
          rcode = 0,           # 0, nicio eroare http://www.networksorcery.com
          qdcount = 1,
          ancount = 1,
          qd = packet.qd,      # request-ul original
          an = dns_answer)     # obiectul de reply
        print('response:')
        print (dns_response.summary())
        simple_udp.sendto(bytes(dns_response), src_address)


simple_udp.close()