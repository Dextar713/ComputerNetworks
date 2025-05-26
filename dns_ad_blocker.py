import socket

from scapy.layers.dns import DNS, DNSRR

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 5000))

while True:
    request, src_address = simple_udp.recvfrom(65535)
    if request == bytes('quit', 'utf-8'):
        break
    # converitm payload-ul in pachet scapy
    packet = DNS(request)
    dns = packet.getlayer(DNS)
    if dns is not None and dns.opcode == 0: # dns QUERY
        print ("got: ")
        print (packet.summary())
        try:
            resolved_ip = socket.gethostbyname(dns.qd.qname.decode().strip('.'))
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