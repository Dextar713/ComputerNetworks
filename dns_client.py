import random

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr1
from scapy.volatile import RandShort

dns_queries = ['www.google.com', 'www.yahoo.com', 'fmi.unibuc.ro']
q_cnt = 0

while q_cnt < len(dns_queries):
    cur_query = random.choice(dns_queries)
    ip = IP(dst='127.0.0.1')
    transport = UDP(sport=RandShort(), dport=5000)  # RandShort() for random source port

    # DNS query: rd = 1 (recursive desired), qname = site-ul dorit
    dns = DNS(rd=1, qd=DNSQR(qname=bytes(cur_query, 'utf-8'), qtype='A'))

    response = sr1(ip / transport / dns, timeout=2)

    if response is None:
        print("No response from server.")
    elif response.haslayer(DNS):
        print(response[DNS].summary())
    elif response.haslayer(Raw):
        dns_parsed = DNS(response[Raw].load)
        print("Manually parsed DNS from Raw:")
        print(dns_parsed.summary())
        print(dns_parsed.an.rdata)  # resolved IP, for example: 1.1.1.1
    else:
        print("Received unknown format:")
        response.show()