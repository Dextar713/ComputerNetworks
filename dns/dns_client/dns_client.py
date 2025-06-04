import os
import socket
from scapy.layers.dns import DNS, DNSQR
from scapy.all import raw

server_port = int(os.getenv("DNS_PORT", 5000))
dns_queries = ['www.google.com', 'www.yahoo.com', 'fmi.unibuc.ro', '0001-cab8-4c8c-43de.reporo.net']
server_ip = '127.0.0.1'
if server_port == 53:
    server_ip = 'dns_server'

def launch_dns_client():
    for query in dns_queries:
        # Build DNS request using Scapy (for correctness)
        dns_request = DNS(rd=1, qd=DNSQR(qname=query))
        raw_data = raw(dns_request)

        # Create UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(2)

        try:
            # Send raw DNS query to custom DNS server on localhost:5000
            client_socket.sendto(raw_data, (server_ip, server_port))

            # Wait for response
            response_data, _ = client_socket.recvfrom(1024)

            # Parse the response using Scapy
            dns_response = DNS(response_data)

            print(f"Query: {query}", flush=True)
            if dns_response.an:
                print(f"Answer: {dns_response.an.rdata}", flush=True)
            else:
                print("No answer section in response", flush=True)

        except socket.timeout:
            print(f"Query: {query} -> No response (timeout)", flush=True)

        finally:
            client_socket.close()

if __name__ == '__main__':
    launch_dns_client()
