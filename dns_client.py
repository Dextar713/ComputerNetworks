import socket
from scapy.layers.dns import DNS, DNSQR
from scapy.all import raw

dns_queries = ['www.google.com', 'www.yahoo.com', 'fmi.unibuc.ro', '0001-cab8-4c8c-43de.reporo.net', 'quit']

for query in dns_queries:
    # Build DNS request using Scapy (for correctness)
    dns_request = DNS(rd=1, qd=DNSQR(qname=query))
    raw_data = raw(dns_request)

    # Create UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)

    try:
        # Send raw DNS query to custom DNS server on localhost:5000
        client_socket.sendto(raw_data, ("127.0.0.1", 5000))

        # Wait for response
        response_data, _ = client_socket.recvfrom(1024)

        # Parse the response using Scapy
        dns_response = DNS(response_data)

        print(f"Query: {query}")
        if dns_response.an:
            print(f"Answer: {dns_response.an.rdata}")
        else:
            print("No answer section in response")

    except socket.timeout:
        print(f"Query: {query} -> No response (timeout)")

    finally:
        client_socket.close()
