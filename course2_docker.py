import socket

sock_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
port_server = 10000
adresa_server = 'localhost'
server_address = (adresa_server, port_server)
sock_server.bind(server_address)

sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
port_client, adresa_client = 10001, 'localhost'
client_address = (adresa_client, port_client)
sock_client.bind(client_address)

octeti = b"salut de la client cu"
octeti = octeti + "你好".encode('utf-8')
octeti = octeti + bytes("你好", 'utf-8')

sent = sock_client.sendto(octeti, server_address)
print(sent)
data, address = sock_server.recvfrom(33)
print(data, address)
sock_server.sendto(b"Data received", client_address)
sock_server.close()
sock_client.close()
