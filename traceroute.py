from scapy.all import *
import requests
from scapy.layers.inet import IP, UDP, TCP, ICMP
import matplotlib.pyplot as plt
import networkx as nx
import folium


class Hop:
    def __init__(self, ip, is_public: bool):
        self.ip = ip
        self.public = is_public

    def setInfo(self, country, city, org, longitude, latitude):
        self.country = country
        self.city = city
        self.org = org
        self.longitude = longitude
        self.latitude = latitude

    def __str__(self):
        if self.public:
            return (f"IP: {self.ip}, country: {self.country}, "
                    f"city: {self.city}, org: {self.org}")
        else:
            return f"IP: {self.ip} private"



def traceroute(destination, port=33434, max_hops=30, timeout=2):
    destination_ip = socket.gethostbyname(destination)
    #destination_ip = "34.218.62.116"
    tracert_file = open("traceroute_stats.txt", "a")
    print(f"Tracing route to {destination} [{destination_ip}] "
          f"over a maximum of {max_hops} hops:")
    tracert_file.write(f"Tracing route to {destination} [{destination_ip}] "
          f"over a maximum of {max_hops} hops:\n")

    hops = []
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=destination_ip, ttl=ttl) / UDP(dport=port)
        #pkt = IP(dst=destination_ip, ttl=ttl) / TCP(dport=port, flags="S")
        #pkt = IP(dst=destination_ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=timeout)

        if reply is None:
            print(f"{ttl}\t*")
            continue
        src_ip_info = ip_info(reply.src)
        if 'bogon' in src_ip_info and src_ip_info['bogon']:
            cur_hop = Hop(reply.src, False)
            print(f"{ttl}\t{reply.src}")
            tracert_file.write(f"{ttl}\t{reply.src}\n")
        else:
            cur_hop = Hop(reply.src, True)
            cur_loc = src_ip_info['loc'].split(',')
            cur_lat = float(cur_loc[0])
            cur_long = float(cur_loc[1])
            cur_hop.setInfo(src_ip_info['country'], src_ip_info['city'],
                            src_ip_info['org'], cur_long, cur_lat)
            print(f"{ttl}\t{reply.src} {src_ip_info['city']} {src_ip_info['org']}")
            tracert_file.write(f"{ttl}\t{reply.src} "
                               f"{src_ip_info['city']} {src_ip_info['org']}\n")
        hops.append(cur_hop)
        if reply.type == 3:
            # ICMP Port Unreachable (we reached the destination)
            print("Destination reached!")
            tracert_file.write("Destination reached!\n\n"
                               "--------------------------\n\n")
            break
    tracert_file.close()
    return hops



def ip_info(target_ip):
    api_url = "https://ipinfo.io"
    response = requests.get(f'{api_url}/{target_ip}/json')
    return response.json()
    # print (response.json())


def visualize_traceroute(hops):
    G = nx.DiGraph()  # Directed graph to show direction of hops

    prev_node = "Your Device"
    for i, hop in enumerate(hops, start=1):
        label = hop if hop != "*" else f"Unknown {i}"
        G.add_node(label)
        G.add_edge(prev_node, label)
        prev_node = label

    pos = nx.spring_layout(G, k=1, iterations=50)  # layout for aesthetics
    plt.figure(figsize=(12, 9))
    nx.draw_networkx_nodes(G, pos, node_size=1500, node_color='lightblue')
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=20, arrows=True)
    nx.draw_networkx_labels(G, pos, font_size=10, font_family="sans-serif")

    plt.title("Traceroute Network Graph")
    plt.axis('off')
    plt.tight_layout()
    plt.show()


def plot_route_map(hops):
    public_hops = [hop for hop in hops if hop.public]
    route_map = folium.Map(location=[public_hops[0].latitude,
                             public_hops[0].longitude],
                   zoom_start=4)

    # Add markers and lines
    for i in range(len(public_hops)):
        hop = public_hops[i]
        popup_text = f"{hop.ip}<br>{hop.city}, {hop.country}<br>{hop.org}"
        folium.Marker([hop.latitude, hop.longitude],
                      popup=popup_text).add_to(route_map)

        # Draw line to next hop
        if i > 0:
            prev_lat, prev_lon = public_hops[i - 1].latitude, public_hops[i - 1].longitude
            folium.PolyLine(locations=[[prev_lat, prev_lon],
                                       [hop.latitude, hop.longitude]],
                            color='blue').add_to(route_map)

    # Save to HTML and open in browser
    route_map.save("traceroute_map.html")


if __name__ == '__main__':
    # hops = traceroute(sys.argv[1], timeout=10)
    all_hops = traceroute("python.org", timeout=10)
    plot_route_map(all_hops)
    # visualize_traceroute([hop.ip for hop in all_hops])
    # res = ip_info("142.251.140.46")
    # print(res)
