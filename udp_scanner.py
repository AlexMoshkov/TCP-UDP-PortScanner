import socket
import select

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, ICMP

from utils import check_dns_echo, get_sockets_dict
from port_info import PortInfo
from scapy.all import *

DNS_MESSAGE = b'\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
              b'\x01h\x0croot-servers\x03net\x00\x00\x01\x00\x01'


def create_udp_sock(address: str, port: int) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(DNS_MESSAGE, (address, port))
    return sock

def create_udp_packet(address: str, port: int):
    pkt = sr1(IP(dst=address)/UDP(sport=port, dport=port)/DNS(DNS_MESSAGE), verbose=0)
    r, w, x = select.select([pkt], [], [], 2)
    print(r)
    # if pkt == None:
    #     print(f"{port} open")
    # else:
    #     print(pkt)
    #     if pkt.haslayer(ICMP):
    #         print(f"{port} close")
    #     elif pkt.haslayer(DNS):
    #         print(f"{port} dns")
    #     elif pkt.haslayer(UDP):
    #         print(f"{port} open udp")
    #     else:
    #         print(f"{port} unknown")


def scan(address: str, ports: list[int], timeout: float = 2,
         num_threads: int = 512) -> list[PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        sockets = get_sockets_dict(address, ports[i:i + 50], create_udp_sock)
        rsockets, _, _ = select.select(sockets.keys(), [], [], timeout)
        for sock, port in sockets.items():
            status = "open"
            protocol = None
            if sock in rsockets:
                try:
                    data, addr = sock.recvfrom(4096)
                    protocol = check_dns_echo(data, DNS_MESSAGE)
                except ConnectionResetError:
                    status = "close"
            ports_infos.append(PortInfo(port, status, "UDP", protocol))
    return ports_infos


if __name__ == '__main__':
    create_udp_packet('1.1.1.1', 53)
    # ports_infos = scan('1.1.1.1', [68], timeout=2, num_threads=512)
    # for port_info in ports_infos:
    #     print(port_info)
