from dnslib import DNSRecord, DNSError
from port_info import PortInfo
from scapy.all import *

DNS_MESSAGE = b'\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01' \
              b'h\x0croot-servers\x03net\x00\x00\x01\x00\x01'


def check_dns_echo(data: bytes, send_data: bytes) -> str:
    try:
        dns_parse = DNSRecord.parse(data)
        return "dns"
    except DNSError:
        pass

    if data == send_data:
        return "echo"
    return "unknown"


def create_udp_sock(address: str, port: int) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(DNS_MESSAGE, (address, port))
    return sock


def get_sockets_dict(address: str, ports: list[int]) -> dict[socket, int]:
    sockets = dict()
    for port in ports:
        sockets[create_udp_sock(address, port)] = port
    return sockets


def scan(address: str, ports: list[int], timeout: float = 2,
         num_threads: int = 512) -> list[PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        recv_start = time.time()
        sockets = get_sockets_dict(address, ports[i:i + num_threads])
        rsockets, _, _ = select.select(sockets.keys(), [], [], timeout)
        recv_time = (time.time() - recv_start) * 1000
        for sock, port in sockets.items():
            status = "filtered"
            protocol = '-'
            if sock in rsockets:
                try:
                    data, addr = sock.recvfrom(4096)
                    protocol = check_dns_echo(data, DNS_MESSAGE)
                    status = "open"
                except ConnectionResetError:
                    status = "close"
            ports_infos.append(
                PortInfo(port, status, "UDP", recv_time, protocol))
    return ports_infos


if __name__ == '__main__':
    ports_infos = scan('80.93.177.132', range(0, 100), timeout=2,
                       num_threads=512)
    for port_info in ports_infos:
        print(port_info)
