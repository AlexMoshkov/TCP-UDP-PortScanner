import socket
import select
from utils import check_dns_echo
from port_info import PortInfo

DNS_MESSAGE = b'\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
              b'\x01h\x0croot-servers\x03net\x00\x00\x01\x00\x01'


def create_sock(address: str, port: int) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(DNS_MESSAGE, (address, port))
    return sock


def get_sockets_dict(address: str, ports: list[int]) -> dict[socket, int]:
    sockets = dict()
    for port in ports:
        sockets[create_sock(address, port)] = port
    return sockets


def scan(address: str, ports: list[int], timeout: float = 2,
         num_threads: int = 50) -> list[PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        sockets = get_sockets_dict(address, ports[i:i + 50])
        rsockets, _, x = select.select(sockets.keys(), [], [], timeout)
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
    ports_infos = scan('1.1.1.1', [68], timeout=2, num_threads=512)
    for port_info in ports_infos:
        print(port_info)
