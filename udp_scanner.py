import socket
import select
from utils import check_protocol_by_data
from port_info import PortInfo


def create_sock(address: str, port: int) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b'\n\n', (address, port))
    return sock


def get_sockets_dict(address: str, ports: [int]) -> dict[socket, int]:
    sockets = dict()
    for port in ports:
        sockets[create_sock(address, port)] = port
    return sockets


def scan(address: str, ports: [int], timeout: float = 2, num_threads: int = 50) -> [PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        sockets = get_sockets_dict(address, ports[i:i+50])
        rsockets, _, x = select.select(sockets.keys(), [], [], timeout)
        for sock, port in sockets.items():
            status = "open"
            protocol = None
            if sock in rsockets:
                data, addr = sock.recvfrom(4096)
                print(f"{port}: {data}")
                protocol = check_protocol_by_data(data)
                if protocol == "ERROR":
                    status = "close"
                    protocol = None
            ports_infos.append(PortInfo(port, status, "UDP", protocol))
    return ports_infos

if __name__ == '__main__':
    ports_infos = scan('176.59.211.104', [5000], timeout=2)
    for port_info in ports_infos:
        print(port_info)
