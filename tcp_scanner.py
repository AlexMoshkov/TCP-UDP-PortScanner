import select
from struct import pack
import socket

from port_info import PortInfo
from utils import get_sockets_dict
from scapy.all import *


def calc_checksum(package: Union[str, bytes]):
    checksum = 0
    for i in range(0, len(package), 2):
        checksum += package[i] + (package[i + 1] << 8)

    checksum = (checksum >> 8) + (checksum & 0xffff)
    checksum += checksum >> 16
    checksum = ~checksum & 0xffff
    return checksum


def create_tcp_header(address: str, port: int) -> bytes:
    src_port = 55555
    dest_port = port
    seq_nr = 454
    ack_nr = 0
    offset = 5

    urg, ack, psh, rst, syn, fin = 0, 0, 0, 0, 1, 0
    window = socket.htons(5840)
    checksum = 0
    urg_pointer = 0

    packet_offset = (offset << 4) | 0
    flags = fin | (syn << 1) | (rst << 2) | (psh << 3) | (ack << 4) | (
            urg << 5)

    tcp_header = pack('!HHLLBBHHH', src_port, dest_port, seq_nr, ack_nr,
                      packet_offset, flags, window, checksum,
                      urg_pointer)

    psh = pack('!4s4sBBH', socket.inet_aton('0.0.0.0'),
               socket.inet_aton(address), 0,
               socket.IPPROTO_TCP, len(tcp_header)) + tcp_header
    checksum = calc_checksum(psh)

    tcp_header = pack("!HHLLBBH", src_port, dest_port, seq_nr, ack_nr,
                      packet_offset, flags, window)
    tcp_header += pack('H', checksum) + pack('!H', urg_pointer)
    return tcp_header


def create_tcp_socket(address: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind((address, port))
    package = create_tcp_header(address, port)
    sock.send(package)
    return sock


def scan(address: str, ports: [int], timeout: float = 2,
         num_threads: int = 512) -> [PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        sockets = get_sockets_dict(address, ports[i:i + 50], create_tcp_socket)
        rsockets, _, _ = select.select(sockets.keys(), [], [], timeout)
        for sock, port in sockets.items():
            if sock in rsockets:
                pass


if __name__ == '__main__':
    s = create_tcp_socket('8.8.8.8', 53)
    rsoc, _, _ = select.select([s], [], [], 2)
    for sr in rsoc:
        data, _ = sr.recv(4096)
        print(data)
