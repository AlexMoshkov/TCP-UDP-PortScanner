import select
from struct import pack
import socket
from dnslib import DNSRecord, DNSError
from scapy.layers.inet import IP, TCP, ICMP

from port_info import PortInfo
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


DNS_MESSAGE = b'\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01' \
              b'h\x0croot-servers\x03net\x00\x00\x01\x00\x01'

HTTP_MESSAGE = "GET / HTTP/1.1\nHost: andgein.ru\n\n".encode()


def check_protocol(address: str, port: int) -> str:
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((address, port))

    conn.send(DNS_MESSAGE)
    data = conn.recv(4096)
    try:
        parse_data = DNSRecord.parse(data)
        print(parse_data.q)
        return 'dns'
    except DNSError:
        pass
    if data == DNS_MESSAGE:
        return 'echo'

    conn.send(HTTP_MESSAGE)
    data = conn.recv(4096)
    print(data)
    if "HTTP".encode() in data:
        return 'http'
    else:
        return '-'


def scan(address: str, ports: [int], timeout: float = 2,
         num_threads: int = 512) -> [PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        ports_group = ports[i:i + num_threads]
        recv_start = time.time()
        answered, unanswered = sr(IP(dst=address) / TCP(sport=55555, dport=ports_group, flags="S"),timeout=timeout)
        recv_time = (time.time() - recv_start) * 1000
        time.sleep(2)
        for pkt in unanswered:
            print(pkt[TCP].flags)
            ports_infos.append(PortInfo(pkt.dport, "close", "tcp", recv_time))
        for pkt, ans in answered:
            print(ans[TCP].flags)
            print(pkt.dport)
            if ans.haslayer(TCP) and ans[TCP].flags == 18:  # syn ack
                protocol = check_protocol(address, pkt.dport)
                ports_infos.append(
                    PortInfo(pkt.dport, "open", "tcp", recv_time, protocol))
    return ports_infos


if __name__ == '__main__':
    ports_infos = scan('80.93.177.132', range(50, 90), num_threads=2)
    for port_info in ports_infos:
        print(port_info)
