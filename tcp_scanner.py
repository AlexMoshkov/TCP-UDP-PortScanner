from dnslib import DNSRecord, DNSError
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Loopback

from port_info import PortInfo
from scapy.all import *

DNS_MESSAGE = b'\x00\x24\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01h\x0croot-servers\x03net\x00\x00\x01\x00\x01'

HTTP_MESSAGE = b'GET / HTTP/1.1\nHost: localhost\n\n'


def send_message(address: str, port: int, message: bytes,
                 timeout: float = 2) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((address, port))
    data = b''
    try:
        s.send(message)
        data = s.recv(4096)
    except socket.error:
        pass
    finally:
        s.close()
    return data


def check_protocol(address: str, port: int, timeout: float = 2) -> str:
    data = send_message(address, port, DNS_MESSAGE, timeout)
    if data == DNS_MESSAGE:
        return 'echo'
    try:
        DNSRecord.parse(data[2:])
        return 'dns'
    except DNSError:
        pass
    data = send_message(address, port, HTTP_MESSAGE, timeout)
    if b'220' == data[:3]:
        return 'smtp'
    if b'HTTP' in data:
        return 'http'
    elif b'SSH' in data:
        return 'ssh'
    return '-'


def scan(address: str, ports: [int], timeout: float = 2,
         num_threads: int = 200) -> [PortInfo]:
    ports_infos = []
    conf.L3socket = L3RawSocket
    for i in range(0, len(ports), num_threads):
        ports_group = ports[i:i + num_threads]
        conf.L3socket = L3RawSocket
        t = time.time()
        answered, unanswered = sr(
            IP(dst=address) / TCP(sport=55555, dport=ports_group, flags="S"),
            timeout=timeout, verbose=0)
        print(time.time() - t)
        for pkt in unanswered:
            ports_infos.append(
                PortInfo(pkt.dport, "open|filtered", "TCP", timeout * 1000))
        for pkt, ans in answered:
            status = 'open|f`iltered'
            protocol = '-'
            if ans.haslayer(TCP) and ans[TCP].flags == 18:  # syn ack
                status = 'open'
                protocol = check_protocol(address, pkt.dport, timeout)
            elif ans.haslayer(TCP) and ans[TCP].flags == 20:  # rst ack
                status = 'close'
            ports_infos.append(PortInfo(ans.sport, status, "TCP",
                                        (ans.time - pkt.sent_time) * 1000,
                                        protocol))
    return ports_infos
