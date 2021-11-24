from dnslib import DNSRecord, DNSError
from scapy.layers.inet import IP, TCP
from port_info import PortInfo
from scapy.all import *

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
    print(port)
    conn.close()

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((address, port))
    conn.send(HTTP_MESSAGE)
    data = conn.recv(4096)
    if "HTTP".encode() in data:
        return 'http'
    elif "SSH".encode() in data:
        return 'ssh'
    else:
        return '-'


def scan(address: str, ports: [int], timeout: float = 2,
         num_threads: int = 512) -> [PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        ports_group = ports[i:i + num_threads]
        recv_start = time.time()
        answered, unanswered = sr(
            IP(dst=address) / TCP(sport=55555, dport=ports_group, flags="S"),
            timeout=timeout, verbose=0, multi=True)
        recv_time = (time.time() - recv_start) * 1000
        for pkt in unanswered:
            ports_infos.append(PortInfo(pkt.dport, "close", "TCP", recv_time))
        for pkt, ans in answered:
            status = 'filtered'
            protocol = '-'
            if ans.haslayer(TCP) and ans[TCP].flags == 18:  # syn ack
                status = 'open'
                protocol = check_protocol(address, pkt.dport)
            elif ans.haslayer(TCP) and ans[TCP].flags == 20:  # rst ack
                status = 'close'
            ports_infos.append(
                PortInfo(pkt.dport, status, "TCP", recv_time, protocol))
    return ports_infos


if __name__ == '__main__':
    ports_infos = scan('80.93.177.132', range(0, 20000), num_threads=20000)
    for port_info in ports_infos:
        print(port_info)
