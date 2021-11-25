from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, ICMP
from port_info import PortInfo
from scapy.all import *

DNS_MESSAGE = b'\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01' \
              b'h\x0croot-servers\x03net\x00\x00\x01\x00\x01'


def check_dns_echo(query: IP, answer: IP) -> str:
    if answer.haslayer(DNS):
        return 'dns'
    elif raw(answer[Raw]) == raw(query[DNS]):
        return 'echo'
    return '-'


def scan(address: str, ports: list[int], timeout: float = 2,
         num_threads: int = 512) -> list[PortInfo]:
    ports_infos = []
    for i in range(0, len(ports), num_threads):
        ports_group = ports[i:i + num_threads]
        answered, unanswered = sr(
            IP(dst=address) / UDP(sport=55555, dport=ports_group) / DNS(DNS_MESSAGE),
            timeout=timeout, verbose=0, multi=True)
        for req in unanswered:
            ports_infos.append(
                PortInfo(req.dport, "open|filtered", "udp", timeout*1000))

        for req, ans in answered:
            status = "filtered"
            protocol = '-'
            if ans.haslayer(UDP):
                status = "open"
                protocol = check_dns_echo(req, ans)
            elif ans.haslayer(ICMP):
                if ans[ICMP].type == 3 and ans[ICMP].code == 3:
                    status = "close"
                else:
                    status = "open|filtered"
            ports_infos.append(
                PortInfo(ans.sport, status, "udp", (ans.time - req.sent_time)*1000, protocol))
    return ports_infos
