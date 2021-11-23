from socket import socket
from typing import Callable
from dnslib import DNSRecord, DNSError


def check_dns_echo(data: bytes, send_data: bytes) -> str:
    try:
        dns_parse = DNSRecord.parse(data)
        return "dns"
    except DNSError:
        pass

    if data == send_data:
        return "echo"
    return "unknown"


def get_sockets_dict(
        address: str, ports: list[int],
        create_sock: Callable[[str, int], socket]) -> dict[socket, int]:
    sockets = dict()
    for port in ports:
        sockets[create_sock(address, port)] = port
    return sockets
