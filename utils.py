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
