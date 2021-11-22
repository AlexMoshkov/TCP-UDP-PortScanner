class PortInfo:
    def __init__(self, port: int, status: str, scan_protocol: str,
                 protocol: str = None):
        self.port = port
        self.status = status
        self.scan_protocol = scan_protocol
        self.protocol = protocol

    def __str__(self):
        return f"{self.scan_protocol} {self.port} {self.status} {self.protocol}"
