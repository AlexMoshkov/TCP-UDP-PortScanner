class PortInfo:
    def __init__(self, port: int, status: str, scan_protocol: str,
                 recv_time: float, protocol: str = '-') -> None:
        self.port = port
        self.status = status
        self.scan_protocol = scan_protocol
        self.protocol = protocol
        self.recv_time = recv_time


    def __str__(self):
        return f"{self.scan_protocol} {self.port} {self.status} {self.protocol}"
