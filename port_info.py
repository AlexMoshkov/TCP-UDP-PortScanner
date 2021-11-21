class PortInfo:
    def __init__(self, port, status, scan_protocol, protocol=None):
        self.port = port
        self.status = status
        self.scan_protocol =scan_protocol
        self.protocol = protocol

    def __str__(self):
        return f"{self.scan_protocol} {self.port} {self.status}"
