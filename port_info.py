class PortInfo:
    def __init__(self, port: int, status: str, scan_protocol: str,
                 recv_time: float, protocol: str = '-') -> None:
        self.port = port
        self.status = status
        self.scan_protocol = scan_protocol
        self.protocol = protocol
        self.recv_time = round(recv_time, 1)

    def print(self, verbose: bool = False, guess: bool = False) -> None:
        recv_time = f"{self.recv_time:<5}" if verbose else ""
        protocol = self.protocol if guess else ""
        print(f"{self.scan_protocol:<5}{self.port:<5} {recv_time} {protocol:<3}")

    def __str__(self):
        return f"{self.scan_protocol} {self.port} {self.status} {self.protocol}"
