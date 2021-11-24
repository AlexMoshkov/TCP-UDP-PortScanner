import argparse
import udp_scanner
import tcp_scanner


def main():
    arg_parser = argparse.ArgumentParser('PortScanner')

    arg_parser.add_argument('ip_address', type=str,
                            help="ip address of the scanning object")
    arg_parser.add_argument('ports', metavar='ports', type=str, nargs='*',
                            help="ports and scanning methods in the specified"
                                 " format [{tcp|udp}[/[PORT|PORT-PORT],...]]")
    arg_parser.add_argument('--timeout', type=float, metavar='TIME', default=2,
                            required=False,
                            help="response timeout (2 seconds by default)")
    arg_parser.add_argument('-j', '--num-threads', type=int, metavar='NUM',
                            required=False, default=512,
                            help="number of threads")
    arg_parser.add_argument('-v', '--verbose', action='store_true',
                            help="enable verbose mode")
    arg_parser.add_argument('-g', '--guess', action='store_true',
                            help="definition of application layer protocols")


    args = arg_parser.parse_args()
    print(args)
    tcp_ports, udp_ports = parse_tcp_udp_ports(args.ports)

    scanned_ports = udp_scanner.scan(args.ip_address, udp_ports,
                                     timeout=args.timeout,
                                     num_threads=args.num_threads)
    scanned_ports += tcp_scanner.scan(args.ip_address, tcp_ports,
                                     timeout=args.timeout,
                                     num_threads=args.num_threads)

    scanned_ports.sort(key=lambda info: (info.scan_protocol, info.port))
    for port_info in filter(lambda p: p.status == "open", scanned_ports):
        port_info.print(verbose=args.verbose, guess=args.guess)


def parse_tcp_udp_ports(groups_ports: [str]) -> ([int], [int]):
    all_tcp_ports = []
    all_udp_ports = []
    for group in groups_ports:
        tcp, udp = parse_group_ports(group)
        all_tcp_ports += tcp
        all_udp_ports += udp
    return all_tcp_ports, all_udp_ports


def parse_group_ports(group: str) -> ([int], [int]):
    split_group = group.split('/')
    protocol = split_group[0]
    ports = []
    if len(split_group) == 2:
        for port_range in split_group[1].split(','):
            if '-' in port_range:
                split_range = port_range.split('-')
                ports += range(int(split_range[0]), int(split_range[1]) + 1)
            else:
                ports += [int(port_range)]
    if protocol.lower() == "tcp":
        return ports, []
    return [], ports


if __name__ == '__main__':
    main()

# scapy использует select в файле libcap.py в классе _L2libpcapSocket в функции select
