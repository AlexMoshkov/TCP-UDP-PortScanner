import argparse
import socket
import logging
import udp_scanner
import tcp_scanner


def main():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    arg_parser = argparse.ArgumentParser('portscanner')

    arg_parser.add_argument('ip_address', type=str,
                            help="ip address of the scanning object")
    arg_parser.add_argument('ports', metavar='ports', type=str, nargs='*',
                            help="ports and scanning methods in the specified"
                                 " format [{tcp|udp}[/[PORT|PORT-PORT],...]]")
    arg_parser.add_argument('--timeout', type=float, metavar='TIME', default=2,
                            required=False,
                            help="response timeout (2 seconds by default)")
    arg_parser.add_argument('-j', '--num-threads', type=int, metavar='NUM',
                            required=False, default=200,
                            help="number of threads (from 1 to 200")
    arg_parser.add_argument('-v', '--verbose', action='store_true',
                            help="enable verbose mode")
    arg_parser.add_argument('-g', '--guess', action='store_true',
                            help="definition of application layer protocols")
    arg_parser.add_argument('-a', '--all', action='store_true',
                            help="see info about all ports")
    args = arg_parser.parse_args()

    try:
        socket.inet_aton(args.ip_address)
    except socket.error:
        print("Invalid argument: ip_address")
        exit(1)
    if args.timeout < 1:
        print("Invalid argument: timeout. Must be positive (from 1)")
        exit(2)
    if args.num_threads < 1 or args.num_threads > 200:
        print(
            "Invalid argument: num_threads. Must be positive (from 1 to 200)")
        exit(3)

    tcp_ports, udp_ports = parse_tcp_udp_ports(args.ports)

    scanned_ports = udp_scanner.scan(args.ip_address, udp_ports,
                                     timeout=args.timeout,
                                     num_threads=args.num_threads)
    scanned_ports += tcp_scanner.scan(args.ip_address, tcp_ports,
                                      timeout=args.timeout,
                                      num_threads=args.num_threads)

    scanned_ports.sort(key=lambda info: (info.scan_protocol, info.port))
    result = scanned_ports
    if not args.all:
        result = filter(lambda x: x.status == 'open', scanned_ports)
    for port_info in result:
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
                try:
                    left, right = [int(i) for i in port_range.split('-')]
                except ValueError:
                    print(f"Wrong port range. Must be from 0 to 65535")
                    exit(6)
                if left > right:
                    print(f"Wrong port range : '{left}-{right}'")
                    exit(4)
                if right > 65535 or left < 0:
                    print(f"Wrong port range. Must be from 0 to 65535")
                    exit(5)
                ports += range(left, right + 1)
            else:
                port = int(port_range)
                if port > 65535 or port < 0:
                    print(f"Wrong port range. Must be from 0 to 65535")
                    exit(6)
                ports += [int(port_range)]
    if protocol.lower() == "tcp":
        return ports, []
    return [], ports


if __name__ == '__main__':
    main()

# scapy использует select в файле libcap.py в классе _L2libpcapSocket в функции select
