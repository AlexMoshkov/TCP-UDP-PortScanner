import argparse
import udp_scanner


def main():
    arg_parser = argparse.ArgumentParser('PortScanner')

    arg_parser.add_argument('ip_address', type=str,
                            help="ip address of the scanning object")
    arg_parser.add_argument('ports', metavar='ports', type=str, nargs='+',
                            help="ports and scanning methods in the specified format "
                                 "[{tcp|udp}[/[PORT|PORT-PORT],...]]")
    arg_parser.add_argument('--timeout', type=float, metavar='TIME', default=2, required=False,
                            help="response timeout (2 seconds by default)")
    arg_parser.add_argument('-j', '--num-threads', type=int, metavar='NUM', required=False,
                            help="number of threads")
    arg_parser.add_argument('-v', '--verbose', action='store_true',
                            help="enable verbose mode")
    arg_parser.add_argument('-g', '--guess', action='store_true',
                            help="definition of application layer protocols")

    args = arg_parser.parse_args()
    print(args)


def parse_tcp_udp_ports(all_ports):
    pass

def parse_group_ports(group):
    pass

if __name__ == '__main__':
    main()
