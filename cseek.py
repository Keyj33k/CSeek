#!/usr/bin/env python3

from argparse import ArgumentParser, SUPPRESS, HelpFormatter
from socket import socket, AF_INET, SOCK_STREAM, getservbyport, gethostbyaddr, herror
from subprocess import check_output, CalledProcessError
from time import strftime
from os import mkdir
from sys import exit
from datetime import datetime

"""
cseek - Client Identifier

Ping ranges of ipv4 addresses to get the status and if enabled scans for open ports
from the current address.

Author: Keyjeek
Date: 18.09.22
Version: 0.0.5
"""

color = {
    "R": "\033[0;31m",
    "Y": "\033[0;93m",
    "G": "\033[0;92m",
    "D": "\033[0m"
}

def host_conf_check(b_host: int, l_host: int):
    if int(b_host) <= 0 or int(b_host) >= 255 or int(l_host) <= 0 or int(l_host) >= 255:
        exit(f"cseek: invalid config, please check your host configs")

def write_outp_p(port: int, service: str):
    print(f" |\t+ proto=TCP, port={port}, status=open, service={service}")
    with open("output/cseek_output.txt", 'a') as write_output:
        write_output.write(f" |\tproto=TCP, port={port}, status=open, service={service}\n")

def write_outp_i(cur_addr: str, status: str, count: int):
    with open("output/cseek_output.txt", 'a') as write_output:
        write_output.write((f"\n[+] {cur_addr} ( {status} ): connected successfully, "
                            f"count={count}, time={strftime('%H:%M:%S')}\n"))

class CSeek:
    def __init__(
            self, target_address: str, begin_host: str, final_host: str,
            begin_port: int, final_port: int, activate_port_scan: bool, ping_count: int
    ):
        self.ping_count = ping_count
        self.activate_port_scan = activate_port_scan
        self.final_port = final_port
        self.begin_port = begin_port
        self.final_host = final_host
        self.begin_host = begin_host
        self.target_address = target_address

    @staticmethod
    def create_output_file():
        try:
            mkdir("output")
            with open("output/cseek_output.txt", 'w') as output_file:
                output_file.write("cseek - output file\n")
        except (FileExistsError, OSError):
            pass

    def port_check(self):
        ports = [self.begin_port, self.final_port]

        if self.begin_port > self.final_port:
            exit(f"cseek: {color['R']}invalid config{color['D']}, start host cannot be bigger then the last host")

        for port in ports:
            if port >= 65534 or port <= 0: exit(f"cseek: {color['R']}invalid config{color['D']}, "
                                                f"port {port} is invalid")

    def octet_check(self):
        split_address = self.target_address.split(".")
        for octet in range(3):
            if int(split_address[octet]) <= 0 or int(split_address[octet]) >= 253:
                exit(f"cseek: {color['R']}invalid config{color['D']}, octet {octet + 1} "
                     f"( {split_address[octet]} ) is incorrect")

    def scan_port_range(self, target_address):
        open_ports = 0
        for port in range(self.begin_port, self.final_port):
            with socket(AF_INET, SOCK_STREAM) as port_scan:
                port_scan.settimeout(2)
                if port_scan.connect_ex((target_address, port)) == 0:
                    open_ports += 1
                    try:
                        write_outp_p(port, getservbyport(port))
                    except OSError:
                        write_outp_p(port, "unknown")

        port_range = self.final_port - self.begin_port
        closed_ports = port_range - open_ports
        print(f" |  port scan done: total={port_range} open={open_ports} closed={closed_ports}")

    def ping_target(self):
        if self.ping_count is None: self.ping_count = 2
        scan_start = datetime.now()
        scan_count = int(self.final_host) - int(self.begin_host) + 1
        host_count, active_host_count = 0, 0
        for octet in range(int(self.begin_host), int(self.final_host) + 1):
            final_address = f"{self.target_address}.{octet}"
            scan_count -= 1
            host_count += 1

            try:
                check_output(["ping", "-c", str(self.ping_count), final_address])
                print(f"[{color['G']}+{color['D']}] {final_address} ( hostname: {gethostbyaddr(final_address)[0]} ): "
                      f"{color['G']}connected successfully{color['D']}, count={scan_count}, "
                      f"time={strftime('%H:%M:%S')}")
                write_outp_i(final_address, gethostbyaddr(final_address)[0], scan_count)
                active_host_count += 1
                if self.activate_port_scan is not False: cseek.scan_port_range(final_address)
            except CalledProcessError:
                print(f"{final_address}: {color['R']}connection failed{color['D']}, "
                      f"count={scan_count}, time={strftime('%H:%M:%S')}")
            except herror:
                print(f"[{color['G']}+{color['D']}] {final_address} ( {color['R']}unknown{color['D']} ): "
                      f"{color['G']}connected successfully{color['D']}, count={scan_count}, "
                      f"time={strftime('%H:%M:%S')}")
                write_outp_i(final_address, "unknown", scan_count)

        inactive_hosts = host_count - active_host_count
        active_hosts = host_count - inactive_hosts
        min_address = f"{self.target_address}.{self.begin_host}"
        max_address = f"{self.target_address}.{self.final_host}"

        print(f"\n{'*' * 15} statistics {'*' * 17}\n"
               f"total={host_count} active={active_hosts} "
               f"inactive={inactive_hosts} min={min_address}\n"
               f"max={max_address} runtime={datetime.now() - scan_start}")


if __name__ == "__main__":
    def headline(mode: str):
        print(f"cseek - v0.0.5 ( https://github.com/Keyj33k/CSeek )\n\nstart {mode} scan at {datetime.now()} ...\n")

    parser = ArgumentParser(description="cseek - Network Client Identifier",
                            formatter_class=lambda prog: HelpFormatter(prog, max_help_position=37))
    parser.add_argument("-v", "--version", action="version",
                        version="cseek - Client Identifier, Version 0.0.3", help=SUPPRESS)
    parser.add_argument("-u", "--unlock", help="unlock port scanning", action="store_true")
    parser.add_argument("-a", "--addr", type=str, metavar="address",
                        help="address to ping (first three octets only)", required=True)
    parser.add_argument("-b", "--begin", type=str, metavar="begin_host",
                        help="host where the scan should start", required=True)
    parser.add_argument("-f", "--final", type=str, metavar="final_host",
                        help="host where the scan should end", required=True)
    parser.add_argument("-s", "--start", type=int, metavar="start_port", help="port where the scan should start")
    parser.add_argument("-l", "--last", type=int, metavar="last_port", help="port where the scan should end")
    parser.add_argument("-c", "--count", type=int, metavar="ping_count", help="determine ping count")
    args = parser.parse_args()
    unlock_flag = vars(args)["unlock"]

    if (unlock_flag is False and vars(args)["start"] is not None
        or unlock_flag is False and vars(args)["last"] is not None):
        exit(f"cseek: {color['R']}invalid config{color['D']}, perhaps you forgot the unlock flag?")
    elif (unlock_flag is True and vars(args)["start"] is None
          or unlock_flag is True and vars(args)["last"] is None):
        exit(f"cseek: {color['R']}invalid config{color['D']}, you cannot activate "
             "the port scan without the scan configs")

    try:
        cseek = CSeek(args.addr, args.begin, args.final, args.start, args.last, args.unlock, args.count)
        cseek.create_output_file()
        host_conf_check(args.begin, args.final)
        if unlock_flag is True: cseek.port_check()
        cseek.octet_check()
        headline("extended") if args.unlock is not False else headline("basic")
        cseek.ping_target()
    except (IndexError, AttributeError, ValueError):
        parser.print_help()
        print(("\nexamples:\n"
               "  cseek.py -a 192.168.2 -b 1 -f 100 --unlock -s 10 -l 90\n"
               "  cseek.py -a 192.168.2 -b 1 -f 100 -c 1 "))
        exit(1)
    except TypeError:
        print(f'{color["R"]}interrupted{color["D"]}: cannot process because of invalid configurations\n'
              'type "python3 cseek.py -h" to get more informations')
    except KeyboardInterrupt:
        print(f"\n{color['Y']}cseek exits due interruption")
