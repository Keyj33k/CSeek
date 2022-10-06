#!/usr/bin/env python3

from argparse import ArgumentParser, SUPPRESS 
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
Version: 0.0.4
"""

RED = "\033[0;31m"
GREEN = "\033[0;32m"
RESET = "\033[0m"

def host_conf_check(b_host: int, l_host: int):
    if int(b_host) <= 0 or int(l_host) <= 0:
        print(f"host check: {RED}FALSE{RESET}")
        return False
    else:
        print(f"host check: {GREEN}OK{RESET}")
        return True

def port_check_outp(port: int):
    exit(f"cseek: port check: port {port} {RED}FALSE{RESET}")

def write_outp_p(port: int, service: str):
    print(f" |\tproto=TCP, port={port}, status=open, service={service}")
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
            print(f"output file check: {GREEN}OK{RESET}")
        except (FileExistsError, OSError):
            print(f"output file check: {GREEN}OK{RESET}")

    def port_check(self):
        if self.begin_port > self.final_port:
            exit(f"cseek: port check: {RED}FALSE{RESET}")
        elif self.begin_port >= 65534 or self.begin_port <= 0:
            port_check_outp(self.begin_port)
        elif self.final_port >= 65535 or self.final_port <= 0:
            port_check_outp(self.final_port)
        else:
            print(f"port check: {GREEN}OK{RESET}")

    def octet_check(self):
        split_address = self.target_address.split(".")
        for octet in range(3): 
            if int(split_address[octet]) <= 0 or int(split_address[octet]) >= 253:
                exit(f"octet check: octet {octet + 1} ( {split_address[octet]} ) {RED}FALSE{RESET}")
            else:
                print(f"octet check: {octet + 1} {GREEN}OK{RESET}")

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
                print((f"[{GREEN}+{RESET}] {final_address} ( {gethostbyaddr(final_address)[0]} ): {GREEN}connected "
                       f"successfully{RESET}, count={scan_count}, time={strftime('%H:%M:%S')}"))
                write_outp_i(final_address, gethostbyaddr(final_address)[0], scan_count)
                active_host_count += 1
                if self.activate_port_scan is not False: cseek.scan_port_range(final_address)
            except CalledProcessError:  
                print(f"{final_address}: {RED}connection failed{RESET}, "
                      f"count={scan_count}, time={strftime('%H:%M:%S')}")
            except herror:  
                print((f"[{GREEN}+{RESET}] {final_address} ( {RED}unknown{RESET} ): {GREEN}connected "
                       f"successfully{RESET}, count={scan_count}, time={strftime('%H:%M:%S')}"))
                write_outp_i(final_address, "unknown", scan_count)

        inactive_hosts = host_count - active_host_count
        active_hosts = host_count - inactive_hosts
        min_address = f"{self.target_address}.{self.begin_host}"
        max_address = f"{self.target_address}.{self.final_host}"

        print("\n***************** statistics *****************")
        print((f"total={host_count} active={active_hosts} "
               f"inactive={inactive_hosts} min={min_address}\n"
               f"max={max_address} runtime={datetime.now() - scan_start}"))


if __name__ == "__main__":
    def headline(mode: str):
        print(f"\ncseek ( 0.0.4 ) start {mode} scan at {datetime.now()}\n")

    parser = ArgumentParser(description="cseek - Network Client Identifier")
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

    if int(args.begin) >= 253 or int(args.final) >= 254:
        exit(f"host config check: {RED}FALSE{RESET}")
    elif int(args.begin) > int(args.final):
        exit(f"host check: {RED}FALSE{RESET}")
    elif (unlock_flag is False and vars(args)["start"] is not None
          or unlock_flag is False and vars(args)["last"] is not None):
        exit(f"port config check: {RED}FALSE{RESET}")
    elif (unlock_flag is True and vars(args)["start"] is None
          or unlock_flag is True and vars(args)["last"] is None):
        exit(f"port config check: {RED}FALSE{RESET}")

    try:
        cseek = CSeek(args.addr, args.begin, args.final, args.start,
                      args.last, args.unlock, args.count)
        cseek.create_output_file()
        if host_conf_check(args.begin, args.final) is not True: exit(1)
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
        print((f'\n{RED}interrupted{RESET}: cannot process because of invalid configurations\n'
               'type "python3 cseek.py -h" to get more informations'))
    except KeyboardInterrupt:
        print("\ncseek exits due interruption")
