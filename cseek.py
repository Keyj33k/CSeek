#!/usr/bin/env python3

from argparse import ArgumentParser  # command line arguments
from logging import basicConfig, getLogger, INFO  # runtime logging
from socket import socket, AF_INET, SOCK_STREAM, getservbyport, gethostbyaddr, herror  # port scanning
from subprocess import check_output, CalledProcessError  # process calling (ping)
from time import strftime  # formatted time specification
from os import mkdir  # output file creation
from sys import exit
from datetime import datetime  # current timestamp

"""
cseek - Client Identifier

Ping ranges of ipv4 addresses to get the status and if enabled scans for open ports
from the current address.

Author: Keyjeek
Date: 18.09.22
Version: 0.0.3
"""

def port_check_outp(port: int):
    print(f"port check: port {port} is invalid")
    LOGGER.error(f"port check: port {port} is invalid")
    exit(1)

def write_outp_p(port: int, service: str):
    """
    Function for saving the port scanning output.
    
    :param port: current port to scan
    :param service: service behind current port
    """
    with open("output/cseek_output.txt", 'a') as write_output:
        write_output.write(f" |\tproto=TCP, port={port}, status=open, service={service}\n")

def write_outp_i(cur_addr: str, status: str, count: int):  # save ipsweep output
    """
    Function for saving the ipsweep output.
    
    :param cur_addr: current built address
    :param status: reachability status of the current address
    :param count: scan count
    """
    with open("output/cseek_output.txt", 'a') as write_output:
        write_output.write(
            f"\n[+] {cur_addr} ( {status} ): connected successfully, count={count}, time={strftime('%H:%M:%S')}\n")


basicConfig(filename="logfile.log", format="[%(levelname)s] %(asctime)s\t%(message)s", filemode='w')
LOGGER = getLogger()
LOGGER.setLevel(INFO)


class CSeek:
    def __init__(
            self, target_address: str, begin_host: str, final_host: str,
            begin_port: int, final_port: int, activate_port_scan: bool, ping_count: int
    ):
        """
        :param target_address: the first three octets of the addresses created during processing
        :param activate_port_scan: responsible for port scan activation
        :param ping_count: define number of ping requests
        """
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
                output_file.write("cseek - output file\n")  # creating output file headline
            LOGGER.info("output file check: created successfully")
        except FileExistsError:
            LOGGER.info("output file check: already exists")
        except OSError as os_err:
            LOGGER.error(os_err)

    def port_check(self):
        if self.begin_port > self.final_port:
            print("port check: invalid order")
            LOGGER.error("port check: invalid order")
            exit(1)
        elif self.begin_port >= 65534 or self.begin_port <= 0:
            port_check_outp(self.begin_port)
        elif self.final_port >= 65535 or self.final_port <= 0:
            port_check_outp(self.final_port)
        else:
            LOGGER.info("port check: passed")

    def octet_check(self):
        split_address = self.target_address.split(".")
        for octet in range(3):  # loop through each single octet to compare
            if int(split_address[octet]) <= 0 or int(split_address[octet]) >= 253:
                print(f"octet check: octet {octet + 1} ( {split_address[octet]} ) is invalid")
                LOGGER.error(f"octet check: octet {octet + 1} ( {split_address[octet]} ) is invalid")
                exit(1)
            else:
                LOGGER.info(f"octet check: octet {octet + 1} ( {split_address[octet]} ) passed")

    def scan_port_range(self, target_address):
        """
        Port scanning function (will be enabled if --unlock flag is given).
        
        :param target_address: previously built valid ipv4 address
        """
        cseek.port_check()
        open_ports = 0
        for port in range(self.begin_port, self.final_port):
            # creating a socket connection using IPv4 and TCP configurations
            with socket(AF_INET, SOCK_STREAM) as port_scan:
                port_scan.settimeout(5)
                if port_scan.connect_ex((target_address, port)) == 0:
                    open_ports += 1

                    try:
                        print(f" |\tproto=TCP, port={port}, status=open, service={getservbyport(port)}")
                        write_outp_p(port, getservbyport(port))
                    except OSError:
                        print(f" |\tproto=TCP, port={port}, status=open, service=unknown")
                        write_outp_p(port, "unknown")

        # statistics calculation section for port scanning process
        port_range = self.final_port - self.begin_port
        closed_ports = port_range - open_ports
        print(f" |  port scan done: total={port_range} open={open_ports} closed={closed_ports}")

    def ping_target(self):
        if self.ping_count is None: self.ping_count = 2  # set two as default if ping count isn't configured
        scan_start = datetime.now()
        scan_count = int(self.final_host) - int(self.begin_host) + 1  # start point to count runtime value
        host_count, active_host_count = 0, 0
        # count the scan range
        for octet in range(int(self.begin_host), int(self.final_host) + 1):
            # added to the given 24 bit value an 8 bit value to generate a valid IPv4 address
            final_address = f"{self.target_address}.{octet}"
            scan_count -= 1
            host_count += 1

            try:
                check_output(["ping", "-c", str(self.ping_count), final_address])
                print((f"[+] {final_address} ( {gethostbyaddr(final_address)[0]} ): connected successfully, "
                       f"count={scan_count}, time={strftime('%H:%M:%S')}"))
                write_outp_i(final_address, gethostbyaddr(final_address)[0], scan_count)
                active_host_count += 1
                if self.activate_port_scan is not False: cseek.scan_port_range(final_address)
            except CalledProcessError:  # raises if check_output returns a non-zero exit status
                print(f"{final_address}: connection failed, count={scan_count}, time={strftime('%H:%M:%S')}")
            except herror:  # raises if gethostbyaddr returns an error
                print((f"[+] {final_address} ( unknown ): connected successfully, "
                       f"count={scan_count}, time={strftime('%H:%M:%S')}"))
                write_outp_i(final_address, "unknown", scan_count)

        # statistics calculation section for ipsweep scanning process
        scan_end = datetime.now()
        inactive_hosts = host_count - active_host_count
        active_hosts = host_count - inactive_hosts
        min_address = f"{self.target_address}.{self.begin_host}"
        max_address = f"{self.target_address}.{self.final_host}"
        needed_time = scan_end - scan_start

        print("\n***************** statistics *****************")
        print((f"total={host_count} active={active_hosts} "
               f"inactive={inactive_hosts} min={min_address}\n"
               f"max={max_address} runtime={needed_time}"))


if __name__ == "__main__":
    def headline(mode: str):
        print(f"cseek ( 0.0.3 ) start {mode} scan at {datetime.now()}\n")

    parser = ArgumentParser(description="cseek - Network Client Identifier")

    def display_help():
        parser.print_help()
        print(("\nexamples:\n"
               "  cseek.py -a 192.168.2 -b 1 -f 100 --unlock -s 10 -l 90\n"
               "  cseek.py -a 192.168.2 -b 1 -f 100 -c 1 "))
        exit(1)

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
    address = args.addr

    # config checks
    if int(args.begin) > 252 or int(args.final) > 253 or len(address.split(".")) != 3:
        display_help()
    elif (vars(args)["unlock"] is False and vars(args)["start"] is not None
          or vars(args)["unlock"] is False and vars(args)["last"] is not None):
        display_help()
    elif (vars(args)["unlock"] is True and vars(args)["start"] is None
          or vars(args)["unlock"] is True and vars(args)["last"] is None):
        display_help()

    try:
        cseek = CSeek(args.addr, args.begin, args.final, args.start,
                      args.last, args.unlock, args.count)
        cseek.octet_check()
        cseek.create_output_file()
        headline("extended") if args.unlock is not False else headline("basic")
        cseek.ping_target()  # get targets status (if enabled scan for open ports)
    except (IndexError, AttributeError, ValueError):
        parser.print_help()
    except TypeError:
        print(('\ninterrupted: cannot process because of invalid configurations\n'
               'type "python3 cseek.py -h" to get more informations'))
    except KeyboardInterrupt:
        print("\ncseek exits due interruption")
