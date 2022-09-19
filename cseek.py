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

Author: Keyjeek
Date: 18.09.22
Version: 0.0.2

"""

basicConfig(filename="logfile.log", format="%(asctime)s\t%(message)s", filemode='w')
LOGGER = getLogger()
LOGGER.setLevel(INFO)


class CSeek:
    def __init__(
            self, target_address: str, begin_host: str, final_host: str,
            begin_port: int, final_port: int, activate_port_scan: str
    ):
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
            LOGGER.info("output file check: successful")

    def port_check(self):
        if self.begin_port > self.final_port:
            print("port check: invalid order")
            exit(1)
        elif self.begin_port >= 65534 or self.begin_port <= 0:
            print(f"port check: port {self.begin_port} is invalid")
            exit(1)
        elif self.final_port >= 65535 or self.final_port <= 0:
            print(f"port check: port {self.final_port} is invalid")
            exit(1)
        else:
            LOGGER.info("port check: successful")

    def octet_check(self):
        # compare each given octet individually to avoid misconfigurations
        split_address = self.target_address.split(".")

        for octet in range(3): # loop through each single octet to compare
            if int(split_address[octet]) <= 0 or int(split_address[octet]) >= 253:
                print(f"octet check: octet {octet + 1} ( {split_address[octet]} ) is invalid")
                exit(1)
            else:
                LOGGER.info(f"octet check: octet {octet + 1} ( {split_address[octet]} ) passed")

    def scan_port_range(self, target_address):
        cseek.port_check()
        open_ports = 0

        for port in range(self.begin_port, self.final_port):
            # creating a socket connection using IPv4 and TCP configurations
            with socket(AF_INET, SOCK_STREAM) as port_scan:
                port_scan.settimeout(5)
                # returns an error indicator instead of raising an exception
                result = port_scan.connect_ex((target_address, port))

                if result == 0:
                    open_ports += 1
                    try:
                        print(f" |\tproto=TCP, port={port}, status=open, service={getservbyport(port)}")
                        
                        with open("output/cseek_output.txt", 'a') as write_output:
                            write_output.write(
                                f" |\tproto=TCP, port={port}, status=open, service={getservbyport(port)}\n"
                            )
                    except OSError:
                        print(f" |\tproto=TCP, port={port}, status=open, service=unknown")

        # statistics calculation section for port scanning process
        port_range = self.final_port - self.begin_port
        closed_ports = port_range - open_ports
        print(f" |  port scan done: total={port_range} open={open_ports} closed={closed_ports}")

    def ping_target(self):
        scan_count = int(self.final_host) - int(self.begin_host) + 1  # start point to count runtime value
        host_count, active_host_count = 0, 0
        scan_start = datetime.now()

        # count the scan range
        for octet in range(int(self.begin_host), int(self.final_host) + 1):
            # added to the given 24 bit value an 8 bit value to generate a valid IPv4 address
            final_address = f"{self.target_address}.{octet}"
            scan_count -= 1
            host_count += 1

            try:
                # call a ping process to identify the target host status
                check_output(["ping", "-c", "2", final_address])
                active_host_count += 1
                # extract result from output list
                print(
                    f"[+] {final_address} ( {gethostbyaddr(final_address)[0]} ): connected successfully, " + \
                    f"count={scan_count}, time={strftime('%H:%M:%S')}"
                )
                
                with open("output/cseek_output.txt", 'a') as write_output:
                    write_output.write(
                        f"\n[+] {final_address} ( {gethostbyaddr(final_address)[0]} ): connected successfully, " + \
                        f"count={scan_count}, time={strftime('%H:%M:%S')}\n"
                    )

                if self.activate_port_scan != "off":
                    cseek.scan_port_range(final_address) # activate port scan
            except CalledProcessError:
                print(f"{final_address}: connection failed, count={scan_count}, time={strftime('%H:%M:%S')}")
            except herror:
                print(f"{final_address}: connection failed, count={scan_count}, time={strftime('%H:%M:%S')}")

        # statistics calculation section for ipsweep scanning process
        scan_end = datetime.now()
        inactive_hosts = host_count - active_host_count
        active_hosts = host_count - inactive_hosts
        min_address = f"{self.target_address}.{self.begin_host}"
        max_address = f"{self.target_address}.{self.final_host}"
        needed_time = scan_end - scan_start
        print("\n***************** statistics *****************")
        print(
            f"total={host_count} active={active_hosts} inactive={inactive_hosts} " + \
            f"min={min_address}\nmax={max_address} runtime={needed_time}"
        )


if __name__ == '__main__':
    parser = ArgumentParser(description="cseek - Network Client Identifier")

    def display_help():
        parser.print_help()
        exit(1)

    parser.add_argument(
        "-a", "--addr", type=str, metavar="address",
        help="address to ping - first three octets only", required=True
    )
    parser.add_argument(
        "-b", "--begin", type=str, metavar="begin_host",
        help="host where the scan should start", required=True
    )
    parser.add_argument(
        "-f", "--final", type=str, metavar="final_host",
        help="host where the scan should end", required=True
    )
    parser.add_argument(
        "-u", "--unlock", type=str, metavar="on/off",
        help="activate or deactivate portscan (on/off)", required=True
    )
    parser.add_argument("-s", "--start", type=int, metavar="start_port", help="port where the scan should start")
    parser.add_argument("-l", "--last", type=int, metavar="last_port", help="port where the scan should end")
    args = parser.parse_args()
    address = args.addr

    # config checks
    if args.unlock != "off" and args.unlock != "on":
        display_help()
    elif int(args.begin) > 252 or int(args.final) > 253:
        display_help()
    elif len(address.split(".")) != 3:
        display_help()

    print("cseek - version 0.0.2\n")

    try:
        cseek = CSeek(args.addr, args.begin, args.final, args.start, args.last, args.unlock)
        cseek.octet_check()
        cseek.create_output_file()

        if args.unlock != "off":
            print(f"extended scan begins at {datetime.now()}\n")
        else:
            print(f"basic scan begins at {datetime.now()}\n")

        cseek.ping_target()  # get targets status (if enabled scan for open ports)
    except IndexError:
        parser.print_help()
    except AttributeError:
        parser.print_help()
    except TypeError:
        print(
            '\ninterrupted: cannot process because of invalid configurations\n' + \
            'type "python3 cseek.py -h" to get more informations'
        )
    except ValueError:
        parser.print_help()
    except KeyboardInterrupt:
        print("\ncseek exits due interruption")
