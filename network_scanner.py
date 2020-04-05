#!/usr/bin/env python

import scapy.all as scapy
import argparse

def arguments():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-a", "--address", metavar="", required=True, help="IP Address or Network")
    args = parser.parse_args()
    return args

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n----------------------------------------")
    for client in results_list:
        print(client["IP"] + "\t\t" + client["MAC"])

args = arguments()
scan_result = scan(args.address)
print_result(scan_result)