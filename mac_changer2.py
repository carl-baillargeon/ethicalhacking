#!/usr/bin/env python

import subprocess
import argparse

parser = argparse.ArgumentParser(description="Change the MAC address of an interface.")

parser.add_argument("-i", "--interface", metavar="", required=True, help="Interface to change its MAC address")
parser.add_argument("-m", "--mac", metavar="", required=True, help="New MAC address")

args = parser.parse_args()

interface = args.interface
new_mac = args.mac

print("[+] Changing MAC address for " + interface + " to " + new_mac)

subprocess.call(["ifconfig", interface, "down"])
subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
subprocess.call(["ifconfig", interface, "up"])

