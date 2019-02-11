#!/usr/bin/python3
# Coded by vay3t!

from core import *
from scapy.all import *

import sys

def help():
	print("""usage: python3 """ + sys.argv[0] + """ <pcap file> <option> 

 	help - Show help
 	simple - Show ip with port connections
	arpdisplay - View ARP requests and responses
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing
	macrecon - Recon hosts with MACs
""")

try:
	if len(sys.argv) != 3:
		help()

	elif sys.argv[1] == "help":
		help()

	else:
		packets = rdpcap(sys.argv[1])

		if sys.argv[2] == "onlydns":
			print("[+] Starting module 'onlydns'")
			for packet in packets:
				onlydns_sniff(packet)

		elif sys.argv[2] == "dnsdump":
			print("[+] Starting module 'dnsdump'")
			for packet in packets:
				dns_sniff(packet)

		elif sys.argv[2] == "simple":
			print("[+] Starting module 'simple'")
			for packet in packets:
				ip_port_viewer(packet)

		elif sys.argv[2] == "recon":
			print("[+] Starting module 'recon'")
			for packet in packets:
				ip_dump_priv(packet)

		elif sys.argv[2] == "arpdisplay":
			print("[+] Starting module 'arpdisplay'")
			for packet in packets:
				arp_display(packet)

		elif sys.argv[2] == "macrecon":
			print("[+] Starting module 'macrecon'")
			for packet in packets:
				mac_recon(packet)
		else:
			help()
except IndexError:
	help()
except Scapy_Exception as e:
	print(e)
except Exception as e:
	print(e)