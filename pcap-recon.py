#!/usr/bin/python2
# Coded by vay3t!

from core import *
from scapy.all import *

import sys

def help():
	print("""usage: python """ + sys.argv[0] + """ <pcap file> <option> 

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
			for packet in packets:
				dns_dump(packet)

		elif sys.argv[2] == "dnsdump":
			for packet in packets:
				dns_sniff(packet)

		elif sys.argv[2] == "simple":
			for packet in packets:
				ip_port_viewer(packet)

		elif sys.argv[2] == "recon":
			for packet in packets:
				ip_dump_priv(packet)

		elif sys.argv[2] == "arpdisplay":
			for packet in packets:
				arp_display(packet)

		elif sys.argv[2] == "macrecon":
			for packet in packets:
				macrecon(packet)
		else:
			help()
except IndexError:
	help()
except Scapy_Exception as e:
	print(e)
except Exception as e:
	print(e)