#!/usr/bin/python2
# Coded by vay3t!

from core import *
from scapy.all import *

import sys



def help():
	print """usage: sudo python2 """ + sys.argv[0] + """ <option>

	help - Show help
	arping - Discovery hosts with ARP (Active scan)
	arpdisplay - View ARP requests and responses
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing
	macrecon - Recon hosts with MACs
	poisondetect - Detect ARP Poison
"""


if os.geteuid() != 0:
	print "You need run with root!"

try:
	if len(sys.argv) != 2:
		help()

	elif sys.argv[1] == "help":
		help()

	elif sys.argv[1] == "arping":
		arping_scan(network)

	elif sys.argv[1] == "onlydns":
		sniff(iface=iface,filter="udp port 53 and not host "+myip,prn=dns_sniff)
	
	elif sys.argv[1] == "dnsdump":
		sniff(iface=iface,filter="udp port 53 and not host "+myip,prn=dns_dump)
	
	elif sys.argv[1] == "recon":
		sniff(iface=iface,filter="not host "+myip,prn=ip_dump_priv)
	
	elif sys.argv[1] == "arpdisplay":
		sniff(iface=iface,filter="arp and not host "+myip,prn=arp_display)
	
	elif sys.argv[1] == "macrecon":
		macGateway = getmacbyip(gateway)
		hosts.add(macGateway+" - "+gateway)
		sniff(iface=iface,prn=mac_recon)
	
	elif sys.argv[1] == "poisondetect":
		request_threshold = 10
		requests = []
		replies_count = {}
		notification_issued = []
		print datenow()+"ARP Spoofing Detection Started on "+network
		sniff(iface=iface,filter="arp", prn=poison_detect, store=0)

	else:
		help()
except IndexError:
	help()
