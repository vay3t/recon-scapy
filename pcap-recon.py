#!/usr/bin/python2
# Coded by vay3t!

from core import *
from scapy.all import *

import sys

def help():
	print """usage: python2 """ + sys.argv[0] + """ <option> <pcap file>

 	help - Show help
 	simple - Show ip with port connections
	arpdisplay - View ARP requests and responses
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing
	macrecon - Recon hosts with MACs
	poisondetect - Detect ARP Poison
"""

try:
	if len(sys.argv) != 3:
		help()

	elif sys.argv[1] == "help":
		help()

	elif sys.argv[1] == "onlydns":
		if sys.argv[2]:
			try:
				packets = rdpcap(sys.argv[2])
				for packet in packets:
					dns_sniff(packet)
			except Scapy_Exception as e:
				print "[-] Error:",e

	elif sys.argv[1] == "dnsdump":
		if sys.argv[2]:
			try:
				packets = rdpcap(sys.argv[2])
				for packet in packets:
					dns_dump(packet)
			except Scapy_Exception as e:
				print "[-] Error:",e

	elif sys.argv[1] == "simple":
		if sys.argv[2]:
			try:
				packets = rdpcap(sys.argv[2])
				for packet in packets:
					ip_port_viewer(packet)
			except Scapy_Exception as e:
				print "[-] Error:",e

	elif sys.argv[1] == "recon":
		if sys.argv[2]:
			try:
				packets = rdpcap(sys.argv[2])
				for packet in packets:
					ip_dump_priv(packet)
			except Scapy_Exception as e:
				print "[-] Error:",e

	elif sys.argv[1] == "arpdisplay":
		if sys.argv[2]:
			try:
				packets = rdpcap(sys.argv[2])
				for packet in packets:
					arp_display(packet)
			except Scapy_Exception as e:
				print "[-] Error:",e

	elif sys.argv[1] == "macrecon":
		macGateway = getmacbyip(gateway)
		hosts.add(macGateway+" - "+gateway)
		if sys.argv[2]:
			try:
				packets = rdpcap(sys.argv[2])
				for packet in packets:
					macrecon(packet)
			except Scapy_Exception as e:
				print "[-] Error:",e

	elif sys.argv[1] == "poisondetect":
		request_threshold = 10
		requests = []
		replies_count = {}
		notification_issued = []
		print datenow()+"ARP Spoofing Detection..."
		if sys.argv[2]:
			try:
				packets = rdpcap(sys.argv[2])
				for packet in packets:
					poisondetect(packet)
			except Scapy_Exception as e:
				print "[-] Error:",e

	else:
		help()
except IndexError:
	help()