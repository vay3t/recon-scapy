#!/usr/bin/python3
# Coded by vay3t!

from core import *
from scapy.all import *

import sys

#lul
def poison_detect(packet):
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == myip:
        requests.append(dest)
    if operation == 'is-at':
        return check_spoof(source, source_mac, dest)

def help():
	print("""usage: python3 """ + sys.argv[0] + """ <iface> <option>

	help - Show help
	simple - Show ip with port connections
	arpdisplay - View ARP requests and responses
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing
	macrecon - Recon hosts with MACs
	poisondetect - Detect ARP Poison
""")

try:
	if len(sys.argv) != 3:
		help()

	elif sys.argv[1] == "help":
		help()

	else:
		iface = sys.argv[1]

		myip = netifaces.ifaddresses(iface)[2][0]["addr"].encode("utf-8").decode("utf-8")
		netmask = netifaces.ifaddresses(iface)[2][0]["netmask"].encode("utf-8").decode("utf-8")
		mymac = netifaces.ifaddresses(iface)[17][0]["addr"].encode("utf-8").decode("utf-8")
		print("[*] addr: "+myip+"/"+str(bitNetmask(iface,netmask))+" --- "+mymac)
		if sys.argv[2] == "simple":
			filtro = "not host "+myip+" and not host 255.255.255.255"
			print("[+] Starting module 'simple' with filter: '"+filtro+"'")
			sniff(iface=iface,filter=filtro,prn=ip_port_viewer)

		elif sys.argv[2] == "onlydns":
			filtro = "udp port 53 and not host "+myip
			print("[+] Starting module 'onlydns' with filter: '"+filtro+"'")
			sniff(iface=iface,filter=filtro,prn=onlydns_sniff)
		
		elif sys.argv[2] == "dnsdump":
			filtro = "udp port 53 and not host "+myip
			print("[+] Starting module 'dnsdump' with filter: '"+filtro+"'")
			sniff(iface=iface,filter=filtro,prn=dns_sniff)
		
		elif sys.argv[2] == "recon":
			filtro = "not host "+myip
			print("[+] Starting module 'recon' with filter: '"+filtro+"'")
			sniff(iface=iface,filter=filtro,prn=ip_dump_priv)
		
		elif sys.argv[2] == "arpdisplay":
			filtro = "arp and not host "+myip
			print("[+] Starting module 'arpdisplay' with filter: '"+filtro+"'")
			sniff(iface=iface,filter=filtro,prn=arp_display)
		
		elif sys.argv[2] == "macrecon":
			print("[+] Starting 'macrecon'")
			sniff(iface=iface,prn=mac_recon)
		
		elif sys.argv[2] == "poisondetect":
			request_threshold = 10
			requests = []
			replies_count = {}
			notification_issued = []
			print(datenow()+"[+] Starting module 'poisondetect' on "+myip+"/"+str(bitNetmask(iface,netmask)))
			sniff(iface=iface,filter="arp", prn=poison_detect, store=0)

		else:
			help()
except IndexError:
	help()
except Exception as e:
	print(e)
