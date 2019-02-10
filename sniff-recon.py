#!/usr/bin/python2
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
	print("""usage: python """ + sys.argv[0] + """ <iface> <option>

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

		if sys.argv[2] == "simple":
			sniff(iface=iface,filter="not host "+myip+" and not host 255.255.255.255",prn=ip_port_viewer)

		elif sys.argv[2] == "onlydns":
			sniff(iface=iface,filter="udp port 53 and not host "+myip,prn=dns_sniff)
		
		elif sys.argv[2] == "dnsdump":
			sniff(iface=iface,filter="udp port 53 and not host "+myip,prn=dns_dump)
		
		elif sys.argv[2] == "recon":
			sniff(iface=iface,filter="not host "+myip,prn=ip_dump_priv)
		
		elif sys.argv[2] == "arpdisplay":
			sniff(iface=iface,filter="arp and not host "+myip,prn=arp_display)
		
		elif sys.argv[2] == "macrecon":
			sniff(iface=iface,prn=mac_recon)
		
		elif sys.argv[2] == "poisondetect":
			request_threshold = 10
			requests = []
			replies_count = {}
			notification_issued = []
			print(datenow()+"ARP Spoofing Detection Started on "+myip+"/"+str(bitNetmask(iface,netmask)))
			sniff(iface=iface,filter="arp", prn=poison_detect, store=0)

		else:
			help()
except IndexError:
	help()

except Exception as e:
	print(e)
