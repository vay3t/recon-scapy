#!/usr/bin/python2
# Coded by vay3t!

import commands
import os
import sys

from scapy.all import *
import IPy

# rdpcap comes from scapy and loads in our pcap file
#packets = rdpcap(sys.argv[1])

def detect_iface():
	iface = commands.getoutput("route -n | grep UG | awk '{print $8}'")
	return iface

def detect_gateway():
	gateway = commands.getoutput("route -n | grep UG | awk '{print $2}'")
	return gateway

def detect_ip(iface):
	myip = commands.getoutput('ifconfig '+iface+' | grep "inet "').split()[1]
	return myip

def detect_netmask(iface):
	netmask = commands.getoutput('ifconfig '+iface+' | grep "inet "').split()[3]
	return netmask

def detect_network(iface):
	from netaddr import IPAddress
	bitNetmask = IPAddress(netmask).netmask_bits()
	network = commands.getoutput("route -n | grep "+iface+" | grep '"+netmask+"' | awk '{print $1}'")
	return network+"/"+str(bitNetmask)

iface = detect_iface()
myip = detect_ip(iface)
gateway = detect_gateway()
netmask = detect_netmask(iface)
network = detect_network(iface)


def dns_dump(packet):
    # We're only interested packets with a DNS Round Robin layer
    if packet.haslayer(DNSRR):
        # If the an(swer) is a DNSRR, print the name it replied with.
        if isinstance(packet.an, DNSRR):
            print(packet.an.rrname[:-1])


def dns_sniff(packet):
	if IP in packet:
		ip_src = packet[IP].src
		ip_dst = packet[IP].dst   
		if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
			print str(ip_src) + " -> " + str(ip_dst) + " : " + packet.getlayer(DNS).qd.qname[:-1]


hosts = set()
def ip_dump_priv(packet):
	if packet.haslayer(IP):
		ipSrc = packet['IP'].src
		type_ipSrc = IPy.IP(ipSrc)

		ipDst = packet['IP'].dst
		type_ipDst = IPy.IP(ipDst)

		if type_ipSrc.iptype() == 'PRIVATE':
			if ipSrc not in hosts:
				hosts.add(ipSrc)
				print(ipSrc)
		if type_ipDst.iptype() == 'PRIVATE':
			if ipDst not in hosts:
				hosts.add(ipDst)
				print(ipDst)

def arping_scan(network):
	conf.verb=0
	ans,uans = arping(network)
	for snd,rcv in ans:
		print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")

def arp_recon(packet):
	if packet.haslayer(ARP):
		macSrc = packet["ARP"].hwsrc
		ipSrc = packet["ARP"].psrc
		complete_string = macSrc + " - " + ipSrc
		if complete_string not in hosts:
			hosts.add(complete_string)
			print complete_string


def help():
	print """usage: """ + sys.argv[0] + """ <option>

	help - Show help
	arping - Discovery hosts with ARP
	arprecon - Discovery host with passive sniffing ARP
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing
"""

if os.geteuid() != 0:
	print "You need run with root!"
if len(sys.argv) != 2:
	help()
elif sys.argv[1] == "help":
	help()
elif sys.argv[1] == "arping":
	arping_scan(network)
elif sys.argv[1] == "arprecon":
	sniff(iface=iface,prn=arp_recon)
elif sys.argv[1] == "onlydns":
	sniff(iface=iface,prn=dns_sniff)
elif sys.argv[1] == "dnsdump":
	sniff(iface=iface,prn=dns_dump)
elif sys.argv[1] == "recon":
	sniff(iface=iface,prn=ip_dump_priv)
else:
	help()
