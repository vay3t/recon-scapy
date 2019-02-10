# recon-scapy
Simple script for recon network

# Install (for Arch Linux)
```
sudo pacman -S python python-pip git
git clone https://github.com/vay3t/recon-scapy
cd recon-scapy
sudo pip install -r requirements.txt
```

# Help
```
usage: python sniff-recon.py <iface> <option>

	help - Show help
	simple - Show ip with port connections
	arpdisplay - View ARP requests and responses
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing
	macrecon - Recon hosts with MACs
	poisondetect - Detect ARP Poison
```

```
usage: python pcap-recon.py <pcap file> <option>

 	help - Show help
	simple - Show ip with port connections
	arpdisplay - View ARP requests and responses
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing
	macrecon - Recon hosts with MACs
```
