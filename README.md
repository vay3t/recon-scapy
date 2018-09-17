# recon-scapy
Simple script for recon netowrk

# Install (for Arch Linux)
```
sudo pacman -S python2-pip git net-tools
git clone https://github.com/vay3t/recon-scapy
cd recon-scapy
sudo pip2 install -r requirements.txt
```

# Help
```
usage: python2 recon-scapy.py <option>

	help - Show help
	arping - Discovery hosts with ARP
	arprecon - Discovery host with passive sniffing ARP
	recon - Discovery hosts with passive sniffing
	onlydns - Collect DNS with passive sniffing
	dnsdump - View DNS requests of hosts with passive sniffing

```
