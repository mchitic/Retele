import sys


try:
        ips = raw_input("[*] Enter Range of IPs to Scan for: ")
 
except KeyboardInterrupt:
        print "\n[*] User Requested Shutdown"
		print "[*] Quitting..."
		sys.exit(1)
	
print "\n[*] Scanning..."

from scapy.all import srp,Ether,ARP,conf

conf.verb = 0
ans, unans =srp(Ether[dst="ff:ff:ff:ff:ff:ff"]/ARP(pdst=ips), timeout=2, inter=0.1)

print "MAC - IP\n"
for snd,rcv in ans:
        print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")
		
print "\n[*] Scan complete!"