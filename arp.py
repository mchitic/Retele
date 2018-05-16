import sys
from scapy.all import *


try:
        ips = raw_input("Enter Range of IPs to Scan for: ")
 
except KeyboardInterrupt:
        print "\nUser Requested Shutdown"
	print "Quitting..."
	sys.exit(1)
	
print "\nScanning..."

eth = Ether(dst = "ff:ff:ff:ff:ff:ff")
arp = ARP(pdst = ips)

answered, unanswered = srp(eth/arp)

print "MAC -- IP\n"
for snd,rcv in answered:
        print rcv[ARP].psrc
	print rcv[Ether].hwsrc
		
print "\nScan complete!"
