from scapy.all import sniff,Raw
from scapy.layers import http

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):#obtenemos solo los paquetes que se envien por http	
		url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		print(url)
	
		if packet.haslayer(Raw):
			print(packet[Raw].load)
	

def packet_sniff(interface):
	#sniff, vamos a capturar los paquetes que pasan. store no los guardamos, prn es un callback
	sniff(iface = interface, store = False, prn = process_sniffed_packet, filter = "tcp port 80")
	
print("empieza")
packet_sniff("eth0")
