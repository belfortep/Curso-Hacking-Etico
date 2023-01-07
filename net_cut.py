import netfilterqueue


def process_packet(packet):
	print(packet)
	packet.accept()#los paquetes van a fluir y la victima tiene internet
	#packet.drop()#me quedo con los paquetes, no tiene internet
	#antes de este ataque hay que hacer un arp spoof


#para establecer tablas ip:
#iptables -I FORWARD -j NFQUEUE --queue-num 0
#el FORWARD es para remoto, osea en otra compu. si es en la misma se usa OUTPUT y despues el mismo comando con INPUT 

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()