from arp_spoofer import ARPspoofer

print('''
Esta herramienta ha sido desarrollada exclusivamente con fines **educativos y de investigación en ciberseguridad**. 
Su propósito es facilitar la comprensión de conceptos técnicos como el ARP spoofing, el análisis de tráfico en redes 
locales y la detección de vulnerabilidades en entornos controlados.

El autor **no se hace responsable** del uso indebido de este software. Cualquier acción realizada con esta herramienta 
**es responsabilidad única del usuario**.

Queda **terminantemente prohibido** utilizar este software en redes que no sean de su propiedad, sin autorización 
explícita de los administradores o propietarios del entorno. El uso no autorizado puede constituir un delito, conforme a las leyes vigentes en su país o región.

Al ejecutar este software, usted acepta que:
- Comprende los riesgos asociados al ARP spoofing y otras técnicas similares.
- Se compromete a utilizar esta herramienta únicamente en **laboratorios, entornos de práctica o con fines éticos**.
- Libera al autor de cualquier responsabilidad legal, civil o penal derivada del uso de esta herramienta.

**Si no está de acuerdo con estos términos, no use esta herramienta.**
      
      Hecho por V0lg-s
''')

target_IP = str(input("\n\n[+] Ingrese la IP del objetivo:\n"))
spoofed_IP= str(input("\n\n[+] Ingrese la IP a falsificar:\n"))

spoofer = ARPspoofer(spoofed_IP,target_IP)

print('''\n\n
      
      ******************************************************
                Confirmar Detalles
        [*] Ataque dirigido a: {}
        [*] Falsificar las respuestas ARP de: {}
      ******************************************************
      '''.format(target_IP,spoofed_IP))
attack = int(input("\n\n[+] Presione 1 para confirmar e iniciar el ataque\n[+] Presione 2 para cancelar\n"))

if attack == 1:
    
    spoofer.start_attack(5,1)
    attack= int(input("Ataque iniciado, presione 0 en cualquier momento para cancelar."))
    if(attack == 0):
        print("\n[!] Ataque detenido por el usuario")
        spoofer.stop_attack()
        
elif attack == 2:
    exit()




