from scapy.all import IP, ICMP, Raw, send
import time

def enviar_mensaje_oculto(mensaje, destino):
    for caracter in mensaje:
        paquete = IP(dst=destino)/ICMP()/Raw(load=caracter)
        send(paquete, verbose=False)
        time.sleep(0.1)  # Pequeña pausa para no saturar la red
    
    # Enviar 'b' como último carácter
    paquete_final = IP(dst=destino)/ICMP()/Raw(load='b')
    send(paquete_final, verbose=False)
    print(f"Mensaje enviado a {destino}")

if __name__ == "__main__":
    mensaje_cifrado = input("Ingrese el mensaje cifrado a enviar: ")
    ip_destino = input("Ingrese la dirección IP de destino: ")
    
    enviar_mensaje_oculto(mensaje_cifrado, ip_destino)