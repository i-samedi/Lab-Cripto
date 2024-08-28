from scapy.all import *

def enviar_ping(datos, destino):
    if isinstance(datos, str):
        datos = datos.encode()  # Convierte la cadena de texto a bytes si es necesario
    
    # Construye un paquete ICMP con los datos especificados
    paquete = IP(dst=destino)/ICMP()/Raw(load=datos)
    
    # Envía el paquete
    send(paquete, verbose=0)
    print(f'Sent 1 packet with data: {datos.hex()}')


def ping_reales(destino):
    # Envía pings normales para capturar los campos reales
    for _ in range(4):
        paquete = IP(dst=destino)/ICMP()
        respuesta = sr1(paquete, timeout=1, verbose=0)
        if respuesta:
            print(f'Real ping: {respuesta.summary()}')
        else:
            print("No response.")

def enviar_datos_como_ping(datos, destino):
    # Muestra pings reales
    print("Ping real previo:")
    ping_reales(destino)
    
    print("\nEnviando datos como ping:")
    enviar_ping(datos, destino)
    
    # Muestra pings reales posteriores
    print("\nPing real posterior:")
    ping_reales(destino)

def desplazar_string(texto, desplazamiento):
    resultado = ""

    for caracter in texto:
        valor_ascii = ord(caracter)
        
        nuevo_valor_ascii = valor_ascii + desplazamiento
        
        if nuevo_valor_ascii > 126: 
            nuevo_valor_ascii = (nuevo_valor_ascii - 32) % 95 + 32 
        elif nuevo_valor_ascii < 32:
            nuevo_valor_ascii = 126 - (31 - nuevo_valor_ascii)
        
        nuevo_caracter = chr(nuevo_valor_ascii)
        
        resultado += nuevo_caracter
    return resultado

if __name__ == "__main__":
    texto = input("Ingresa el texto: ")
    desplazamiento = int(input("Ingresa el texto: "))

    datos = desplazar_string(texto, desplazamiento)

    print("Texto original: ", texto)
    print("Texto desplazado: ", datos)

    destino = "172.20.85.13"
    enviar_datos_como_ping(datos, destino)