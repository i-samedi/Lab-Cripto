from scapy.all import *
from scapy.layers.inet import IP, ICMP

def enviar_ping(caracter, destino):
    """
    Envía un paquete ICMP con un solo carácter en el campo de datos.
    """
    if destino:
        paquete = IP(dst=destino) / ICMP() / Raw(load=caracter.encode())
        send(paquete, verbose=0)
        print(f'Enviado 1 paquete con datos: {caracter.encode().hex()}')
        return paquete
    else:
        raise ValueError("El destino no puede ser None")

def ping_reales(destino):
    """
    Envía pings normales para capturar los campos reales y mostrar el resumen.
    """
    if destino:
        for _ in range(4):
            paquete = IP(dst=destino) / ICMP()
            respuesta = sr1(paquete, timeout=1, verbose=0)
            if respuesta:
                print(f'Ping real: {respuesta.summary()}')
            else:
                print("Sin respuesta.")
    else:
        raise ValueError("El destino no puede ser None")

def enviar_datos_como_ping(datos, destino):
    """
    Envía cada carácter del texto cifrado como un ping individual.
    """
    paquetes = []
    if destino:
        # Muestra pings reales previos
        print("Ping real previo:")
        ping_reales(destino)

        # Envía los datos como pings
        print("\nEnviando datos como pings:")
        for caracter in datos:
            paquete = enviar_ping(caracter, destino)
            paquetes.append(paquete)

        # Muestra pings reales posteriores
        print("\nPing real posterior:")
        ping_reales(destino)
    else:
        raise ValueError("El destino no puede ser None")
    return paquetes

def cesar(texto, desplazamiento):
    """
    Aplica el cifrado César al texto con el desplazamiento dado.
    """
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            ascii_inicial = ord('A') if caracter.isupper() else ord('a')
            nuevo_ascii = (ord(caracter) - ascii_inicial + desplazamiento) % 26 + ascii_inicial
            resultado += chr(nuevo_ascii)
        else:
            resultado += caracter
    return resultado

if __name__ == "__main__":
    # Ingreso de datos para realizar el cifrado César
    print("------------------------------------------------------------------------------")
    texto = input("Ingrese el texto a cifrar: ")
    desplazamiento = int(input("Ingrese el desplazamiento (del 1 al 25): "))
    print("------------------------------------------------------------------------------")

    texto_cifrado = cesar(texto, desplazamiento)
    print(f"Texto cifrado: {texto_cifrado}")
    print("------------------------------------------------------------------------------")
    destino = input("Ingrese la dirección IP de destino (Ejemplo 8.8.8.8): ")
    print("------------------------------------------------------------------------------")
    # Enviar los datos y capturar los paquetes
    paquetes = enviar_datos_como_ping(texto_cifrado, destino)

    # Guardar los paquetes capturados
    name = input("Ingrese el nombre del archivo de captura (agrega el '.pcap'): ")
    while not name.endswith('.pcap'):
        name = input("Ingrese el nombre del archivo de captura (agrega el '.pcap'): ")
    # Necesito que se guarde en la carpeta capturas
    wrpcap(f'./capturas/{name}', paquetes)
    print("------------------------------------------------------------------------------")
    print(f"Captura guardada nombreda {name} contiene: {len(paquetes)} paquetes.")
    print("------------------------------------------------------------------------------")
