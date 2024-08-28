from scapy.all import rdpcap, ICMP, IP, Raw
from colorama import Fore, Style
import string

def leer_pcap(archivo):
    """
    Lee el archivo .pcap o .pcapng y extrae los mensajes ICMP.
    """
    paquetes = rdpcap(archivo)
    mensaje_cifrado = ""
    print("------------------------------------------------------------------------------")
    print(f"Total de paquetes en el archivo: {len(paquetes)}")
    print("------------------------------------------------------------------------------")

    for i, paquete in enumerate(paquetes):
        print(f"\nAnalizando paquete {i}:")
        if IP in paquete:
            print(f"  IP src: {paquete[IP].src}, dst: {paquete[IP].dst}")

        if ICMP in paquete and paquete[ICMP].type == 8:  # tipo 8 es echo-request
            print(f"  ICMP type: {paquete[ICMP].type}")
            if Raw in paquete:
                payload = paquete[Raw].load
                print(f"  Raw payload: {payload}")
                if payload:
                    caracter = payload.decode(errors='ignore')
                    mensaje_cifrado += caracter
                    print(f"  Caracter extraído: {caracter}")
                else:
                    print("  Advertencia: Carga útil Raw vacía.")
            else:
                print("  Advertencia: No se encontró capa Raw en el paquete ICMP.")
        else:
            print("  No es un paquete ICMP echo-request")

    return mensaje_cifrado


def descifrar_cesar(texto, desplazamiento):
    """
    Descifra un texto cifrado con el cifrado César para un desplazamiento dado.
    """
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            codigo_base = ord('A') if caracter.isupper() else ord('a')
            nuevo_caracter = chr((ord(caracter) - codigo_base - desplazamiento) % 26 + codigo_base)
            resultado += nuevo_caracter
        else:
            resultado += caracter
    return resultado


def calcular_puntuacion_frecuencia(texto):
    """
    Calcula una puntuación basada en la frecuencia de las letras en español.
    """
    frecuencia_esperada = {
        'e': 13.68, 'a': 12.53, 'o': 8.68, 'l': 8.44, 's': 7.20, 'n': 6.83, 'd': 5.86, 'r': 6.87,
        'u': 3.93, 'i': 6.25, 't': 4.63, 'c': 4.68, 'p': 2.51, 'm': 3.15, 'y': 0.90, 'q': 0.88,
        'b': 1.42, 'h': 0.70, 'g': 1.01, 'f': 0.69, 'v': 0.90, 'j': 0.44, 'ñ': 0.29, 'z': 0.15,
        'x': 0.22, 'k': 0.01, 'w': 0.01
    }

    texto = texto.lower()
    total_letras = sum(1 for c in texto if c.isalpha())
    if total_letras == 0:
        return 0

    frecuencia_actual = {letra: texto.count(letra) / total_letras * 100 for letra in string.ascii_lowercase}

    puntuacion = sum(abs(frecuencia_actual.get(letra, 0) - valor) for letra, valor in frecuencia_esperada.items())
    return -puntuacion  # Negativo porque queremos maximizar la similitud


def descifrar_mensaje_completo(mensaje_cifrado):
    if not mensaje_cifrado:
        print("No se encontró ningún mensaje cifrado en los paquetes.")
        return

    posibles_mensajes = {}
    for desplazamiento in range(26):
        texto_descifrado = descifrar_cesar(mensaje_cifrado, desplazamiento)
        puntuacion = calcular_puntuacion_frecuencia(texto_descifrado)
        posibles_mensajes[desplazamiento] = (texto_descifrado, puntuacion)

    # Determinar la opción más probable
    desplazamiento_probable = max(posibles_mensajes.keys(), key=lambda x: posibles_mensajes[x][1])

    print("\nOpciones de descifrado:")
    for desplazamiento, (mensaje, _) in posibles_mensajes.items():
        if desplazamiento == desplazamiento_probable:
            print(f"{Fore.GREEN}Desplazamiento {desplazamiento}: {mensaje}{Style.RESET_ALL}")
        else:
            print(f"Desplazamiento {desplazamiento}: {mensaje}")

    print(f"\nDesplazamiento más probable: {desplazamiento_probable}")


if __name__ == "__main__":
    # Necesito que se escoga el archivo de captura
    print("------------------------------------------------------------------------------")
    archivo = input("Ingrese el nombre del archivo de captura (agrega el '.pcap'): ")
    while not archivo.endswith('.pcap'):
        print("------------------------------------------------------------------------------")
        archivo = input("Ingrese el nombre del archivo de captura (agrega el '.pcap'): ")
    
    archivo_pcap = f"./capturas/{archivo}"
    
    mensaje_cifrado = leer_pcap(archivo_pcap)
    print("------------------------------------------------------------------------------")
    print("Mensaje cifrado extraído:", mensaje_cifrado)
    print("------------------------------------------------------------------------------")
    if mensaje_cifrado:
        descifrar_mensaje_completo(mensaje_cifrado)
    else:
        print("No se pudo extraer ningún mensaje cifrado de los paquetes.")