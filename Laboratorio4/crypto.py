from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_message(algorithm, plaintext):
    # Establecer tamaño de clave y algoritmo
    if algorithm == 'DES':
        key_size = 8       # Clave de 8 bytes para DES
        iv_size = 8
        mode = DES.MODE_ECB

    elif algorithm == 'AES-256':
        key_size = 32      # Clave de 32 bytes para AES-256
        iv_size = 16       # AES requiere un IV de 16 bytes
        mode = AES.MODE_ECB

    elif algorithm == '3DES':
        key_size = 24      # Clave de 24 bytes para 3DES
        iv_size = 8
        mode = DES3.MODE_ECB

    else:
        print("Algoritmo no reconocido.")
        return

    # Pedir al usuario clave, IV y mensaje para cifrar
    key = input(f"Ingrese una clave de {key_size} bytes para {algorithm}: ").encode()

    # Validar que la clave tenga la longitud correcta
    if len(key) != key_size:
        print(f"La clave debe ser de {key_size} bytes.")
        return

    # Configuración de cifrado según el algoritmo seleccionado
    if algorithm == 'DES':
        cipher = DES.new(key, mode)
    elif algorithm == 'AES-256':
        cipher = AES.new(key, mode)
    elif algorithm == '3DES':
        cipher = DES3.new(key, mode)

    # Cifrar el mensaje
    padded_text = pad(plaintext, cipher.block_size)  # Ajustar al tamaño de bloque
    encrypted_data = cipher.encrypt(padded_text)
    encoded_data = base64.b64encode(encrypted_data).decode()

    # Mostrar el texto cifrado en base64
    print(f"\nMensaje cifrado (base64): {encoded_data}")

# Llamada a la función principal
if __name__ == "__main__":
    plaintext = input("Ingrese el mensaje a cifrar: ").encode()
    algorithm = input("Seleccione el algoritmo (DES, 3DES, AES-256): ")
    encrypt_message(algorithm, plaintext)

#   Texto a cifrar: Este es un mensaje secreto de prueba para el laboratorio de criptografía!
#   DES
#       Clave : 12345678 
#       IV : 26S7eBSu
#   LujsDpnTGh1x42krUBPwb9qf1dJgf72N5GNsjQB+N+nrs0MT66AwCSge/OSCEzYFIP25gIIMT30JB08+HIWM3JtNosBPl+6rbSku1l1R8DM=

#   AES-256
#       Clave : Esta_es_una_clave_AES_de_32_bytes!
#       IV : 26S7eBSuDYedBQUM
#   F/JfWDXcNnserBjcUACK6qlqIuBhPl3xWcB7cUapyGqFlTfughfNXIhw11V82vszZ+10fdWTME5bealhKuJQ9uLn7Yn0w1MT0wW/cRAIXrc=

#   3DES
#       Clave : TripleDESde24bytesExacto  s!
#       IV : 26S7eBSu
#   Xwaoh50E0Goworp93n/olCALS7q8STB0zawRhWj/4LT7xlckMrrF+/5+DRV/ZGrwjvTJmY/UtfRMeCVdwNvgpuM9OU9lvjydqHyCPSpgvTs=