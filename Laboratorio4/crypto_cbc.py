from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Función para ajustar la clave a la longitud necesaria
def adjust_key(key, key_size):
    if len(key) < key_size:
        key += get_random_bytes(key_size - len(key))
    elif len(key) > key_size:
        key = key[:key_size]
    return key

# Función para cifrar con DES en modo CBC
def encrypt_des(key, iv, plaintext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = pad(plaintext, DES.block_size)
    encrypted_data = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_data).decode()

# Función para descifrar con DES en modo CBC
def decrypt_des(key, iv, ciphertext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, DES.block_size).decode()

# Función para cifrar con AES-256 en modo CBC
def encrypt_aes(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plaintext, AES.block_size)
    encrypted_data = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_data).decode()

# Función para descifrar con AES-256 en modo CBC
def decrypt_aes(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, AES.block_size).decode()

# Función para cifrar con 3DES en modo CBC
def encrypt_3des(key, iv, plaintext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = pad(plaintext, DES3.block_size)
    encrypted_data = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_data).decode()

# Función para descifrar con 3DES en modo CBC
def decrypt_3des(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, DES3.block_size).decode()

# Función principal que maneja el cifrado y descifrado
def main():
    algorithm = input("Seleccione el algoritmo (DES, 3DES, AES-256): ")
    plaintext = input("Ingrese el mensaje a cifrar: ").encode()
    key_size = 8 if algorithm == 'DES' else (24 if algorithm == '3DES' else 32)
    iv_size = 8 if algorithm in ['DES', '3DES'] else 16
    
    # Obtener y ajustar clave
    key = input(f"Ingrese una clave de hasta {key_size} bytes para {algorithm}: ").encode()
    key = adjust_key(key, key_size)
    
    # Obtener y validar IV
    iv = input(f"Ingrese un IV de {iv_size} bytes: ").encode()  # Cambiar de hexadecimal a texto
    if len(iv) != iv_size:
        print(f"El IV debe ser de {iv_size} bytes.")
        return

    # Cifrar y descifrar según el algoritmo
    if algorithm == 'DES':
        encrypted_text = encrypt_des(key, iv, plaintext)
        decrypted_text = decrypt_des(key, iv, encrypted_text)
    elif algorithm == '3DES':
        encrypted_text = encrypt_3des(key, iv, plaintext)
        decrypted_text = decrypt_3des(key, iv, encrypted_text)
    elif algorithm == 'AES-256':
        encrypted_text = encrypt_aes(key, iv, plaintext)
        decrypted_text = decrypt_aes(key, iv, encrypted_text)
    else:
        print("Algoritmo no reconocido.")
        return
    
    # Mostrar resultados
    print(f"\nMensaje cifrado (base64): {encrypted_text}")
    print(f"Mensaje descifrado: {decrypted_text}")



# Ejecución del programa
if __name__ == "__main__":
    main()


#   Texto a cifrar: Este es un mensaje secreto de prueba para el laboratorio de criptografía!
#   DES
#       Clave : 12345678 1234567891234567
#       IV : 26S7eBSu
#   LujsDpnTGh1x42krUBPwb9qf1dJgf72N5GNsjQB+N+nrs0MT66AwCSge/OSCEzYFIP25gIIMT30JB08+HIWM3JtNosBPl+6rbSku1l1R8DM=

#   AES-256
#       Clave : Esta_es_una_clave_AES_de_32_bytes!
#       IV : 26S7eBSuDYedBQUM
#   F/JfWDXcNnserBjcUACK6qlqIuBhPl3xWcB7cUapyGqFlTfughfNXIhw11V82vszZ+10fdWTME5bealhKuJQ9uLn7Yn0w1MT0wW/cRAIXrc=

#   3DES
#       Clave : TripleDESde24bytesExactos!
#       IV : 26S7eBSu
#   Xwaoh50E0Goworp93n/olCALS7q8STB0zawRhWj/4LT7xlckMrrF+/5+DRV/ZGrwjvTJmY/UtfRMeCVdwNvgpuM9OU9lvjydqHyCPSpgvTs=

