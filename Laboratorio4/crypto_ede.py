from Crypto.Cipher import DES3, AES
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

# Función para cifrar con DES-EDE-CBC (Triple DES con dos claves)
def encrypt_des_ede(key, iv, plaintext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = pad(plaintext, DES3.block_size)
    encrypted_data = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_data).decode()

# Función para descifrar con DES-EDE-CBC (Triple DES con dos claves)
def decrypt_des_ede(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, DES3.block_size).decode()

# Función para cifrar con 3DES (DES-EDE3-CBC)
def encrypt_3des(key, iv, plaintext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = pad(plaintext, DES3.block_size)
    encrypted_data = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_data).decode()

# Función para descifrar con 3DES (DES-EDE3-CBC)
def decrypt_3des(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, DES3.block_size).decode()

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

# Función principal que maneja el cifrado y descifrado
def main():
    algorithm = input("Seleccione el algoritmo (DES-EDE, 3DES, AES-256): ")
    plaintext = input("Ingrese el mensaje a cifrar: ").encode()
    
    # Configuración de tamaño de clave e IV
    if algorithm == 'DES-EDE':  # DES-EDE-CBC (dos claves, 16 bytes)
        key_size = 16
        iv_size = 8
    elif algorithm == '3DES':  # DES-EDE3-CBC (tres claves, 24 bytes)
        key_size = 24
        iv_size = 8
    elif algorithm == 'AES-256':
        key_size = 32
        iv_size = 16
    else:
        print("Algoritmo no reconocido.")
        return

    # Obtener y ajustar clave
    key = input(f"Ingrese una clave de hasta {key_size} bytes para {algorithm}: ").encode()
    key = adjust_key(key, key_size)
    
    # Obtener y validar IV
    iv = input(f"Ingrese un IV de {iv_size} bytes: ").encode()
    if len(iv) != iv_size:
        print(f"El IV debe ser de {iv_size} bytes.")
        return

    # Cifrar y descifrar según el algoritmo
    if algorithm == 'DES-EDE':
        encrypted_text = encrypt_des_ede(key, iv, plaintext)
        decrypted_text = decrypt_des_ede(key, iv, encrypted_text)
    elif algorithm == '3DES':
        encrypted_text = encrypt_3des(key, iv, plaintext)
        decrypted_text = decrypt_3des(key, iv, encrypted_text)
    elif algorithm == 'AES-256':
        encrypted_text = encrypt_aes(key, iv, plaintext)
        decrypted_text = decrypt_aes(key, iv, encrypted_text)
    
    # Mostrar resultados
    print(f"\nMensaje cifrado (base64): {encrypted_text}")
    print(f"Mensaje descifrado: {decrypted_text}")

# Ejecución del programa
if __name__ == "__main__":
    main()
