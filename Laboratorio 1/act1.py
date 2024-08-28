def cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            ascii_inicial = ord('A') if caracter.isupper() else ord('a')
            nuevo_ascii = (ord(caracter) - ascii_inicial + desplazamiento) % 26 + ascii_inicial
            resultado += chr(nuevo_ascii)
        else:
            resultado += caracter
    return resultado

# Ingreso de datos para realizar el cifrado César
print("------------------------------------------------------------------------------")
texto = input("Ingrese el texto a cifrar: ")
move = int(input("Ingrese el desplazamiento (número entero): "))
print("------------------------------------------------------------------------------")
# Llamada a la función cesar
texto_cifrado = cesar(texto, move)
print(f"Texto original: {texto}")
print(f"Texto cifrado: {texto_cifrado}")
print("------------------------------------------------------------------------------")




