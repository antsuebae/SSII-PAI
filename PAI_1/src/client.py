import socket
import json
import getpass
from crypto_utils import compute_mac, generate_nonce

def send_msg(conn, msg_dict):
    conn.send(json.dumps(msg_dict).encode())

def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect(("127.0.0.1", 8888))
    except ConnectionRefusedError:
        print("❌ Error: No se puede conectar al servidor. ¿Está ejecutándose?")
        return

    current_user = None  # Para recordar quién está logeado

    while True:
        print("\n1. Registrar")
        print("2. Login")
        print("3. Transacción")
        print("4. Cerrar sesión")
        print("5. Salir")
        opt = input("Opción: ").strip()

        if opt == "1":
            user = input("Usuario: ")
            pwd = getpass.getpass("Contraseña: ")
            send_msg(conn, {"type": "register", "username": user, "password": pwd})
            response = conn.recv(1024).decode()
            print(response)

        elif opt == "2":
            user = input("Usuario: ")
            pwd = getpass.getpass("Contraseña: ")
            send_msg(conn, {"type": "login", "username": user, "password": pwd})
            response = conn.recv(1024).decode()
            print(response)
            # Interpretamos la respuesta para saber si el login fue exitoso
            if '"status": "ok"' in response:
                current_user = user

        elif opt == "3":
            if current_user is None:
                print("❌ Debes iniciar sesión primero.")
                continue
            destino = input("Cuenta destino: ")
            cantidad = input("Cantidad: ")
            # Construimos el mensaje con la cuenta origen implícita
            data = f"{current_user},{destino},{cantidad}"
            nonce = generate_nonce()
            mac = compute_mac(data, nonce)
            send_msg(conn, {"type": "transaction", "data": data, "nonce": nonce, "mac": mac})
            response = conn.recv(1024).decode()
            print(response)

        elif opt == "4":
            send_msg(conn, {"type": "logout"})
            response = conn.recv(1024).decode()
            print(response)
            current_user = None

        elif opt == "5":
            print("Saliendo...")
            break

        else:
            print("Opción no válida.")

    conn.close()

if __name__ == "__main__":
    main()
