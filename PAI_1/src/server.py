import socket
import json
import os
import hmac
import hashlib
import secrets
from datetime import datetime

# Rutas relativas al directorio raíz del proyecto (PAI_1/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "transactions.log")

# Clave compartida para MAC (32 bytes = 256 bits)
SHARED_KEY = b"clave_secreta_256_bits_segura_PA1"

# Conjunto de NONCE usados (protección anti-replay)
used_nonces = set()

def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return pwd_hash.hex(), salt

def verify_password(stored_hash: str, stored_salt: str, password: str) -> bool:
    pwd_hash, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(pwd_hash, stored_hash)

def verify_mac(data: str, nonce: str, received_mac: str) -> bool:
    message = data + nonce
    expected_mac = hmac.new(SHARED_KEY, message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_mac, received_mac)

def load_users():
    if not os.path.exists(USERS_FILE):
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        pwd1, salt1 = hash_password("pepe")
        pwd2, salt2 = hash_password("paco")
        default_users = {
            "paco": {"password_hash": pwd1, "salt": salt1},
            "pepe": {"password_hash": pwd2, "salt": salt2}
        }
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)
        return default_users
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def log_transaction(tx):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {tx}\n")

def handle_client(conn):
    users = load_users()
    logged_in = False
    current_user = None

    while True:
        try:
            raw = conn.recv(1024).decode()
            if not raw:
                break
            msg = json.loads(raw)

            if msg["type"] == "register":
                username = msg["username"]
                password = msg["password"]
                if username in users:
                    response = {"status": "error", "msg": "Usuario ya existe"}
                else:
                    pwd_hash, salt = hash_password(password)
                    users[username] = {"password_hash": pwd_hash, "salt": salt}
                    save_users(users)
                    response = {"status": "ok", "msg": "Registro exitoso"}
                conn.send(json.dumps(response, ensure_ascii=False).encode())

            elif msg["type"] == "login":
                username = msg["username"]
                password = msg["password"]
                if username in users and verify_password(
                    users[username]["password_hash"],
                    users[username]["salt"],
                    password
                ):
                    logged_in = True
                    current_user = username
                    response = {"status": "ok", "msg": "Login exitoso"}
                else:
                    response = {"status": "error", "msg": "Credenciales inválidas"}
                conn.send(json.dumps(response, ensure_ascii=False).encode())

            elif msg["type"] == "transaction":
                if not logged_in:
                    response = {"status": "error", "msg": "No autenticado"}
                    conn.send(json.dumps(response, ensure_ascii=False).encode())
                    continue

                if "data" not in msg or "nonce" not in msg or "mac" not in msg:
                    response = {"status": "error", "msg": "Mensaje de transacción incompleto"}
                    conn.send(json.dumps(response, ensure_ascii=False).encode())
                    continue

                data = msg["data"]
                nonce = msg["nonce"]
                mac = msg["mac"]

                if nonce in used_nonces:
                    response = {"status": "error", "msg": "NONCE repetido (replay)"}
                    conn.send(json.dumps(response, ensure_ascii=False).encode())
                    continue
                used_nonces.add(nonce)

                if not verify_mac(data, nonce, mac):
                    response = {"status": "error", "msg": "Fallo de integridad (MAC)"}
                    conn.send(json.dumps(response, ensure_ascii=False).encode())
                    continue

                try:
                    parts = [p.strip() for p in data.split(",")]
                    if len(parts) != 3:
                        raise ValueError("Formato inválido")
                    origen, destino, cantidad = parts
                    if origen != current_user:
                        response = {"status": "error", "msg": "La cuenta origen debe ser la del usuario logeado"}
                        conn.send(json.dumps(response, ensure_ascii=False).encode())
                        continue
                except Exception:
                    response = {"status": "error", "msg": "Formato de transacción inválido"}
                    conn.send(json.dumps(response, ensure_ascii=False).encode())
                    continue

                log_transaction(f"{current_user}: {data}")
                response = {"status": "ok", "msg": "Transacción registrada"}
                conn.send(json.dumps(response, ensure_ascii=False).encode())

            elif msg["type"] == "logout":
                logged_in = False
                current_user = None
                response = {"status": "ok", "msg": "Sesión cerrada"}
                conn.send(json.dumps(response, ensure_ascii=False).encode())

            else:
                response = {"status": "error", "msg": "Tipo de mensaje desconocido"}
                conn.send(json.dumps(response, ensure_ascii=False).encode())

        except json.JSONDecodeError:
            response = {"status": "error", "msg": "Mensaje no válido (JSON inválido)"}
            conn.send(json.dumps(response, ensure_ascii=False).encode())
        except Exception as e:
            response = {"status": "error", "msg": f"Error interno: {str(e)}"}
            conn.send(json.dumps(response, ensure_ascii=False).encode())
            break

    conn.close()

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 8888))
    server.listen(5)
    print("🏦 Servidor iniciado en 127.0.0.1:8888")
    print("Usuarios preexistentes: paco (pass: pepe), pepe (pass: paco)")
    try:
        while True:
            conn, addr = server.accept()
            print(f"🔌 Conexión desde {addr}")
            handle_client(conn)
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido.")
    finally:
        server.close()
