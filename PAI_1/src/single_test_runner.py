#!/usr/bin/env python3
"""
single_test_runner.py
Versión final:
 - Sin opción admin ni ruta get_login_stats
 - Log histórico de login con contadores acumulados
 - JSON UTF-8 (sin caracteres escapados)
 - Servidor, proxy MITM y cliente en un solo script
"""
import socket, threading, json, os, hmac, hashlib, secrets, time
from datetime import datetime

# ---------- Rutas ----------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
TRAN_LOG = os.path.join(LOG_DIR, "transactions.log")
LOGIN_LOG = os.path.join(LOG_DIR, "login_attempts.log")
LOGIN_SUM = os.path.join(LOG_DIR, "login_attempts_summary.json")

# ---------- Configuración ----------
SHARED_KEY = b"clave_secreta_256_bits_segura_PA1"
SERVER_HOST, SERVER_PORT = "127.0.0.1", 8888
PROXY_HOST, PROXY_PORT   = "127.0.0.1", 9999

used_nonces = set()
login_attempts = {}

# ---------- Utilidades ----------
def ensure_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)

def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000)
    return pwd_hash.hex(), salt

def verify_password(stored_hash: str, stored_salt: str, password: str) -> bool:
    pwd_hash, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(pwd_hash, stored_hash)

def verify_mac(data: str, nonce: str, received_mac: str) -> bool:
    expected = hmac.new(SHARED_KEY, (data+nonce).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, received_mac)

def compute_mac(data: str, nonce: str) -> str:
    return hmac.new(SHARED_KEY, (data+nonce).encode(), hashlib.sha256).hexdigest()

def load_users():
    if not os.path.exists(USERS_FILE):
        pwd1, s1 = hash_password("pepe")
        pwd2, s2 = hash_password("paco")
        default = {"paco":{"password_hash":pwd1,"salt":s1},
                   "pepe":{"password_hash":pwd2,"salt":s2}}
        with open(USERS_FILE,"w",encoding="utf-8") as f:
            json.dump(default,f,indent=2,ensure_ascii=False)
        return default
    with open(USERS_FILE,"r",encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE,"w",encoding="utf-8") as f:
        json.dump(users,f,indent=2,ensure_ascii=False)

def log_transaction(txt):
    with open(TRAN_LOG,"a",encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat()}] {txt}\n")

# ---------- Log de intentos ----------
def write_login_summary():
    with open(LOGIN_SUM,"w",encoding="utf-8") as f:
        json.dump(login_attempts,f,indent=2,ensure_ascii=False)

def log_login_attempt(username, success, peer=None):
    """Guarda intento en histórico y actualiza contadores"""
    if username not in login_attempts:
        login_attempts[username] = {"success":0,"failure":0}
    if success:
        login_attempts[username]["success"] += 1
    else:
        login_attempts[username]["failure"] += 1

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    addr = f" from {peer}" if peer else ""
    counters = login_attempts[username]
    line = (f"[{ts}] user={username} success={success}{addr} "
            f"(total: success={counters['success']} failure={counters['failure']})\n")

    with open(LOGIN_LOG,"a",encoding="utf-8") as f:
        f.write(line)
    write_login_summary()

def send_json(conn, obj):
    conn.send(json.dumps(obj, ensure_ascii=False).encode('utf-8'))

# ---------- Servidor ----------
def handle_server_client(conn, addr):
    users = load_users()
    logged_in = False
    current_user = None
    try:
        while True:
            raw = conn.recv(8192).decode('utf-8', errors='ignore')
            if not raw: break
            try:
                msg = json.loads(raw)
            except:
                send_json(conn, {"status":"error","msg":"JSON inválido"}); continue

            t = msg.get("type")
            if t == "register":
                u = msg.get("username"); p = msg.get("password")
                if not u or not p:
                    send_json(conn, {"status":"error","msg":"Datos inválidos"}); continue
                if u in users:
                    send_json(conn, {"status":"error","msg":"Usuario ya existe"})
                else:
                    ph, s = hash_password(p)
                    users[u] = {"password_hash":ph,"salt":s}
                    save_users(users)
                    send_json(conn, {"status":"ok","msg":"Registro exitoso"})

            elif t == "login":
                u = msg.get("username"); p = msg.get("password")
                ok = u in users and verify_password(users[u]["password_hash"], users[u]["salt"], p)
                if ok:
                    logged_in = True; current_user = u
                    log_login_attempt(u, True, addr)
                    send_json(conn, {"status":"ok","msg":"Login exitoso"})
                else:
                    log_login_attempt(u or "<unknown>", False, addr)
                    send_json(conn, {"status":"error","msg":"Credenciales inválidas"})

            elif t == "transaction":
                if not logged_in:
                    send_json(conn, {"status":"error","msg":"No autenticado"}); continue
                data, nonce, mac = msg.get("data"), msg.get("nonce"), msg.get("mac")
                if not data or not nonce or not mac:
                    send_json(conn, {"status":"error","msg":"Mensaje de transacción incompleto"}); continue
                if nonce in used_nonces:
                    send_json(conn, {"status":"error","msg":"NONCE repetido (replay)"}); continue
                if not verify_mac(data, nonce, mac):
                    send_json(conn, {"status":"error","msg":"Fallo de integridad (MAC)"}); continue
                used_nonces.add(nonce)
                try:
                    origen,dest,cant = [p.strip() for p in data.split(",")]
                    if origen != current_user:
                        send_json(conn, {"status":"error","msg":"La cuenta origen debe ser la del usuario logeado"}); continue
                except:
                    send_json(conn, {"status":"error","msg":"Formato inválido"}); continue
                log_transaction(f"{current_user}: {data}")
                send_json(conn, {"status":"ok","msg":"Transacción registrada"})

            elif t == "logout":
                logged_in = False; current_user = None
                send_json(conn, {"status":"ok","msg":"Sesión cerrada"})
            else:
                send_json(conn, {"status":"error","msg":"Tipo desconocido"})
    except ConnectionResetError:
        pass
    finally:
        conn.close()

def server_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    srv.bind((SERVER_HOST, SERVER_PORT)); srv.listen(5)
    print(f"[SERVER] escuchando {SERVER_HOST}:{SERVER_PORT}")
    try:
        while True:
            c,a = srv.accept()
            threading.Thread(target=handle_server_client, args=(c,a), daemon=True).start()
    except Exception as e:
        print("[SERVER] stop:", e)
    finally:
        srv.close()

# ---------- Proxy MITM ----------
last_tx = None

def handle_proxy_client(csock, addr):
    global last_tx
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.connect((SERVER_HOST, SERVER_PORT))

    def c2s_loop():
        global last_tx
        while True:
            data = csock.recv(8192)
            if not data: break
            try:
                msg = json.loads(data.decode('utf-8', errors='ignore'))
            except:
                ss.sendall(data); continue

            if msg.get("type") == "transaction":
                print("\n[PROXY] TX INTERCEPTADA:")
                print(json.dumps(msg, indent=2, ensure_ascii=False))
                print("Acciones: [enter]=reenviar | 1=cambiar cantidad | 2=cambiar destino | 3=quitar mac | 4=replay")
                choice = input("> ").strip()
                if choice == "1":
                    nueva = input("Nueva cantidad: ").strip()
                    partes = [p.strip() for p in msg["data"].split(",")]
                    if len(partes)==3:
                        partes[2] = nueva; msg["data"] = ",".join(partes)
                        print("[PROXY] cantidad cambiada (mac NO recalculada).")
                elif choice == "2":
                    nd = input("Nuevo destino: ").strip()
                    partes = [p.strip() for p in msg["data"].split(",")]
                    if len(partes)==3:
                        partes[1] = nd; msg["data"] = ",".join(partes)
                        print("[PROXY] destino cambiado.")
                elif choice == "3":
                    msg.pop("mac",None); print("[PROXY] mac eliminada.")
                elif choice == "4":
                    if last_tx:
                        print("[PROXY] reenviando last_tx (replay).")
                        ss.sendall(json.dumps(last_tx, ensure_ascii=False).encode('utf-8')); continue
                    else:
                        print("[PROXY] no hay last_tx; reenviando actual.")
                last_tx = msg
                ss.sendall(json.dumps(msg, ensure_ascii=False).encode('utf-8'))
            else:
                ss.sendall(data)
        ss.close(); csock.close()

    def s2c_loop():
        while True:
            data = ss.recv(8192)
            if not data: break
            try:
                parsed = json.loads(data.decode('utf-8', errors='ignore'))
                print("\n[PROXY] RESPUESTA SERVIDOR:", json.dumps(parsed, indent=2, ensure_ascii=False))
            except:
                print("\n[PROXY] RESPUESTA SERVIDOR (raw)")
            csock.sendall(data)
        ss.close(); csock.close()

    threading.Thread(target=c2s_loop, daemon=True).start()
    threading.Thread(target=s2c_loop, daemon=True).start()

def proxy_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    srv.bind((PROXY_HOST, PROXY_PORT)); srv.listen(5)
    print(f"[PROXY] escuchando {PROXY_HOST}:{PROXY_PORT} -> {SERVER_HOST}:{SERVER_PORT}")
    while True:
        c,a = srv.accept()
        threading.Thread(target=handle_proxy_client, args=(c,a), daemon=True).start()

# ---------- Cliente ----------
def client_menu():
    print("Cliente interactivo (conectado a proxy en 127.0.0.1:9999)")
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((PROXY_HOST, PROXY_PORT))
    logged = False
    current_user = None
    while True:
        try:
            print("\n1. Registrar\n2. Login\n3. Transacción\n4. Cerrar sesión\n5. Salir")
            opt = input("Opción: ").strip()
            if opt == "1":
                u = input("Usuario: ").strip(); p = input("Contraseña: ").strip()
                send_json(conn, {"type":"register","username":u,"password":p})
                print(conn.recv(4096).decode('utf-8', errors='ignore'))
            elif opt == "2":
                u = input("Usuario: ").strip(); p = input("Contraseña: ").strip()
                send_json(conn, {"type":"login","username":u,"password":p})
                resp = conn.recv(4096).decode('utf-8', errors='ignore')
                print(resp)
                try:
                    r = json.loads(resp)
                    if r.get("status") == "ok":
                        logged = True; current_user = u
                except: pass
            elif opt == "3":
                if not logged or not current_user:
                    print("Debes iniciar sesión primero."); continue
                dest = input("Cuenta destino: ").strip(); cant = input("Cantidad: ").strip()
                nonce = secrets.token_hex(16)
                data = f"{current_user},{dest},{cant}"
                mac = compute_mac(data, nonce)
                req = {"type":"transaction","data":data,"nonce":nonce,"mac":mac}
                send_json(conn, req)
                print(conn.recv(4096).decode('utf-8', errors='ignore'))
            elif opt == "4":
                send_json(conn, {"type":"logout"}); print(conn.recv(4096).decode('utf-8', errors='ignore'))
                logged=False; current_user=None
            elif opt == "5":
                conn.close(); break
            else:
                print("Opción desconocida")
        except Exception as e:
            print("Error cliente:", e); break

# ---------- Main ----------
if __name__ == "__main__":
    ensure_dirs()
    threading.Thread(target=server_thread, daemon=True).start()
    time.sleep(0.2)
    threading.Thread(target=proxy_thread, daemon=True).start()
    time.sleep(0.2)
    try:
        client_menu()
    except KeyboardInterrupt:
        print("\nSaliendo...")
    finally:
        print("✅ Finalizado correctamente.")
