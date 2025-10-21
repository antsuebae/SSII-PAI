#!/usr/bin/env python3
"""
PAI2 single-file runner: starts a TLS asyncio server (background task) and provides
an interactive menu (REPL) to send messages, keeping a persistent TLS client connection to the server.

Uso:
    chmod +x PAI2_single_run.py
    ./PAI2_single_run.py
"""
import asyncio, ssl, json, sqlite3, os, sys, time, hashlib, base64, logging, subprocess, textwrap
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CERTS_DIR = ROOT / "certs"
DATA_DIR = ROOT / "data"
LOGS_DIR = ROOT / "logs"

for d in (CERTS_DIR, DATA_DIR, LOGS_DIR):
    d.mkdir(exist_ok=True, parents=True)

CONFIG = {
    "host": "127.0.0.1",
    "port_tls": 4444,
    "db_path": str(DATA_DIR / "app.db"),
    "certfile": str(CERTS_DIR / "server.crt"),
    "keyfile": str(CERTS_DIR / "server.key"),
    "message_max_len": 144,
    "lockout": {"max_failures":5, "window_seconds":600, "lock_seconds":900},
    # >>> NUEVO: perfil de cifrado seleccionable ('normal' | 'robust'). Por defecto, robusto.
    "cipher_profile": os.environ.get("PAI2_CIPHERS", "robust").lower()
}

SERVER_LOG = LOGS_DIR / "server.log"
logging.basicConfig(filename=str(SERVER_LOG), level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# >>> NUEVO: referencia global a la tarea del servidor para poder reiniciarlo al cambiar perfil
SERVER_TASK = None

# ---------- Generación automática de certificados ----------
def ensure_certs():
    crt = Path(CONFIG["certfile"])
    key = Path(CONFIG["keyfile"])
    if crt.exists() and key.exists():
        return True
    print("🔍 Certificados no encontrados. Generando con OpenSSL...")
    cmd = [
        "openssl","req","-x509","-newkey","rsa:2048",
        "-keyout",str(key),"-out",str(crt),
        "-sha256","-days","365","-nodes","-subj","/CN=localhost"
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Certificados creados:", crt, key)
        return True
    except Exception as e:
        print("⚠️ No se pudieron generar certificados:", e)
        return False

# ---------- Base de datos ----------
DB_PATH = Path(CONFIG["db_path"])

def scrypt_hash(password: str, salt: bytes) -> str:
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return base64.b64encode(digest).decode('ascii')

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt BLOB NOT NULL,
        created_at TEXT NOT NULL
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    users = [("paco","pepe"),("pepe","paco"),("alice","alice1234"),("bob","bob1234"),("carol","carol1234")]
    for u,p in users:
        try:
            salt = os.urandom(16)
            ph = scrypt_hash(p, salt)
            cur.execute("INSERT INTO users VALUES(?,?,?,?)",(u,ph,salt,datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            pass
    con.commit(); con.close()

# ---------- Servidor TLS ----------
failed_attempts, locked_until = {}, {}
def now_ts(): return int(time.time())

def verify_user(cur,u,p):
    row = cur.execute("SELECT password_hash,salt FROM users WHERE username=?",(u,)).fetchone()
    return row and scrypt_hash(p,row[1])==row[0]

def add_user(cur,u,p):
    salt=os.urandom(16)
    cur.execute("INSERT INTO users VALUES(?,?,?,?)",(u,scrypt_hash(p,salt),salt,datetime.now(timezone.utc).isoformat()))

def record_message(cur,u,m):
    cur.execute("INSERT INTO messages(username,message,created_at) VALUES(?,?,?)",(u,m,datetime.utcnow().isoformat()))

def count_messages(cur,u):
    r=cur.execute("SELECT COUNT(*) FROM messages WHERE username=?",(u,)).fetchone()
    return r[0] if r else 0

class Session:
    def __init__(self): self.username=None

async def handle_client(r,w):
    ip = w.get_extra_info("peername")[0]
    # >>> NUEVO: imprimir versión TLS y suite negociada al conectar
    sslobj = w.get_extra_info("ssl_object")
    if sslobj:
        tls_ver = getattr(sslobj, "version", lambda: "UNKNOWN")()
        cipher_info = getattr(sslobj, "cipher", lambda: ("UNKNOWN", "", 0))()
        # cipher_info es (cipher_name, protocol, secret_bits) en CPython/OpenSSL
        cipher_name = cipher_info[0] if isinstance(cipher_info, (tuple, list)) else str(cipher_info)
        msg = f"🔐 Conexión entrante desde {ip} — TLS={tls_ver}, Cipher={cipher_name}"
        print(msg); logging.info(msg)
        # Si quieres exigir explícitamente TLS 1.3, puedes comprobarlo y cerrar si no cumple:
        # if tls_ver != "TLSv1.3": w.close(); await w.wait_closed(); return

    s=Session(); con=sqlite3.connect(DB_PATH); cur=con.cursor()
    try:
        while True:
            d=await r.readline()
            if not d: break
            try: req=json.loads(d.decode())
            except: await send(w,{"status":"error","msg":"invalid_json"}); continue
            a=req.get("action")
            if a=="register":
                u,p=req.get("username","").strip(),req.get("password","")
                if not u or not p: await send(w,{"status":"error","msg":"username_and_password_required"});continue
                try: add_user(cur,u,p); con.commit(); await send(w,{"status":"ok","msg":"user_registered"})
                except sqlite3.IntegrityError: await send(w,{"status":"error","msg":"user_exists"})
            elif a=="login":
                u,p=req.get("username","").strip(),req.get("password",""); key=(u,ip)
                if now_ts()<locked_until.get(key,0): await send(w,{"status":"error","msg":"locked"}); continue
                if verify_user(cur,u,p): s.username=u; failed_attempts.pop(key,None); locked_until.pop(key,None); await send(w,{"status":"ok","msg":"login_success"})
                else:
                    lst=failed_attempts.setdefault(key,[]); lst.append(now_ts())
                    lst[:]=[t for t in lst if t>=now_ts()-CONFIG["lockout"]["window_seconds"]]
                    if len(lst)>=CONFIG["lockout"]["max_failures"]:
                        locked_until[key]=now_ts()+CONFIG["lockout"]["lock_seconds"]; failed_attempts[key]=[]
                        await send(w,{"status":"error","msg":"locked"})
                    else: await send(w,{"status":"error","msg":"bad_credentials"})
            elif a=="logout": s.username=None; await send(w,{"status":"ok","msg":"logged_out"})
            elif a=="send_message":
                if not s.username: await send(w,{"status":"error","msg":"auth_required"}); continue
                m=req.get("message","")
                if len(m)>CONFIG["message_max_len"]: await send(w,{"status":"error","msg":"message_too_long"}); continue
                record_message(cur,s.username,m); con.commit()
                await send(w,{"status":"ok","msg":"message_received","count":count_messages(cur,s.username)})
            elif a=="stats":
                rows=cur.execute("SELECT username,COUNT(*) FROM messages GROUP BY username").fetchall()
                await send(w,{"status":"ok","stats":{u:c for u,c in rows}})
            elif a=="whoami": await send(w,{"status":"ok","username":s.username})
            else: await send(w,{"status":"error","msg":"unknown_action"})
    finally:
        con.close(); w.close(); await w.wait_closed()

async def send(w,o): w.write((json.dumps(o)+"\n").encode()); await w.drain()

# >>> NUEVO: helper para aplicar perfiles de cifrado al SSLContext
def apply_cipher_profile(ctx: ssl.SSLContext, profile: str):
    """
    Aplica un perfil de cifrado 'normal' o 'robust' al contexto.
    - Para TLS 1.3: si la plataforma soporta set_ciphersuites, restringe cuando profile='robust'.
    - Para < TLS 1.3: usa set_ciphers con expresiones OpenSSL.
    """
    profile = (profile or "robust").lower()
    # TLS 1.3 ciphersuites: (si está disponible)
    try:
        if hasattr(ctx, "set_ciphersuites"):
            if profile == "robust":
                # Restringe a suites fuertes y comunes en TLS 1.3
                ctx.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
            else:
                # "normal": no restringimos explícitamente las TLS 1.3 (deja las default del sistema)
                pass
    except Exception:
        pass

    # TLS 1.2 y anteriores (afecta sólo si se negocia <1.3)
    try:
        if profile == "robust":
            ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
        else:
            # normal: conjunto alto, evitando algoritmos inseguros
            ctx.set_ciphers("HIGH:!aNULL:!MD5:!RC4")
    except Exception:
        pass

def tls_context_server():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Intenta TLS 1.3; si no está disponible, baja a 1.2
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        c.minimum_version = ssl.TLSVersion.TLSv1_2

    # >>> NUEVO: aplicar perfil de cifrado seleccionado
    apply_cipher_profile(c, CONFIG.get("cipher_profile", "robust"))

    c.load_cert_chain(CONFIG["certfile"], CONFIG["keyfile"])
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

async def start_server():
    init_db()
    try:
        srv = await asyncio.start_server(
            handle_client, CONFIG["host"], CONFIG["port_tls"], ssl=tls_context_server()
        )
    except Exception as e:
        print(f"❌ Error iniciando servidor TLS: {e}")
        raise
    print(f"🚀 Servidor TLS escuchando en {CONFIG['host']}:{CONFIG['port_tls']} (perfil cifrado: {CONFIG.get('cipher_profile')})")
    async with srv:
        await srv.serve_forever()

# ---------- Servidor NO-TLS (baseline) ----------
async def handle_plain(r,w):
    try:
        while True:
            d=await r.readline()
            if not d: break
            w.write(b'{"status":"ok","msg":"plain_ok"}\n'); await w.drain()
    finally: w.close(); await w.wait_closed()

async def start_plain_server():
    s=await asyncio.start_server(handle_plain,CONFIG["host"],4445)
    print(f"🟢 Servidor baseline NO-TLS en {CONFIG['host']}:4445")
    async with s: await s.serve_forever()

# ---------- Contexto TLS cliente ----------
def tls_context_client():
    c=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    c.load_verify_locations(cafile=CONFIG["certfile"])
    c.minimum_version=ssl.TLSVersion.TLSv1_3
    c.check_hostname=False
    return c

# ---------- Cliente persistente ----------
class ClientSession:
    def __init__(self): self.reader=None; self.writer=None; self.connected=False
    async def connect(self):
        if self.connected: return True
        try:
            self.reader,self.writer=await asyncio.open_connection(CONFIG["host"],CONFIG["port_tls"],ssl=tls_context_client())
            # >>> NUEVO: informar versión y cipher desde el lado cliente también (opcional)
            try:
                sslobj = self.writer.get_extra_info("ssl_object")
                if sslobj:
                    tls_ver = getattr(sslobj, "version", lambda: "UNKNOWN")()
                    cipher_info = getattr(sslobj, "cipher", lambda: ("UNKNOWN", "", 0))()
                    cipher_name = cipher_info[0] if isinstance(cipher_info, (tuple, list)) else str(cipher_info)
                    print(f"🤝 Cliente conectado — TLS={tls_ver}, Cipher={cipher_name}")
            except Exception:
                pass
            self.connected=True; return True
        except Exception as e: print("⚠️ No se pudo conectar:",e); return False
    async def send(self,obj):
        if not self.connected and not await self.connect(): return None
        self.writer.write((json.dumps(obj)+"\n").encode()); await self.writer.drain()
        data=await self.reader.readline()
        return json.loads(data.decode()) if data else None
    async def close(self):
        if self.connected:
            self.writer.close(); await self.writer.wait_closed(); self.connected=False

# ---------- Prueba de capacidad ----------
async def capacity_test_tls(n=300):
    import statistics
    async def client_task(i,res):
        try:
            r,w=await asyncio.open_connection(CONFIG["host"],CONFIG["port_tls"],ssl=tls_context_client())
            u,p=[("alice","alice1234"),("bob","bob1234"),("carol","carol1234")][i%3]
            t0=time.perf_counter()
            w.write((json.dumps({"action":"login","username":u,"password":p})+"\n").encode()); await w.drain(); await r.readline()
            w.write((json.dumps({"action":"send_message","message":f"hola {i}"})+"\n").encode()); await w.drain(); await r.readline()
            res.append(time.perf_counter()-t0)
            w.close(); await w.wait_closed()
        except: pass
    res=[]; await asyncio.gather(*(client_task(i,res) for i in range(n)))
    if not res: print("Sin resultados"); return
    res.sort(); print(json.dumps({
        "clients":n,"success":len(res),
        "p50":res[int(.5*len(res))-1],
        "p90":res[int(.9*len(res))-1],
        "p99":res[int(.99*len(res))-1]
    },indent=2))

# ---------- Comparativa rendimiento ----------
async def benchmark_tls_vs_plain(req=500,conc=100):
    import statistics
    plain_task=asyncio.create_task(start_plain_server()); await asyncio.sleep(0.5)
    async def run(mode,port):
        lat=[]
        sem=asyncio.Semaphore(conc)
        async def one():
            async with sem:
                t0=time.perf_counter()
                if mode=="tls":
                    r,w=await asyncio.open_connection(CONFIG["host"],CONFIG["port_tls"],ssl=tls_context_client())
                else:
                    r,w=await asyncio.open_connection(CONFIG["host"],port)
                w.write(b'{"action":"stats"}\n'); await w.drain(); await r.readline()
                lat.append(time.perf_counter()-t0)
                w.close(); await w.wait_closed()
        await asyncio.gather(*(one() for _ in range(req)))
        lat.sort()
        return {"avg":sum(lat)/len(lat),"p50":lat[int(.5*len(lat))-1],"p90":lat[int(.9*len(lat))-1],"p99":lat[int(.99*len(lat))-1],"throughput_rps":len(lat)/sum(lat)}
    print("⏱️ TLS..."); tls=await run("tls",CONFIG["port_tls"])
    print(json.dumps(tls,indent=2))
    print("⏱️ NO-TLS..."); plain=await run("plain",4445)
    print(json.dumps(plain,indent=2))
    print(json.dumps({"TLS":tls,"NO_TLS":plain},indent=2))

# ---------- Interfaz ----------
async def repl_loop():
    global SERVER_TASK
    c = ClientSession()

    # Espera activa hasta que el servidor TLS esté escuchando (127.0.0.1:4444)
    import socket, time as _t
    for _ in range(50):  # ~5s máx
        try:
            with socket.create_connection((CONFIG["host"], CONFIG["port_tls"]), timeout=0.2):
                break  # puerto listo
        except OSError:
            _t.sleep(0.1)

    # Conecta el cliente (ya debe estar el servidor arriba)
    await c.connect()

    print("\nUsuarios preexistentes: paco(pepe), pepe(paco), alice/bob/carol")
    print(f"🔧 Perfil de cifrado actual: {CONFIG.get('cipher_profile')}")
    print("💬 Interfaz cliente:\n")
    menu = textwrap.dedent("""
    1. Registrar
    2. Login
    3. Enviar mensaje
    4. Cerrar sesión
    5. Stats
    6. Salir
    7. Prueba de capacidad (TLS ~300)
    8. Comparativa rendimiento (TLS vs NO-TLS)
    9. Cambiar perfil de cifrado (normal/robust) y reiniciar servidor TLS
    """)
    while True:
        print(menu)
        o = input("Opción: ").strip()
        if o == "1":
            u = input("Usuario: ")
            p = input("Contraseña: ")
            print(await c.send({"action":"register","username":u,"password":p}))
        elif o == "2":
            u = input("Usuario: ")
            p = input("Contraseña: ")
            print(await c.send({"action":"login","username":u,"password":p}))
        elif o == "3":
            m = input("Mensaje: ")
            print(await c.send({"action":"send_message","message":m}))
        elif o == "4":
            print(await c.send({"action":"logout"}))
        elif o == "5":
            print(await c.send({"action":"stats"}))
        elif o == "7":
            n = input("¿N clientes? [300]: ") or "300"
            await capacity_test_tls(int(n))
        elif o == "8":
            r = input("Peticiones [500]: ") or "500"
            c2 = input("Concurrencia [100]: ") or "100"
            await benchmark_tls_vs_plain(int(r), int(c2))
        elif o == "9":
            newp = input(f"Perfil (normal/robust) [actual: {CONFIG.get('cipher_profile')}]: ").strip().lower()
            if newp in ("normal","robust"):
                if newp != CONFIG.get("cipher_profile"):
                    print(f"♻️ Reiniciando servidor TLS con perfil: {newp} ...")
                    CONFIG["cipher_profile"] = newp
                    if SERVER_TASK:
                        SERVER_TASK.cancel()
                        await asyncio.sleep(0.2)
                    SERVER_TASK = asyncio.create_task(start_server())
                    await asyncio.sleep(0.6)  # pequeña espera para que quede escuchando
                    # Re-conectar cliente para que negocie con el nuevo perfil
                    await c.close()
                    await c.connect()
                else:
                    print("Sin cambios (mismo perfil).")
            else:
                print("Perfil no válido. Usa 'normal' o 'robust'.")
        elif o in ("6","exit","q","quit"):
            await c.close()
            print("Saliendo...")
            return
        else:
            print("Opción no válida")

# ---------- Main ----------
async def main():
    global SERVER_TASK
    if not ensure_certs(): return
    SERVER_TASK = asyncio.create_task(start_server())
    await asyncio.sleep(0.5)
    try:
        await repl_loop()
    finally:
        if SERVER_TASK:
            SERVER_TASK.cancel()
        await asyncio.sleep(0.2)

if __name__=="__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\nInterrumpido por usuario.")
