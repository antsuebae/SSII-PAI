#!/usr/bin/env python3
import asyncio, ssl, json, sqlite3, os, time, secrets, hashlib, base64, argparse, logging
from datetime import datetime, timedelta
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config():
    import json
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

cfg = load_config()
DB_PATH = Path(__file__).parent / cfg["db_path"]
LOGS_DIR = Path(__file__).parent / "logs"
LOGS_DIR.mkdir(exist_ok=True, parents=True)
logging.basicConfig(filename=LOGS_DIR/"server_tls.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# In-memory failed attempts for brute-force protection
failed_attempts = {}  # key: (username, ip) -> [timestamps]
locked_until = {}     # key: (username, ip) -> unlock_timestamp

def now_ts():
    return int(time.time())

def scrypt_hash(password: str, salt: bytes) -> str:
    # Strong password hashing using scrypt (built-in, no external deps)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return base64.b64encode(digest).decode("ascii")

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True, parents=True)
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
    con.commit()
    # preload initial users if missing
    initial_users_file = Path(__file__).parent / cfg["initial_users_file"]
    if initial_users_file.exists():
        import json
        with open(initial_users_file, "r") as f:
            init_users = json.load(f)
        for u in init_users:
            try:
                add_user(cur, u["username"], u["password"])
                logging.info(f"Preloaded user {u['username']}")
            except sqlite3.IntegrityError:
                pass
        con.commit()
    con.close()

def add_user(cur, username, password):
    salt = os.urandom(16)
    pwh = scrypt_hash(password, salt)
    cur.execute("INSERT INTO users(username, password_hash, salt, created_at) VALUES(?,?,?,?)",
                (username, pwh, salt, datetime.utcnow().isoformat()))

def verify_user(cur, username, password) -> bool:
    row = cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return False
    pwh, salt = row
    return scrypt_hash(password, salt) == pwh

def record_message(cur, username, message):
    cur.execute("INSERT INTO messages(username, message, created_at) VALUES(?,?,?)",
                (username, message, datetime.utcnow().isoformat()))

def count_messages(cur, username):
    row = cur.execute("SELECT COUNT(*) FROM messages WHERE username=?", (username,)).fetchone()
    return row[0] if row else 0

class Session:
    def __init__(self):
        self.username = None

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    session = Session()
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    msg_max = cfg["message_max_len"]
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            try:
                req = json.loads(data.decode("utf-8"))
            except Exception:
                await send(writer, {"status": "error", "msg": "invalid_json"})
                continue
            action = req.get("action")
            if action == "register":
                username = req.get("username","").strip()
                password = req.get("password","")
                if not username or not password:
                    await send(writer, {"status": "error", "msg": "username_and_password_required"})
                    continue
                try:
                    add_user(cur, username, password)
                    con.commit()
                    await send(writer, {"status": "ok", "msg": "user_registered"})
                except sqlite3.IntegrityError:
                    await send(writer, {"status": "error", "msg": "user_exists"})
            elif action == "login":
                username = req.get("username","").strip()
                password = req.get("password","")
                key = (username, ip)
                # brute force protection
                # check lock
                unlock_at = locked_until.get(key, 0)
                if now_ts() < unlock_at:
                    await send(writer, {"status": "error", "msg": "locked", "unlock_at": unlock_at})
                    continue
                ok = verify_user(cur, username, password)
                if ok:
                    session.username = username
                    failed_attempts.pop(key, None)
                    locked_until.pop(key, None)
                    await send(writer, {"status": "ok", "msg": "login_success"})
                else:
                    lst = failed_attempts.setdefault(key, [])
                    lst.append(now_ts())
                    # remove old
                    window = cfg["lockout"]["window_seconds"]
                    cutoff = now_ts() - window
                    lst[:] = [t for t in lst if t >= cutoff]
                    if len(lst) >= cfg["lockout"]["max_failures"]:
                        locked_until[key] = now_ts() + cfg["lockout"]["lock_seconds"]
                        failed_attempts[key] = []
                        await send(writer, {"status": "error", "msg": "locked", "unlock_at": locked_until[key]})
                    else:
                        await send(writer, {"status": "error", "msg": "bad_credentials"})
            elif action == "logout":
                session.username = None
                await send(writer, {"status": "ok", "msg": "logged_out"})
            elif action == "send_message":
                if not session.username:
                    await send(writer, {"status": "error", "msg": "auth_required"})
                    continue
                message = req.get("message","")
                if not isinstance(message, str):
                    await send(writer, {"status": "error", "msg": "invalid_message"})
                    continue
                if len(message) > msg_max:
                    await send(writer, {"status": "error", "msg": "message_too_long", "max": msg_max})
                    continue
                record_message(cur, session.username, message)
                con.commit()
                total = count_messages(cur, session.username)
                await send(writer, {"status": "ok", "msg": "message_received", "count": total})
            elif action == "whoami":
                await send(writer, {"status": "ok", "username": session.username})
            elif action == "stats":
                # return counts per user
                rows = cur.execute("SELECT username, COUNT(*) FROM messages GROUP BY username").fetchall()
                await send(writer, {"status": "ok", "stats": {u:c for (u,c) in rows}})
            else:
                await send(writer, {"status": "error", "msg": "unknown_action"})
    except Exception as e:
        logging.exception("Exception in client handler: %s", e)
    finally:
        con.close()
        writer.close()
        await writer.wait_closed()

async def send(writer, obj):
    data = (json.dumps(obj) + "\n").encode("utf-8")
    writer.write(data)
    await writer.drain()

def tls_context():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Enforce TLS1.3 minimum if available
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        c.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
    # Strong ciphers (only effective for < TLS1.3; TLS1.3 suites are not configurable in Python, but we document policy)
    try:
        c.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
    except Exception:
        pass
    certfile = Path(__file__).parent / cfg["certfile"]
    keyfile = Path(__file__).parent / cfg["keyfile"]
    c.load_cert_chain(certfile=certfile, keyfile=keyfile)
    c.set_ecdh_curve("secp384r1")
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE  # server-auth only; clients auth by app-level login
    return c

async def main():
    init_db()
    host = cfg["host"]
    port = cfg["port_tls"]
    context = tls_context()
    server = await asyncio.start_server(handle_client, host, port, ssl=context, start_serving=True)
    addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[TLS SERVER] Listening on {addr} (TLS)")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped.")
