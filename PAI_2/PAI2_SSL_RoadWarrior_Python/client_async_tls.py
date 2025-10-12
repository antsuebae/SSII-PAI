#!/usr/bin/env python3
import asyncio, ssl, json, argparse, sys
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config():
    import json
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

cfg = load_config()

def tls_context():
    c = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # Trust the specific self-signed cert by loading it as a CA
    cafile = Path(__file__).parent / cfg["certfile"]
    c.load_verify_locations(cafile=cafile)
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        pass
    c.check_hostname = False  # using self-signed; hostname mismatch acceptable for lab
    return c

async def run_client(args):
    reader, writer = await asyncio.open_connection(cfg["host"], cfg["port_tls"], ssl=tls_context())
    async def send(obj):
        writer.write((json.dumps(obj)+"\n").encode("utf-8"))
        await writer.drain()
        data = await reader.readline()
        if not data: 
            print("Disconnected")
            sys.exit(1)
        resp = json.loads(data.decode("utf-8"))
        return resp

    if args.command == "register":
        resp = await send({"action": "register", "username": args.username, "password": args.password})
        print(resp)
    elif args.command == "login":
        resp = await send({"action": "login", "username": args.username, "password": args.password})
        print(resp)
    elif args.command == "send":
        resp = await send({"action": "send_message", "message": args.message})
        print(resp)
    elif args.command == "logout":
        resp = await send({"action": "logout"})
        print(resp)
    elif args.command == "whoami":
        resp = await send({"action": "whoami"})
        print(resp)
    elif args.command == "stats":
        resp = await send({"action": "stats"})
        print(resp)
    else:
        print("Unknown command")
    writer.close()
    await writer.wait_closed()

def main():
    p = argparse.ArgumentParser(description="TLS Client for PAI2")
    sub = p.add_subparsers(dest="command", required=True)
    p_reg = sub.add_parser("register")
    p_reg.add_argument("username")
    p_reg.add_argument("password")
    p_login = sub.add_parser("login")
    p_login.add_argument("username")
    p_login.add_argument("password")
    p_send = sub.add_parser("send")
    p_send.add_argument("message")
    sub.add_parser("logout")
    sub.add_parser("whoami")
    sub.add_parser("stats")
    args = p.parse_args()
    asyncio.run(run_client(args))

if __name__ == "__main__":
    main()
