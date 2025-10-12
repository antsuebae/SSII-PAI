#!/usr/bin/env python3
import asyncio, json, sqlite3
from datetime import datetime
from pathlib import Path
import argparse

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config():
    import json
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

cfg = load_config()
DB_PATH = Path(__file__).parent / cfg["db_path"]

async def handle(reader, writer):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            req = json.loads(data.decode("utf-8"))
            # only implement simple echo message for baseline comparison
            if req.get("action") == "ping":
                writer.write(b'{"status":"ok","msg":"pong"}\n')
            else:
                writer.write(b'{"status":"ok","msg":"plain_ok"}\n')
            await writer.drain()
    finally:
        con.close()
        writer.close()
        await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, cfg["host"], cfg["port_plain"])
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[PLAIN SERVER] Listening on {addr} (NO TLS)")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
