#!/usr/bin/env python3
import asyncio, json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config():
    import json
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

cfg = load_config()

async def main():
    reader, writer = await asyncio.open_connection(cfg["host"], cfg["port_plain"])
    writer.write(b'{"action":"ping"}\n')
    await writer.drain()
    data = await reader.readline()
    print(json.loads(data.decode("utf-8")))
    writer.close()
    await writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
