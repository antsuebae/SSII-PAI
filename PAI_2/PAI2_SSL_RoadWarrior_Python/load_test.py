#!/usr/bin/env python3
import asyncio, ssl, json, time, statistics
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config():
    import json
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

cfg = load_config()

def tls_context():
    c = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    cafile = Path(__file__).parent / cfg["certfile"]
    c.load_verify_locations(cafile=cafile)
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        pass
    c.check_hostname = False
    return c

async def client_task(idx, results):
    start = time.perf_counter()
    reader, writer = await asyncio.open_connection(cfg["host"], cfg["port_tls"], ssl=tls_context())
    # lightweight flow: login with existing user, send 1 message
    user = f"alice" if idx % 3 == 0 else ("bob" if idx % 3 == 1 else "carol")
    pwd = f"{user}1234"
    async def send(obj):
        writer.write((json.dumps(obj)+"\n").encode("utf-8"))
        await writer.drain()
        data = await reader.readline()
        return json.loads(data.decode("utf-8"))
    r1 = await send({"action":"login","username":user,"password":pwd})
    if r1.get("status")!="ok":
        results.append(("fail", time.perf_counter()-start))
    else:
        r2 = await send({"action":"send_message","message":f"hello from {idx}"})
        results.append(("ok", time.perf_counter()-start))
    writer.close()
    await writer.wait_closed()

async def run(n_clients=300):
    results = []
    start = time.perf_counter()
    await asyncio.gather(*(client_task(i, results) for i in range(n_clients)))
    total = time.perf_counter()-start
    oks = [t for (s,t) in results if s=="ok"]
    fails = [t for (s,t) in results if s!="ok"]
    summary = {
        "clients": n_clients,
        "success": len(oks),
        "failures": len(fails),
        "total_seconds": total,
        "p50_latency": statistics.median(oks) if oks else None,
        "p90_latency": (sorted(oks)[int(0.9*len(oks))-1] if oks else None),
        "p99_latency": (sorted(oks)[int(0.99*len(oks))-1] if oks else None)
    }
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-n","--num", type=int, default=300, help="Number of concurrent clients")
    args = p.parse_args()
    asyncio.run(run(args.num))
