# PAI-2 Road Warrior SSL (Python)

Implementación en **Python** de la Arquitectura Cliente-Servidor con **sockets TLS** para cumplir los requisitos del PAI-2 (BYODSEC – Road Warrior).

> Alineado con los **Objetivos**, **Requisitos funcionales**, **Requisitos de información** y **Normas de entregable** del enunciado (v1), con referencias a TLS 1.3 y pruebas de capacidad para ~300 usuarios.

## Estructura

```
PAI2_SSL_RoadWarrior_Python/
├─ server_async_tls.py        # Servidor TLS (asyncio)
├─ client_async_tls.py        # Cliente TLS (CLI)
├─ baseline_server.py         # Servidor sin TLS (comparativa rendimiento)
├─ baseline_client.py         # Cliente sin TLS (ping)
├─ load_test.py               # Prueba de carga concurrente (hasta 300 clientes)
├─ config.json
├─ certs/
│  └─ gen_certs.sh            # Script para generar certificado auto-firmado
├─ data/
│  ├─ app.db                  # (se crea en ejecución)
│  └─ initial_users.json      # Usuarios pre-registrados (alice, bob, carol)
├─ logs/
│  └─ server_tls.log
├─ tests/
│  ├─ run_capacity_test.sh
│  └─ run_functional_tests.sh
└─ README.md
```

## Requisitos

- Python 3.10+ (recomendado)
- OpenSSL disponible en el sistema (para generar el certificado)
- **Wireshark** o **tcpdump** para análisis de tráfico (opcional, para el informe)

## Preparación

```bash
cd PAI2_SSL_RoadWarrior_Python/certs
./gen_certs.sh
```

## Ejecución (TLS)

Terminal A (servidor):

```bash
cd PAI2_SSL_RoadWarrior_Python
python3 server_async_tls.py
```

Terminal B (cliente):

```bash
cd PAI2_SSL_RoadWarrior_Python
# login con usuario preexistente
python3 client_async_tls.py login alice alice1234
# envío de mensaje (máx. 144 chars)
python3 client_async_tls.py send "hola universidad"
# estadísticas de mensajes
python3 client_async_tls.py stats
```

## Baseline (sin TLS, comparativa)

```bash
# Servidor sin TLS
python3 baseline_server.py
# Cliente sin TLS
python3 baseline_client.py
```

Mide latencias con `/usr/bin/time -f "%E"` o `hyperfine` para incluir en el informe una tabla
de rendimiento con y sin TLS.

## Carga concurrente (~300 Road Warriors)

```bash
./tests/run_capacity_test.sh 300
```

Salida JSON con p50/p90/p99 y éxitos/fallos.

## Seguridad

- **TLS 1.3** (si está disponible en tu OpenSSL/Python). Cifrados seguros: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`.
- Almacenamiento de credenciales con **scrypt** + salt (builtin).
- Protección anti **brute-force**: 5 intentos en 10 minutos -> bloqueo 15 minutos por usuario+IP.
- Límite de **144** caracteres por mensaje.
- Persistencia en **SQLite**: usuarios y mensajes con marca temporal.
- **Usuarios preexistentes**: `alice/bob/carol`.

## Sniffing y evidencias (para el informe)

Captura en loopback mientras tienes el servidor/cliente en marcha:

```bash
sudo tcpdump -i lo -w logs/tls_traffic.pcap tcp port 4444
```

Abre `logs/tls_traffic.pcap` en Wireshark:
- Filtra `tcp.port == 4444`.
- Usa *Follow TLS Stream* para mostrar que el **payload está cifrado**.
- Repite la prueba con el servidor **sin TLS** en el puerto 4445 y observa el **payload legible**.

Incluye capturas de pantalla en tu informe.

## Endpoints (protocolo JSON por línea)

- `register {username, password}`
- `login {username, password}`
- `logout`
- `send_message {message}`  → registra y acumula
- `whoami`
- `stats`  → nº de mensajes por usuario

## Notas de compatibilidad TLS

Python no permite forzar suites TLS 1.3 desde la API; la política de cifrados se define y documenta. Para TLS <1.3 se restringen suites fuertes. En OpenSSL recientes, la negociación será 1.3.

## Qué entregar en el ZIP (según normas)

- Código fuente + scripts
- Logs/resultados de pruebas: `logs/server_tls.log`, `logs/tls_traffic.pcap`, salida JSON de `load_test.py`
- Informe PDF con decisiones, arquitectura y evidencias (máx. 10 páginas)

> Este proyecto está diseñado para ejecutarse en **Ubuntu** vía shell sin dependencias externas.
