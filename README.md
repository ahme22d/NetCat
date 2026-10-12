# NetCat V3

An educational, multi-client **TCP client/server tool** written in pure Python (standard library only). It supports an interactive server console, a JSON-framed protocol, authentication, TLS, integrity-checked file transfer, heartbeats, auto-reconnect, rate limiting, and more.

> **Version:** 3.0.0 · **Python:** 3.9+ recommended · **Dependencies:** none

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Command Reference](#command-reference)
- [CLI Options](#cli-options)
- [Protocol](#protocol)
- [Security Notes](#security-notes)
- [Self Test](#self-test)
- [Disclaimer](#disclaimer)

---

## Features

### Core
- **Dual mode** – run as a TCP **server** (`-l`) or **client** from the same script.
- **Multi-client server** – each client is handled in its own thread, with a configurable cap (`--max-clients`) and listen backlog (`--backlog`).
- **Per-client tracking** – client ID, address, connection time, last activity, username, and auth state.
- **Graceful shutdown** – `Ctrl+C` stops the server/client cleanly and closes all sockets.

### Interactive Server Console (`--interactive`)
- List connected clients, inspect one client, send a message to a client, **broadcast** to all, **kick** a client, and view server stats.

### Interactive Client Shell
- Built-in commands: `help`, `info`, `stats`, `list`, `ping`, `upload`, `download`, `exit`.
- Colored output (toggle with `--color` / `--no-color`).

### File Transfer
- **Upload** and **download** files in configurable chunks (`--chunk-size`).
- **SHA-256 integrity verification** on both directions.
- **Live progress display** on the client.
- **Filename sanitization** (`safe_filename`) to block basic path traversal (e.g. `../../etc/passwd` → `passwd`).
- **Max size limit** (`--max-size`) for frames and files.
- **Cleanup on failure** – partially received files are deleted if a transfer fails.
- Files are stored in a dedicated directory (`--output`, default `uploads/`).
- Can be fully disabled with `--no-file-transfer`.

### Security
- **TLS encryption** (`--tls`) with a server certificate/key (`--cert`, `--key`).
- **Client-side certificate verification** with `--ca-file`.
- **Username/password authentication** (`--auth`) using constant-time comparison (`secrets.compare_digest`) to resist timing attacks.
- **Secure password prompt** – if `--auth` is used without `--password`, the server asks for it with `getpass` (not echoed, not stored in shell history).
- **Rate limiting** (`--rate-limit`) – per-client transfer cap in bytes/second.
- **Frame size validation** – oversized or malformed frames are rejected.

### Reliability
- **Heartbeat** system (`--heartbeat-interval`, `--heartbeat-timeout`) to detect and drop dead connections.
- **Auto-reconnect** for the client (`--reconnect`, `--reconnect-delay`).
- **Configurable socket timeout** (`--timeout`).

### Logging & UX
- Logging to console and to a **log file** (`--log-file`, default `netcat.log`) with timestamps and levels.
- Log levels: `--verbose` (debug) and `--quiet` (errors only).
- Optional startup **banner** (`--banner`).
- Built-in **argument validation** with clear error messages.
- Built-in **self-test suite** (`--self-test`).

---

## Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
python3 netcat.py --help
```

No `pip install` needed — it only uses the Python standard library.

---

## Quick Start

**Terminal 1 – Server**

```bash
python3 netcat.py -l -t 0.0.0.0 -p 5555 --interactive
```

**Terminal 2 – Client**

```bash
python3 netcat.py -t 127.0.0.1 -p 5555
```

Running the script with **no arguments** prints the banner and a quick-start guide.

---

## Usage Examples

**Server with authentication**

```bash
python3 netcat.py -l -t 0.0.0.0 -p 5555 --interactive --auth --username admin
# You will be prompted for the password securely
```

**Client with authentication**

```bash
python3 netcat.py -t 192.168.1.10 -p 5555 --auth --username admin --password 'yourpassword'
```

**Server with TLS**

```bash
# Generate a self-signed certificate (lab use)
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"

python3 netcat.py -l -t 0.0.0.0 -p 5555 --tls --cert server.crt --key server.key --interactive
```

**Client with TLS (verifying the server certificate)**

```bash
python3 netcat.py -t 127.0.0.1 -p 5555 --tls --ca-file server.crt
```

**Auto-reconnect client**

```bash
python3 netcat.py -t 127.0.0.1 -p 5555 --reconnect --reconnect-delay 3
```

**Limit transfer speed to 1 MB/s per client and cap file size at 50 MB**

```bash
python3 netcat.py -l -p 5555 --rate-limit 1048576 --max-size 52428800 --output received_files
```

**Server without file transfer**

```bash
python3 netcat.py -l -p 5555 --no-file-transfer
```

---

## Command Reference

### Server console (requires `--interactive`)

| Command | Description |
|---|---|
| `list` | List all connected clients |
| `info <id>` | Show details about a client |
| `send <id> <message>` | Send a message to one client |
| `broadcast <message>` | Send a message to all clients |
| `kick <id>` | Disconnect a client |
| `stats` | Show server statistics |
| `help` | Show console help |
| `exit` | Shut down the server |

### Client commands

| Command | Description |
|---|---|
| `help` | Show available commands |
| `info` | Show connection/server information |
| `stats` | Show server statistics |
| `list` | List connected clients |
| `ping` | Check connectivity with the server |
| `upload <file>` | Upload a local file to the server |
| `download <file>` | Download a file from the server |
| `exit` | Disconnect |

---

## CLI Options

| Option | Default | Description |
|---|---|---|
| `-l`, `--listen` | off | Run as TCP server |
| `--interactive` | off | Enable interactive server console |
| `-t`, `--host` | `127.0.0.1` | Server / listen host |
| `-p`, `--port` | `5555` | TCP port (1–65535) |
| `--timeout` | `10` | Socket timeout (seconds) |
| `--backlog` | `20` | TCP listen backlog |
| `--max-size` | `104857600` (100 MB) | Maximum frame/file size |
| `--chunk-size` | `65536` (64 KB) | File transfer chunk size |
| `--max-clients` | `20` | Maximum simultaneous clients |
| `--heartbeat-interval` | `20` | Heartbeat interval (seconds) |
| `--heartbeat-timeout` | `60` | Heartbeat timeout (seconds) |
| `--rate-limit` | `0` | Per-client limit in bytes/sec (`0` = unlimited) |
| `--output` | `uploads` | Directory for transferred files |
| `--no-file-transfer` | off | Disable upload/download |
| `--tls` | off | Enable TLS encryption |
| `--cert` | `server.crt` | TLS certificate (server) |
| `--key` | `server.key` | TLS private key (server) |
| `--ca-file` | none | CA certificate used by the client to verify the server |
| `--auth` | off | Enable username/password authentication |
| `--username` | `admin` | Authentication username |
| `--password` | none | Authentication password (prompted on server if omitted) |
| `--reconnect` | off | Client auto-reconnect |
| `--reconnect-delay` | `5` | Reconnect delay (seconds, min 1) |
| `--banner` | off | Show startup banner |
| `--quiet` | off | Reduce console output |
| `-v`, `--verbose` | off | Verbose (debug) logging |
| `--color` / `--no-color` | on | Enable/disable terminal colors |
| `--log-file` | `netcat.log` | Log file path |
| `--self-test` | off | Run built-in self tests |
| `--version` | – | Print version and exit |

> `--verbose` and `--quiet` cannot be used together.

---

## Protocol

Messages use a simple **length-prefixed JSON framing**:

```
[ 4 bytes: payload length (big-endian, unsigned) ][ JSON payload (UTF-8) ]
```

- Every frame must be a JSON **object**.
- Frames larger than `--max-size` or with an invalid size are rejected.
- Message types include authentication (`auth_required`, `auth`, `auth_result`), file transfer (`upload_start`, `upload_result`, `download`, `download_start`), and the control commands listed above.

---

## Security Notes

- **Use `--tls` whenever you use `--auth`.** Without TLS, credentials and files travel in plaintext.
- If the client uses `--tls` **without** `--ca-file`, it runs in *lab mode*: encryption is on, but the server certificate is **not verified** (vulnerable to man-in-the-middle). Always pass `--ca-file` outside of a lab.
- `--ca-file` is used by the **client** to verify the server. The server does not require client certificates.
- Passing `--password` on the command line can leak it via shell history and process lists; prefer the interactive prompt on the server.
- Filename sanitization prevents basic path traversal, but this tool is **not hardened for production or untrusted networks**.

---

## Self Test

```bash
python3 netcat.py --self-test
```

Runs built-in checks for:

1. Protocol header packing/unpacking
2. SHA-256 hashing
3. Filename sanitization
4. JSON protocol framing
5. Rate limiter

---

## Disclaimer

This project is built for **educational purposes** and authorized lab environments only. Only run it on systems and networks you own or have explicit permission to test. The author is not responsible for misuse.

---

## License

Add a `LICENSE` file of your choice (e.g. MIT) before publishing.