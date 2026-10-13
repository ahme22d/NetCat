#!/usr/bin/env python3

import argparse
import getpass
import hashlib
import json
import logging
import os
import queue
try:
    import readline
except ImportError:
    readline = None
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

from quic_transport import (
    QuicClientConnection,
    QuicServer,
    create_client_configuration,
    create_server_configuration,
)

# ============================================================
# NetCat V3
# Educational TCP / QUIC Client / Server
# ============================================================

VERSION = "3.0.0"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5555
DEFAULT_TIMEOUT = 10
DEFAULT_BACKLOG = 20
DEFAULT_MAX_SIZE = 100 * 1024 * 1024
DEFAULT_CHUNK_SIZE = 64 * 1024
DEFAULT_MAX_CLIENTS = 20
DEFAULT_HEARTBEAT_INTERVAL = 20
DEFAULT_HEARTBEAT_TIMEOUT = 60


# ============================================================
# Colors
# ============================================================

class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    BOLD = "\033[1m"


def color(text, code, enabled=True):
    if not enabled:
        return text

    return f"{code}{text}{Colors.RESET}"


# ============================================================
# Utilities
# ============================================================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_filename(filename):
    """
    Prevent basic path traversal by allowing only
    the filename itself.
    """

    filename = filename.replace("\\", "/")
    filename = os.path.basename(filename)

    if not filename or filename in {".", ".."}:
        raise ValueError("Invalid filename")

    return filename


def calculate_sha256(path):
    sha256 = hashlib.sha256()

    with open(path, "rb") as file:
        while True:
            chunk = file.read(DEFAULT_CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# Protocol
# ============================================================

HEADER_STRUCT = struct.Struct("!I")


def send_frame(sock, data, max_size=DEFAULT_MAX_SIZE):
    """
    Send JSON framed message.

    Format:

        [4 bytes length][JSON payload]
    """

    raw = json.dumps(
        data,
        separators=(",", ":")
    ).encode("utf-8")

    if len(raw) > max_size:
        raise ValueError("Message exceeds maximum size")

    header = HEADER_STRUCT.pack(len(raw))

    sock.sendall(header + raw)


def receive_exact(sock, size):
    """
    Receive exactly `size` bytes.
    """

    data = bytearray()

    while len(data) < size:

        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data.extend(chunk)

    return bytes(data)


def receive_frame(sock, max_size=DEFAULT_MAX_SIZE):
    """
    Receive one JSON framed message.
    """

    header = receive_exact(
        sock,
        HEADER_STRUCT.size
    )

    size = HEADER_STRUCT.unpack(header)[0]

    if size <= 0:
        raise ValueError("Invalid frame size")

    if size > max_size:
        raise ValueError(
            f"Frame too large: {size} bytes"
        )

    payload = receive_exact(sock, size)

    data = json.loads(
        payload.decode("utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("Invalid protocol message")

    return data


# ============================================================
# Client Information
# ============================================================

@dataclass
class ClientInfo:

    client_id: int

    sock: socket.socket

    address: tuple

    connected_at: float = field(
        default_factory=time.time
    )

    last_activity: float = field(
        default_factory=time.time
    )

    username: str = ""

    authenticated: bool = False

    send_lock: threading.Lock = field(
        default_factory=threading.Lock
    )

    write_lock: threading.RLock = field(
        default_factory=threading.RLock
    )

    rate_lock: threading.Lock = field(
        default_factory=threading.Lock
    )

    rate_window: float = field(
        default_factory=time.time
    )

    rate_bytes: int = 0

    transfer_active: threading.Event = field(
        default_factory=threading.Event
    )


# ============================================================
# Rate Limiter
# ============================================================

class RateLimiter:

    def __init__(self, limit):

        self.limit = max(
            0,
            int(limit)
        )

    def consume(self, client, amount):

        if self.limit <= 0:
            return

        with client.rate_lock:

            current = time.time()

            elapsed = (
                current -
                client.rate_window
            )

            if elapsed >= 1:

                client.rate_window = current
                client.rate_bytes = 0

            if (
                client.rate_bytes +
                amount >
                self.limit
            ):

                wait_time = (
                    1 -
                    (
                        time.time() -
                        client.rate_window
                    )
                )

                if wait_time > 0:
                    time.sleep(wait_time)

                client.rate_window = time.time()
                client.rate_bytes = 0

            client.rate_bytes += amount


# ============================================================
# Logger
# ============================================================

def setup_logger(
    log_file,
    verbose=False,
    quiet=False
):

    logger = logging.getLogger(
        "NetCatV3"
    )

    logger.handlers.clear()

    if verbose:
        level = logging.DEBUG

    elif quiet:
        level = logging.ERROR

    else:
        level = logging.INFO

    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )

    console = logging.StreamHandler()

    console.setLevel(level)
    console.setFormatter(formatter)

    logger.addHandler(console)

    if log_file:

        path = Path(log_file)

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        file_handler = logging.FileHandler(
            path,
            encoding="utf-8"
        )

        file_handler.setLevel(
            logging.DEBUG
        )

        file_handler.setFormatter(
            formatter
        )

        logger.addHandler(
            file_handler
        )

    return logger


# ============================================================
# Server
# ============================================================

class NetCatServer:

    def __init__(self, args):

        self.args = args

        self.host = args.host
        self.port = args.port

        self.timeout = args.timeout
        self.backlog = args.backlog

        self.max_size = args.max_size
        self.chunk_size = args.chunk_size

        self.max_clients = args.max_clients

        self.output_dir = Path(
            args.output
        ).resolve()

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        self.running = True

        self.server_socket = None

        self.clients = {}

        self.clients_lock = (
            threading.RLock()
        )

        self.next_client_id = 1

        self.server_started = time.time()

        self.logger = setup_logger(
            args.log_file,
            args.verbose,
            args.quiet
        )

        self.rate_limiter = RateLimiter(
            args.rate_limit
        )

        self.tls = args.tls

        self.cert = args.cert
        self.key = args.key

        self.auth_enabled = args.auth

        self.username = args.username
        self.password = args.password

    # ========================================================
    # Client Management
    # ========================================================

    def get_client(self, client_id):

        with self.clients_lock:

            return self.clients.get(
                client_id
            )

    def get_clients(self):

        with self.clients_lock:

            return list(
                self.clients.values()
            )

    def client_count(self):

        with self.clients_lock:

            return len(
                self.clients
            )

    def add_client(self, client):

        with self.clients_lock:

            self.clients[
                client.client_id
            ] = client

    def remove_client(self, client_id):

        with self.clients_lock:

            client = self.clients.pop(
                client_id,
                None
            )

        if client is None:
            return

        try:
            client.sock.shutdown(
                socket.SHUT_RDWR
            )

        except OSError:
            pass

        try:
            client.sock.close()

        except OSError:
            pass

        self.logger.info(
            "Client %s disconnected",
            client_id
        )

    # ========================================================
    # Send To Client
    # ========================================================

    def send_to_client(
        self,
        client,
        data
    ):

        with client.write_lock:

            with client.send_lock:

                send_frame(
                    client.sock,
                    data,
                    self.max_size
                )

    # ========================================================
    # Broadcast
    # ========================================================

    def broadcast(
        self,
        message
    ):

        clients = self.get_clients()

        for client in clients:

            try:

                self.send_to_client(
                    client,
                    {
                        "type":
                            "server_message",

                        "message":
                            message
                    }
                )

            except Exception as e:

                self.logger.error(
                    "Broadcast failed "
                    "for client %s: %s",
                    client.client_id,
                    e
                )

    # ========================================================
    # List Clients
    # ========================================================

    def list_clients(self):

        clients = self.get_clients()

        if not clients:

            print(
                color(
                    "No connected clients.",
                    Colors.YELLOW,
                    self.args.color
                )
            )

            return

        print()

        print(
            "ID   Address                  "
            "User        Auth   Connected"
        )

        print("-" * 75)

        for client in clients:

            connected = datetime.fromtimestamp(
                client.connected_at
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print(
                f"{client.client_id:<4} "
                f"{str(client.address):<24} "
                f"{client.username or '-':<10} "
                f"{'YES' if client.authenticated else 'NO':<6} "
                f"{connected}"
            )

        print()

    # ========================================================
    # Client Info
    # ========================================================

    def print_client_info(
        self,
        client_id
    ):

        client = self.get_client(
            client_id
        )

        if not client:

            print(
                color(
                    "Client not found.",
                    Colors.RED,
                    self.args.color
                )
            )

            return

        print()

        print(
            f"Client ID      : "
            f"{client.client_id}"
        )

        print(
            f"Address        : "
            f"{client.address}"
        )

        print(
            f"Username       : "
            f"{client.username or '-'}"
        )

        print(
            f"Authenticated  : "
            f"{client.authenticated}"
        )

        print(
            f"Connected      : "
            f"{datetime.fromtimestamp(client.connected_at)}"
        )

        print(
            f"Last Activity  : "
            f"{datetime.fromtimestamp(client.last_activity)}"
        )

        print()

    # ========================================================
    # Server Stats
    # ========================================================

    def print_stats(self):

        uptime = int(
            time.time() -
            self.server_started
        )

        print()

        print(
            color(
                "========== SERVER STATS ==========",
                Colors.CYAN,
                self.args.color
            )
        )

        print(
            f"Version       : {VERSION}"
        )

        print(
            f"Host          : {self.host}"
        )

        print(
            f"Port          : {self.port}"
        )

        print(
            f"Clients       : "
            f"{self.client_count()}/"
            f"{self.max_clients}"
        )

        print(
            f"Uptime        : "
            f"{uptime} seconds"
        )

        print(
            f"TLS           : "
            f"{self.tls}"
        )

        print(
            f"Authentication : "
            f"{self.auth_enabled}"
        )

        print()

    # ========================================================
    # TLS
    # ========================================================

    def wrap_tls(self, sock):

        if not self.tls:

            return sock

        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER
        )

        context.load_cert_chain(
            certfile=self.cert,
            keyfile=self.key
        )

        return context.wrap_socket(
            sock,
            server_side=True
        )

    # ========================================================
    # Authentication
    # ========================================================

    def authenticate_client(
        self,
        client
    ):

        if not self.auth_enabled:

            client.authenticated = True

            return True

        self.send_to_client(
            client,
            {
                "type":
                    "auth_required"
            }
        )

        try:

            frame = receive_frame(
                client.sock,
                self.max_size
            )

        except Exception:

            return False

        if frame.get("type") != "auth":

            return False

        received_user = str(
            frame.get(
                "username",
                ""
            )
        )

        received_password = str(
            frame.get(
                "password",
                ""
            )
        )

        valid_user = secrets.compare_digest(
            received_user,
            self.username
        )

        valid_password = secrets.compare_digest(
            received_password,
            self.password
        )

        success = (
            valid_user and
            valid_password
        )

        self.send_to_client(
            client,
            {
                "type":
                    "auth_result",

                "ok":
                    success
            }
        )

        if success:

            client.username = (
                received_user
            )

            client.authenticated = True

        return success
    # ========================================================
    # File Upload
    # ========================================================

    def receive_file(
        self,
        client,
        metadata
    ):

        filename = safe_filename(
            str(metadata.get("name", ""))
        )

        size = int(
            metadata.get("size", -1)
        )

        expected_hash = str(
            metadata.get("sha256", "")
        )

        if size < 0:
            self.send_to_client(
                client,
                {
                    "type": "error",
                    "message": "Invalid file size"
                }
            )

            return

        if size > self.max_size:
            self.send_to_client(
                client,
                {
                    "type": "error",
                    "message":
                        "File exceeds maximum size"
                }
            )

            return

        destination = (
            self.output_dir /
            filename
        )

        received = 0

        sha256 = hashlib.sha256()

        self.logger.info(
            "Receiving file '%s' "
            "from client %s",
            filename,
            client.client_id
        )

        try:

            with open(
                destination,
                "wb"
            ) as file:

                while received < size:

                    remaining = (
                        size -
                        received
                    )

                    chunk_size = min(
                        self.chunk_size,
                        remaining
                    )

                    chunk = client.sock.recv(
                        chunk_size
                    )

                    if not chunk:

                        raise ConnectionError(
                            "Connection closed "
                            "during file upload"
                        )

                    self.rate_limiter.consume(
                        client,
                        len(chunk)
                    )

                    file.write(chunk)

                    sha256.update(chunk)

                    received += len(chunk)

                    client.last_activity = (
                        time.time()
                    )

            actual_hash = (
                sha256.hexdigest()
            )

            verified = (
                actual_hash ==
                expected_hash
            )

            self.send_to_client(
                client,
                {
                    "type":
                        "upload_result",

                    "name":
                        filename,

                    "size":
                        received,

                    "sha256":
                        actual_hash,

                    "verified":
                        verified
                }
            )

            self.logger.info(
                "Upload completed: %s "
                "(%d bytes)",
                filename,
                received
            )

        except Exception:

            try:

                if destination.exists():
                    destination.unlink()

            except OSError:
                pass

            raise

    # ========================================================
    # File Download
    # ========================================================

    def send_file(
        self,
        client,
        filename
    ):
        client.transfer_active.set()
        try:
            with client.write_lock:
                self._send_file(client, filename)
        finally:
            client.transfer_active.clear()

    def _send_file(
        self,
        client,
        filename
    ):

        filename = safe_filename(
            filename
        )

        source = (
            self.output_dir /
            filename
        )

        if not source.exists():

            self.send_to_client(
                client,
                {
                    "type":
                        "error",

                    "message":
                        "File not found"
                }
            )

            return

        if not source.is_file():

            self.send_to_client(
                client,
                {
                    "type":
                        "error",

                    "message":
                        "Not a regular file"
                }
            )

            return

        size = source.stat().st_size

        if size > self.max_size:

            self.send_to_client(
                client,
                {
                    "type":
                        "error",

                    "message":
                        "File exceeds maximum size"
                }
            )

            return

        file_hash = calculate_sha256(
            source
        )

        self.send_to_client(
            client,
            {
                "type":
                    "download_start",

                "name":
                    filename,

                "size":
                    size,

                "sha256":
                    file_hash
            }
        )

        sent = 0

        self.logger.info(
            "Sending file '%s' "
            "to client %s",
            filename,
            client.client_id
        )

        with open(
            source,
            "rb"
        ) as file:

            while True:

                chunk = file.read(
                    self.chunk_size
                )

                if not chunk:
                    break

                self.rate_limiter.consume(
                    client,
                    len(chunk)
                )

                client.sock.sendall(
                    chunk
                )

                sent += len(chunk)

                client.last_activity = (
                    time.time()
                )

        self.logger.info(
            "Download completed: %s "
            "(%d bytes)",
            filename,
            sent
        )

    # ========================================================
    # Client Command Handler
    # ========================================================

    def handle_command(
        self,
        client,
        command
    ):

        command = command.strip()

        if not command:

            return

        parts = command.split(
            maxsplit=1
        )

        action = parts[0].lower()

        argument = (
            parts[1]
            if len(parts) > 1
            else ""
        )

        # ----------------------------------------------------
        # HELP
        # ----------------------------------------------------

        if action == "help":

            self.send_to_client(
                client,
                {
                    "type":
                        "response",

                    "message":
                        """
Available commands:

help
info
stats
list
upload <file>
download <file>
ping
exit
"""
                }
            )

        # ----------------------------------------------------
        # INFO
        # ----------------------------------------------------

        elif action == "info":

            self.send_to_client(
                client,
                {
                    "type":
                        "response",

                    "data":
                    {
                        "client_id":
                            client.client_id,

                        "address":
                            str(client.address),

                        "username":
                            client.username,

                        "authenticated":
                            client.authenticated,

                        "connected_at":
                            datetime.fromtimestamp(
                                client.connected_at
                            ).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),

                        "last_activity":
                            datetime.fromtimestamp(
                                client.last_activity
                            ).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),

                        "server":
                            f"{self.host}:{self.port}",

                        "tls":
                            self.tls or self.args.udp
                    }
                }
            )

        # ----------------------------------------------------
        # STATS
        # ----------------------------------------------------

        elif action == "stats":

            uptime = int(
                time.time() -
                self.server_started
            )

            self.send_to_client(
                client,
                {
                    "type":
                        "response",

                    "data":
                    {
                        "version":
                            VERSION,

                        "clients":
                            self.client_count(),

                        "max_clients":
                            self.max_clients,

                        "uptime":
                            uptime,

                        "tls":
                            self.tls or self.args.udp,

                        "authentication":
                            self.auth_enabled
                    }
                }
            )

        # ----------------------------------------------------
        # LIST
        # ----------------------------------------------------

        elif action == "list":

            clients = []

            for item in self.get_clients():

                clients.append(
                    {
                        "id":
                            item.client_id,

                        "address":
                            str(item.address),

                        "username":
                            item.username,

                        "authenticated":
                            item.authenticated
                    }
                )

            self.send_to_client(
                client,
                {
                    "type":
                        "response",

                    "data":
                        clients
                }
            )

        # ----------------------------------------------------
        # PING
        # ----------------------------------------------------

        elif action == "ping":

            self.send_to_client(
                client,
                {
                    "type":
                        "pong",

                    "time":
                        now()
                }
            )

        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif action == "exit":

            self.send_to_client(
                client,
                {
                    "type":
                        "response",

                    "message":
                        "Goodbye"
                }
            )

            return "exit"

        # ----------------------------------------------------
        # UNKNOWN COMMAND
        # ----------------------------------------------------

        else:

            self.send_to_client(
                client,
                {
                    "type":
                        "error",

                    "message":
                        f"Unknown command: {command}"
                }
            )

        return None

    # ========================================================
    # Client Handler
    # ========================================================

    def handle_client(
        self,
        client
    ):

        client_id = client.client_id

        try:

            # ------------------------------------------------
            # Welcome
            # ------------------------------------------------

            self.send_to_client(
                client,
                {
                    "type":
                        "welcome",

                    "version":
                        VERSION,

                    "client_id":
                        client_id,

                    "server_time":
                        now(),

                    "tls":
                        self.tls or self.args.udp
                }
            )

            # ------------------------------------------------
            # Authentication
            # ------------------------------------------------

            if not self.authenticate_client(
                client
            ):

                self.logger.warning(
                    "Authentication failed "
                    "for client %s",
                    client_id
                )

                return

            # ------------------------------------------------
            # Main Loop
            # ------------------------------------------------

            while self.running:

                client.sock.settimeout(
                    max(
                        self.timeout,
                        self.args.heartbeat_interval * 2 + 1
                    )
                )

                frame = receive_frame(
                    client.sock,
                    self.max_size
                )

                client.last_activity = (
                    time.time()
                )

                frame_type = frame.get(
                    "type"
                )

                # --------------------------------------------
                # COMMAND
                # --------------------------------------------

                if frame_type == "command":

                    result = self.handle_command(
                        client,
                        str(
                            frame.get(
                                "command",
                                ""
                            )
                        )
                    )

                    if result == "exit":

                        break

                # --------------------------------------------
                # UPLOAD
                # --------------------------------------------

                elif frame_type == "upload_start":

                    if self.args.no_file_transfer:

                        self.send_to_client(
                            client,
                            {
                                "type":
                                    "error",

                                "message":
                                    "File transfer disabled"
                            }
                        )

                    else:

                        self.receive_file(
                            client,
                            frame
                        )

                # --------------------------------------------
                # DOWNLOAD
                # --------------------------------------------

                elif frame_type == "download":

                    if self.args.no_file_transfer:

                        self.send_to_client(
                            client,
                            {
                                "type":
                                    "error",

                                "message":
                                    "File transfer disabled"
                            }
                        )

                    else:

                        self.send_file(
                            client,
                            str(
                                frame.get(
                                    "name",
                                    ""
                                )
                            )
                        )

                # --------------------------------------------
                # PING
                # --------------------------------------------

                elif frame_type == "ping":

                    self.send_to_client(
                        client,
                        {
                            "type":
                                "pong",

                            "time":
                                now()
                        }
                    )

                # --------------------------------------------
                # PONG
                # --------------------------------------------

                elif frame_type == "pong":

                    client.last_activity = (
                        time.time()
                    )

                # --------------------------------------------
                # DISCONNECT
                # --------------------------------------------

                elif frame_type == "disconnect":

                    break

                # --------------------------------------------
                # UNKNOWN FRAME
                # --------------------------------------------

                else:

                    self.send_to_client(
                        client,
                        {
                            "type":
                                "error",

                            "message":
                                "Unknown frame type"
                        }
                    )

        except (
            ConnectionError,
            BrokenPipeError,
            ConnectionResetError,
            socket.timeout,
            TimeoutError
        ):

            self.logger.info(
                "Client %s connection closed",
                client_id
            )

        except Exception as e:

            self.logger.exception(
                "Client %s error: %s",
                client_id,
                e
            )

        finally:

            self.remove_client(
                client_id
            )

    # ========================================================
    # Heartbeat
    # ========================================================

    def heartbeat_loop(self):

        while self.running:

            time.sleep(
                self.args.heartbeat_interval
            )

            current = time.time()

            clients = self.get_clients()

            for client in clients:

                if client.transfer_active.is_set():
                    continue

                inactive = (
                    current -
                    client.last_activity
                )

                if inactive > (
                    self.args.heartbeat_timeout
                ):

                    self.logger.warning(
                        "Client %s timed out",
                        client.client_id
                    )

                    self.remove_client(
                        client.client_id
                    )

                    continue

                try:

                    self.send_to_client(
                        client,
                        {
                            "type":
                                "ping",

                            "time":
                                now()
                        }
                    )

                except Exception:

                    self.remove_client(
                        client.client_id
                    )

    # ========================================================
    # Server Console
    # ========================================================

    def server_console(self):

        print()

        print(
            color(
                "Server console started.",
                Colors.GREEN,
                self.args.color
            )
        )

        print(
            color(
                "Commands:",
                Colors.CYAN,
                self.args.color
            )
        )

        print(
            "  list"
        )

        print(
            "  info <id>"
        )

        print(
            "  send <id> <message>"
        )

        print(
            "  broadcast <message>"
        )

        print(
            "  kick <id>"
        )

        print(
            "  stats"
        )

        print(
            "  exit"
        )

        print()

        while self.running:

            try:

                command = input(
                    "server> "
                ).strip()

            except (
                EOFError,
                KeyboardInterrupt
            ):

                command = "exit"

            if not command:
                continue

            parts = command.split(
                maxsplit=2
            )

            action = parts[0].lower()

            # ------------------------------------------------
            # LIST
            # ------------------------------------------------

            if action == "list":

                self.list_clients()

            # ------------------------------------------------
            # INFO
            # ------------------------------------------------

            elif (
                action == "info"
                and len(parts) >= 2
            ):

                try:

                    client_id = int(
                        parts[1]
                    )

                    self.print_client_info(
                        client_id
                    )

                except ValueError:

                    print(
                        "Invalid client ID"
                    )

            # ------------------------------------------------
            # SEND
            # ------------------------------------------------

            elif (
                action == "send"
                and len(parts) >= 3
            ):

                try:

                    client_id = int(
                        parts[1]
                    )

                    message = parts[2]

                    client = self.get_client(
                        client_id
                    )

                    if not client:

                        print(
                            "Client not found"
                        )

                        continue

                    self.send_to_client(
                        client,
                        {
                            "type":
                                "server_message",

                            "message":
                                message
                        }
                    )

                    print(
                        f"Message sent to "
                        f"client {client_id}"
                    )

                except ValueError:

                    print(
                        "Invalid client ID"
                    )

                except Exception as e:

                    print(
                        f"Send failed: {e}"
                    )

            # ------------------------------------------------
            # BROADCAST
            # ------------------------------------------------

            elif (
                action == "broadcast"
                and len(parts) >= 2
            ):

                message = command.split(
                    maxsplit=1
                )[1]

                self.broadcast(
                    message
                )

                print(
                    "Broadcast sent."
                )

            # ------------------------------------------------
            # KICK
            # ------------------------------------------------

            elif (
                action == "kick"
                and len(parts) >= 2
            ):

                try:

                    client_id = int(
                        parts[1]
                    )

                    client = self.get_client(
                        client_id
                    )

                    if not client:

                        print(
                            "Client not found"
                        )

                        continue

                    try:

                        self.send_to_client(
                            client,
                            {
                                "type":
                                    "server_message",

                                "message":
                                    "You were "
                                    "disconnected "
                                    "by the server."
                            }
                        )

                    except Exception:
                        pass

                    self.remove_client(
                        client_id
                    )

                    print(
                        f"Client {client_id} kicked."
                    )

                except ValueError:

                    print(
                        "Invalid client ID"
                    )

            # ------------------------------------------------
            # STATS
            # ------------------------------------------------

            elif action == "stats":

                self.print_stats()

            # ------------------------------------------------
            # EXIT
            # ------------------------------------------------

            elif action == "exit":

                self.shutdown()

                break

            # ------------------------------------------------
            # HELP
            # ------------------------------------------------

            elif action == "help":

                print(
                    """
list
info <id>
send <id> <message>
broadcast <message>
kick <id>
stats
exit
"""
                )

            else:

                print(
                    "Unknown server command."
                )

    # ========================================================
    # Listen
    # ========================================================

    def listen(self):

        self.server_started = (
            time.time()
        )

        if self.args.udp:
            configuration = create_server_configuration(
                self.host,
                self.tls,
                self.cert,
                self.key,
                max(
                    self.timeout,
                    self.args.heartbeat_timeout * 2
                )
            )

            raw_socket = QuicServer(
                self.host,
                self.port,
                configuration,
                self.timeout,
                self.max_clients,
            )
            raw_socket.start()
        else:
            raw_socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            raw_socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )

            raw_socket.settimeout(
                1
            )

            raw_socket.bind(
                (
                    self.host,
                    self.port
                )
            )

            raw_socket.listen(
                self.backlog
            )

        self.server_socket = (
            raw_socket
        )

        print()

        print(
            color(
                "===================================",
                Colors.CYAN,
                self.args.color
            )
        )

        print(
            color(
                "          NetCat V3 SERVER",
                Colors.BOLD,
                self.args.color
            )
        )

        print(
            color(
                "===================================",
                Colors.CYAN,
                self.args.color
            )
        )

        print()

        print(
            f"Listening on "
            f"{self.host}:{self.port}"
        )

        print(
            f"Max clients: "
            f"{self.max_clients}"
        )

        print(
            f"Output directory: "
            f"{self.output_dir}"
        )

        print(
            f"TLS: "
            f"{'ON (QUIC TLS 1.3)' if self.args.udp else ('ON' if self.tls else 'OFF')}"
        )

        print(
            f"Authentication: "
            f"{'ON' if self.auth_enabled else 'OFF'}"
        )

        print()

        # ----------------------------------------------------
        # Heartbeat Thread
        # ----------------------------------------------------

        threading.Thread(
            target=self.heartbeat_loop,
            daemon=True
        ).start()

        # ----------------------------------------------------
        # Server Console
        # ----------------------------------------------------

        if self.args.interactive:

            threading.Thread(
                target=self.server_console,
                daemon=True
            ).start()

        # ----------------------------------------------------
        # Accept Loop
        # ----------------------------------------------------

        try:

            while self.running:

                try:

                    if self.args.udp:
                        connection = raw_socket.accept()
                        address = connection.getpeername()
                    else:
                        connection, address = (
                            raw_socket.accept()
                        )

                except socket.timeout:

                    continue

                except OSError:

                    break

                # --------------------------------------------
                # Max Clients
                # --------------------------------------------

                if (
                    self.client_count()
                    >=
                    self.max_clients
                ):

                    self.logger.warning(
                        "Rejected connection "
                        "from %s: "
                        "maximum clients reached",
                        address
                    )

                    try:
                        connection.close()

                    except OSError:
                        pass

                    continue

                # --------------------------------------------
                # TLS
                # --------------------------------------------

                if not self.args.udp:
                    try:

                        connection = (
                            self.wrap_tls(
                                connection
                            )
                        )

                    except Exception as e:

                        self.logger.error(
                            "TLS handshake failed "
                            "for %s: %s",
                            address,
                            e
                        )

                        try:
                            connection.close()

                        except OSError:
                            pass

                        continue

                # --------------------------------------------
                # Client ID
                # --------------------------------------------

                with self.clients_lock:

                    client_id = (
                        self.next_client_id
                    )

                    self.next_client_id += 1

                client = ClientInfo(
                    client_id=client_id,
                    sock=connection,
                    address=address
                )

                self.add_client(
                    client
                )

                self.logger.info(
                    "Client %s connected "
                    "from %s",
                    client_id,
                    address
                )

                print(
                    color(
                        f"[+] Client {client_id} "
                        f"connected from {address}",
                        Colors.GREEN,
                        self.args.color
                    )
                )

                # --------------------------------------------
                # Handler Thread
                # --------------------------------------------

                threading.Thread(
                    target=self.handle_client,
                    args=(client,),
                    daemon=True
                ).start()

        finally:

            self.shutdown()

    # ========================================================
    # Shutdown
    # ========================================================

    def shutdown(self):

        if not self.running:

            return

        self.running = False

        clients = self.get_clients()

        for client in clients:

            try:

                self.send_to_client(
                    client,
                    {
                        "type":
                            "server_message",

                        "message":
                            "Server shutting down."
                    }
                )

            except Exception:
                pass

            self.remove_client(
                client.client_id
            )

        if self.server_socket:

            try:

                self.server_socket.close()

            except OSError:
                pass

        self.logger.info(
            "Server stopped"
        )

        print(
            color(
                "\nServer stopped.",
                Colors.YELLOW,
                self.args.color
            )
        )
# ============================================================
# CLIENT
# ============================================================

class NetCatClient:

    def __init__(self, args):

        self.args = args

        self.host = args.host
        self.port = args.port

        self.timeout = args.timeout

        self.max_size = args.max_size
        self.chunk_size = args.chunk_size

        self.output_dir = Path(
            args.output
        ).resolve()

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        self.tls = args.tls

        self.ca_file = args.ca_file

        self.auth_enabled = args.auth

        self.username = args.username
        self.password = args.password

        self.sock = None

        self.client_id = None

        self.running = True

        self.connected = False

        self.reconnect = args.reconnect

        self.reconnect_delay = (
            args.reconnect_delay
        )

        self.logger = setup_logger(
            args.log_file,
            args.verbose,
            args.quiet
        )

        self.last_pong = time.time()

        self.receive_thread = None

        self.heartbeat_thread = None

        self.response_queue = queue.Queue()

        self.expected_response_types = set()

        self.response_lock = threading.Lock()

        self.download_active = threading.Event()

        self.file_transfer_active = threading.Event()

    # ========================================================
    # Socket Creation
    # ========================================================

    def create_socket(self):

        if self.args.udp:
            configuration = create_client_configuration(
                self.ca_file,
                max(
                    self.timeout,
                    self.args.heartbeat_timeout * 2
                )
            )
            connection = QuicClientConnection(
                self.host,
                self.port,
                configuration,
                self.timeout,
            )
            return connection.stream

        sock = socket.create_connection(
            (
                self.host,
                self.port
            ),
            timeout=self.timeout
        )

        if not self.tls:

            return sock

        context = ssl.create_default_context(
            cafile=self.ca_file
        )

        # ----------------------------------------------------
        # Lab mode
        # ----------------------------------------------------

        if not self.ca_file:

            context.check_hostname = False

            context.verify_mode = (
                ssl.CERT_NONE
            )

        return context.wrap_socket(
            sock,
            server_hostname=self.host
        )

    # ========================================================
    # Connect
    # ========================================================

    def connect(self):

        self.logger.info(
            "Connecting to %s:%s",
            self.host,
            self.port
        )

        self.sock = (
            self.create_socket()
        )

        self.sock.settimeout(
            self.timeout
        )

        # ----------------------------------------------------
        # Welcome
        # ----------------------------------------------------

        welcome = receive_frame(
            self.sock,
            self.max_size
        )

        if welcome.get("type") != "welcome":

            raise ConnectionError(
                "Invalid server welcome"
            )

        self.client_id = (
            welcome.get("client_id")
        )

        self.connected = True

        self.last_pong = time.time()

        print()

        print(
            color(
                "Connected successfully.",
                Colors.GREEN,
                self.args.color
            )
        )

        if self.args.udp:
            print(
                "Transport: QUIC over UDP "
                "(reliable, TLS 1.3)"
            )

        print(
            f"Client ID: "
            f"{self.client_id}"
        )

        print(
            f"Server: "
            f"{self.host}:{self.port}"
        )

        print(
            f"TLS: "
            f"{welcome.get('tls', False)}"
        )

        if self.args.udp and not self.ca_file:
            print(
                "Warning: server identity is not verified; "
                "use --ca-file outside a lab."
            )

        print()

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        if self.auth_enabled:

            auth_request = receive_frame(
                self.sock,
                self.max_size
            )

            if (
                auth_request.get(
                    "type"
                )
                !=
                "auth_required"
            ):

                raise PermissionError(
                    "Invalid authentication request"
                )

            username = (
                self.username
            )

            password = (
                self.password
            )

            if not username:

                username = input(
                    "Username: "
                )

            if not password:

                password = getpass.getpass(
                    "Password: "
                )

            send_frame(
                self.sock,
                {
                    "type":
                        "auth",

                    "username":
                        username,

                    "password":
                        password
                },
                self.max_size
            )

            result = receive_frame(
                self.sock,
                self.max_size
            )

            if not result.get("ok"):

                raise PermissionError(
                    "Authentication failed"
                )

            print(
                color(
                    "Authentication successful.",
                    Colors.GREEN,
                    self.args.color
                )
            )

    # ========================================================
    # Close Connection
    # ========================================================

    def close_socket(self):

        self.connected = False

        if self.sock:

            try:

                self.sock.shutdown(
                    socket.SHUT_RDWR
                )

            except OSError:
                pass

            try:

                self.sock.close()

            except OSError:
                pass

        self.sock = None

    # ========================================================
    # Progress Bar
    # ========================================================

    def show_progress(
        self,
        label,
        current,
        total
    ):

        if total <= 0:

            percentage = 100

        else:

            percentage = (
                current /
                total *
                100
            )

        width = 35

        filled = int(
            width *
            percentage /
            100
        )

        bar = (
            "#" * filled +
            "-" * (
                width -
                filled
            )
        )

        current_mb = (
            current /
            1024 /
            1024
        )

        total_mb = (
            total /
            1024 /
            1024
        )

        print(
            f"\r"
            f"{label}: "
            f"[{bar}] "
            f"{percentage:6.2f}% "
            f"({current_mb:.2f}/"
            f"{total_mb:.2f} MB)",
            end="",
            flush=True
        )

    # ========================================================
    # Upload
    # ========================================================

    def upload(
        self,
        filename
    ):

        if not self.connected:

            print(
                color(
                    "Not connected.",
                    Colors.RED,
                    self.args.color
                )
            )

            return

        path = Path(
            filename
        ).resolve()

        if not path.exists():

            print(
                color(
                    "File not found.",
                    Colors.RED,
                    self.args.color
                )
            )

            return

        if not path.is_file():

            print(
                color(
                    "Not a regular file.",
                    Colors.RED,
                    self.args.color
                )
            )

            return

        size = path.stat().st_size

        if size > self.max_size:

            print(
                color(
                    "File exceeds "
                    "maximum size.",
                    Colors.RED,
                    self.args.color
                )
            )

            return

        filename = safe_filename(
            path.name
        )

        print(
            "Calculating SHA-256..."
        )

        file_hash = calculate_sha256(
            path
        )

        self.file_transfer_active.set()
        self._expect_response(
            {"upload_result", "error"}
        )

        try:

            # ------------------------------------------------
            # Send Metadata
            # ------------------------------------------------

            send_frame(
                self.sock,
                {
                    "type":
                        "upload_start",

                    "name":
                        filename,

                    "size":
                        size,

                    "sha256":
                        file_hash
                },
                self.max_size
            )

            sent = 0

            # ------------------------------------------------
            # Send Chunks
            # ------------------------------------------------

            with open(
                path,
                "rb"
            ) as file:

                while sent < size:

                    chunk = file.read(
                        self.chunk_size
                    )

                    if not chunk:

                        break

                    self.sock.sendall(
                        chunk
                    )

                    sent += len(chunk)

                    self.show_progress(
                        "Upload",
                        sent,
                        size
                    )

            print()

            # ------------------------------------------------
            # Result
            # ------------------------------------------------

            result = self._wait_for_response(
                {"upload_result", "error"}
            )

            if (
                result.get("type")
                ==
                "upload_result"
            ):

                verified = result.get(
                    "verified",
                    False
                )

                if verified:

                    print(
                        color(
                            "Upload successful "
                            "and SHA-256 verified.",
                            Colors.GREEN,
                            self.args.color
                        )
                    )

                else:

                    print(
                        color(
                            "Upload completed "
                            "but SHA-256 "
                            "verification failed.",
                            Colors.RED,
                            self.args.color
                        )
                    )

            else:

                self.display_response(
                    result
                )

        except Exception as e:

            print()

            print(
                color(
                    f"Upload failed: {e}",
                    Colors.RED,
                    self.args.color
                )
            )

            self.connected = False

        finally:
            self.file_transfer_active.clear()
            self._expect_response(set())

    # ========================================================
    # Download
    # ========================================================

    def download(
        self,
        filename
    ):

        if not self.connected:

            print(
                color(
                    "Not connected.",
                    Colors.RED,
                    self.args.color
                )
            )

            return

        try:

            filename = safe_filename(
                filename
            )

            self.file_transfer_active.set()
            self.download_active.set()
            self._expect_response(
                {"download_start", "error"}
            )

            send_frame(
                self.sock,
                {
                    "type":
                        "download",

                    "name":
                        filename
                },
                self.max_size
            )

            # ------------------------------------------------
            # Metadata
            # ------------------------------------------------

            metadata = self._wait_for_response(
                {"download_start", "error"}
            )

            if (
                metadata.get("type")
                ==
                "error"
            ):

                self.display_response(
                    metadata
                )

                return

            if (
                metadata.get("type")
                !=
                "download_start"
            ):

                raise ValueError(
                    "Invalid download response"
                )

            size = int(
                metadata.get(
                    "size",
                    -1
                )
            )

            expected_hash = str(
                metadata.get(
                    "sha256",
                    ""
                )
            )

            if size < 0:

                raise ValueError(
                    "Invalid file size"
                )

            if size > self.max_size:

                raise ValueError(
                    "File exceeds maximum size"
                )

            destination = (
                self.output_dir /
                filename
            )

            received = 0

            sha256 = hashlib.sha256()

            # ------------------------------------------------
            # Receive Chunks
            # ------------------------------------------------

            with open(
                destination,
                "wb"
            ) as file:

                while received < size:

                    remaining = (
                        size -
                        received
                    )

                    chunk = self.sock.recv(
                        min(
                            self.chunk_size,
                            remaining
                        )
                    )

                    if not chunk:

                        raise ConnectionError(
                            "Connection closed "
                            "during download"
                        )

                    file.write(
                        chunk
                    )

                    sha256.update(
                        chunk
                    )

                    received += len(
                        chunk
                    )

                    self.show_progress(
                        "Download",
                        received,
                        size
                    )

            print()

            # ------------------------------------------------
            # Verify SHA-256
            # ------------------------------------------------

            actual_hash = (
                sha256.hexdigest()
            )

            print(
                f"SHA-256: "
                f"{actual_hash}"
            )

            if actual_hash == expected_hash:

                print(
                    color(
                        "SHA-256 verified successfully.",
                        Colors.GREEN,
                        self.args.color
                    )
                )

            else:

                print(
                    color(
                        "WARNING: SHA-256 "
                        "verification failed!",
                        Colors.RED,
                        self.args.color
                    )
                )

            print(
                f"Saved to: "
                f"{destination}"
            )

        except Exception as e:

            print()

            print(
                color(
                    f"Download failed: {e}",
                    Colors.RED,
                    self.args.color
                )
            )

            self.connected = False

        finally:
            self.download_active.clear()
            self.file_transfer_active.clear()
            self._expect_response(set())

    # ========================================================
    # Display Response
    # ========================================================

    def display_response(
        self,
        response
    ):

        response_type = (
            response.get("type")
        )

        # ----------------------------------------------------
        # Server Message
        # ----------------------------------------------------

        if response_type == (
            "server_message"
        ):

            print()

            print(
                color(
                    "[SERVER] "
                    +
                    str(
                        response.get(
                            "message",
                            ""
                        )
                    ),
                    Colors.CYAN,
                    self.args.color
                )
            )

        # ----------------------------------------------------
        # Normal Response
        # ----------------------------------------------------

        elif response_type == (
            "response"
        ):

            data = response.get(
                "data"
            )

            if data is not None:

                print(
                    json.dumps(
                        data,
                        indent=4
                    )
                )

            else:

                print(
                    response.get(
                        "message",
                        ""
                    )
                )

        # ----------------------------------------------------
        # Error
        # ----------------------------------------------------

        elif response_type == (
            "error"
        ):

            print(
                color(
                    "Error: "
                    +
                    str(
                        response.get(
                            "message",
                            ""
                        )
                    ),
                    Colors.RED,
                    self.args.color
                )
            )

        # ----------------------------------------------------
        # Pong
        # ----------------------------------------------------

        elif response_type == "pong":

            self.last_pong = (
                time.time()
            )

            print(
                color(
                    f"PONG "
                    f"[{response.get('time', '')}]",
                    Colors.GREEN,
                    self.args.color
                )
            )

        # ----------------------------------------------------
        # Ping
        # ----------------------------------------------------

        elif response_type == "ping":

            try:

                send_frame(
                    self.sock,
                    {
                        "type":
                            "pong",

                        "time":
                            now()
                    },
                    self.max_size
                )

            except Exception:
                pass

        # ----------------------------------------------------
        # Unknown
        # ----------------------------------------------------

        else:

            print(
                json.dumps(
                    response,
                    indent=4
                )
            )

    # ========================================================
    # Receive Loop
    # ========================================================

    def _expect_response(self, response_types):
        with self.response_lock:
            self.expected_response_types = set(response_types)

    def _wait_for_response(self, response_types):
        while self.running and self.connected:
            try:
                frame = self.response_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if frame.get("type") in response_types:
                return frame

        raise ConnectionError(
            "Connection closed while waiting for a server response"
        )

    def receive_loop(self):

        while self.running:

            if not self.connected:

                time.sleep(1)

                continue

            try:

                frame = receive_frame(
                    self.sock,
                    self.max_size
                )

                frame_type = frame.get(
                    "type"
                )

                # ------------------------------------------------
                # Ping
                # ------------------------------------------------

                if frame_type == "ping":

                    try:

                        send_frame(
                            self.sock,
                            {
                                "type":
                                    "pong",

                                "time":
                                    now()
                            },
                            self.max_size
                        )

                    except Exception:
                        pass

                # ------------------------------------------------
                # Pong
                # ------------------------------------------------

                elif frame_type == "pong":

                    self.last_pong = (
                        time.time()
                    )

                    with self.response_lock:
                        expects_pong = (
                            "pong" in self.expected_response_types
                        )

                    if expects_pong:
                        self.response_queue.put(frame)

                # ------------------------------------------------
                # Server Message
                # ------------------------------------------------

                elif frame_type == (
                    "server_message"
                ):

                    print()

                    print(
                        color(
                            "[SERVER] "
                            +
                            str(
                                frame.get(
                                    "message",
                                    ""
                                )
                            ),
                            Colors.CYAN,
                            self.args.color
                        )
                    )

                    print(
                        "netcat> ",
                        end="",
                        flush=True
                    )

                # ------------------------------------------------
                # Unexpected Frame
                # ------------------------------------------------

                else:

                    if frame_type in {
                        "response",
                        "error",
                        "upload_result",
                        "download_start",
                    }:
                        self.response_queue.put(frame)

                        if (
                            frame_type == "download_start"
                            and self.download_active.is_set()
                        ):
                            while (
                                self.download_active.is_set()
                                and self.running
                            ):
                                time.sleep(0.01)

                    else:

                        self.display_response(
                            frame
                        )

            except (
                ConnectionError,
                ConnectionResetError,
                BrokenPipeError,
                OSError,
                socket.timeout
            ):

                self.connected = False

                self.close_socket()

                if self.running:

                    self.logger.warning(
                        "Connection lost"
                    )

                break

            except Exception as e:

                self.logger.error(
                    "Receive loop error: %s",
                    e
                )

                self.connected = False

                self.close_socket()

                break

    # ========================================================
    # Heartbeat
    # ========================================================

    def heartbeat_loop(self):

        while self.running:

            time.sleep(
                self.args.heartbeat_interval
            )

            if not self.connected:

                continue

            if self.file_transfer_active.is_set():
                continue

            try:

                send_frame(
                    self.sock,
                    {
                        "type":
                            "ping",

                        "time":
                            now()
                    },
                    self.max_size
                )

                # --------------------------------------------
                # Check last response
                # --------------------------------------------

                if (
                    time.time() -
                    self.last_pong
                    >
                    self.args.heartbeat_timeout
                ):

                    self.logger.warning(
                        "Heartbeat timeout"
                    )

                    self.connected = False

                    self.close_socket()

            except Exception:

                self.connected = False

                self.close_socket()

    # ========================================================
    # Automatic Reconnection
    # ========================================================

    def reconnect_loop(self):

        if not self.reconnect:

            return

        while self.running:

            if self.connected:

                time.sleep(1)

                continue

            print()

            print(
                color(
                    "Connection lost. "
                    "Trying to reconnect...",
                    Colors.YELLOW,
                    self.args.color
                )
            )

            while (
                self.running
                and
                not self.connected
            ):

                try:

                    self.connect()

                    print(
                        color(
                            "Reconnected successfully.",
                            Colors.GREEN,
                            self.args.color
                        )
                    )

                    # ----------------------------------------
                    # Restart receive thread
                    # ----------------------------------------

                    if (
                        self.receive_thread
                        is None
                        or
                        not self.receive_thread.is_alive()
                    ):

                        self.receive_thread = (
                            threading.Thread(
                                target=self.receive_loop,
                                daemon=True
                            )
                        )

                        self.receive_thread.start()

                    break

                except Exception as e:

                    self.logger.warning(
                        "Reconnect failed: %s",
                        e
                    )

                    self.close_socket()

                    time.sleep(
                        self.reconnect_delay
                    )

    # ========================================================
    # Send Command
    # ========================================================

    def send_command(
        self,
        command
    ):

        if not self.connected:

            print(
                color(
                    "Not connected.",
                    Colors.RED,
                    self.args.color
                )
            )

            return

        try:

            expected_responses = {"response", "error"}
            if command.strip().lower() == "ping":
                expected_responses.add("pong")

            self._expect_response(expected_responses)

            send_frame(
                self.sock,
                {
                    "type":
                        "command",

                    "command":
                        command
                },
                self.max_size
            )

            response = self._wait_for_response(
                expected_responses
            )

            self.display_response(
                response
            )

            if command.lower() == "exit":

                self.running = False

        except Exception as e:

            print(
                color(
                    f"Command failed: {e}",
                    Colors.RED,
                    self.args.color
                )
            )

            self.connected = False

        finally:
            self._expect_response(set())

    # ========================================================
    # Client Help
    # ========================================================

    def print_help(self):

        print()

        print(
            color(
                "========== CLIENT COMMANDS ==========",
                Colors.CYAN,
                self.args.color
            )
        )

        print(
            "help"
        )

        print(
            "info"
        )

        print(
            "stats"
        )

        print(
            "list"
        )

        print(
            "ping"
        )

        print(
            "upload <file>"
        )

        print(
            "download <file>"
        )

        print(
            "exit"
        )

        print()

    # ========================================================
    # Interactive Mode
    # ========================================================

    def interactive(self):

        self.print_help()

        while self.running:

            try:

                command = input(
                    "netcat> "
                ).strip()

            except (
                EOFError,
                KeyboardInterrupt
            ):

                print()

                command = "exit"

            if not command:

                continue

            parts = command.split(
                maxsplit=1
            )

            action = (
                parts[0].lower()
            )

            argument = (
                parts[1]
                if len(parts) > 1
                else ""
            )

            # ------------------------------------------------
            # HELP
            # ------------------------------------------------

            if action == "help":

                self.print_help()

            # ------------------------------------------------
            # UPLOAD
            # ------------------------------------------------

            elif action == "upload":

                if not argument:

                    print(
                        "Usage: "
                        "upload <file>"
                    )

                    continue

                if self.args.no_file_transfer:

                    print(
                        color(
                            "File transfer "
                            "is disabled.",
                            Colors.RED,
                            self.args.color
                        )
                    )

                    continue

                self.upload(
                    argument
                )

            # ------------------------------------------------
            # DOWNLOAD
            # ------------------------------------------------

            elif action == "download":

                if not argument:

                    print(
                        "Usage: "
                        "download <file>"
                    )

                    continue

                if self.args.no_file_transfer:

                    print(
                        color(
                            "File transfer "
                            "is disabled.",
                            Colors.RED,
                            self.args.color
                        )
                    )

                    continue

                self.download(
                    argument
                )

            # ------------------------------------------------
            # EXIT
            # ------------------------------------------------

            elif action == "exit":

                try:

                    if self.connected:

                        send_frame(
                            self.sock,
                            {
                                "type":
                                    "command",

                                "command":
                                    "exit"
                            },
                            self.max_size
                        )

                except Exception:
                    pass

                self.running = False

                break

            # ------------------------------------------------
            # Everything Else
            # ------------------------------------------------

            else:

                self.send_command(
                    command
                )

    # ========================================================
    # Start Client
    # ========================================================

    def run(self):

        # ----------------------------------------------------
        # Initial Connection
        # ----------------------------------------------------

        while self.running:

            try:

                self.connect()

                break

            except Exception as e:

                self.logger.error(
                    "Connection failed: %s",
                    e
                )

                self.close_socket()

                if not self.reconnect:

                    raise

                print(
                    color(
                        "Initial connection failed. "
                        "Retrying...",
                        Colors.YELLOW,
                        self.args.color
                    )
                )

                time.sleep(
                    self.reconnect_delay
                )

        if not self.running:

            return

        self.sock.settimeout(None)

        # ----------------------------------------------------
        # Receive Thread
        # ----------------------------------------------------

        self.receive_thread = (
            threading.Thread(
                target=self.receive_loop,
                daemon=True
            )
        )

        self.receive_thread.start()

        # ----------------------------------------------------
        # Heartbeat Thread
        # ----------------------------------------------------

        self.heartbeat_thread = (
            threading.Thread(
                target=self.heartbeat_loop,
                daemon=True
            )
        )

        self.heartbeat_thread.start()

        # ----------------------------------------------------
        # Reconnect Thread
        # ----------------------------------------------------

        if self.reconnect:

            threading.Thread(
                target=self.reconnect_loop,
                daemon=True
            ).start()

        # ----------------------------------------------------
        # Interactive Console
        # ----------------------------------------------------

        self.interactive()

        self.close_socket()
# ============================================================
# SELF TESTS
# ============================================================

def run_self_tests():

    print()
    print("=" * 55)
    print("              NetCat V3 Self-Test")
    print("=" * 55)
    print()

    passed = 0
    failed = 0

    # --------------------------------------------------------
    # Test 1 - Protocol Header
    # --------------------------------------------------------

    try:

        if HEADER_STRUCT.size == 4:

            print("[PASS] Protocol header")

            passed += 1

        else:

            print("[FAIL] Protocol header")

            failed += 1

    except Exception as e:

        print(
            f"[FAIL] Protocol header: {e}"
        )

        failed += 1

    # --------------------------------------------------------
    # Test 2 - SHA256
    # --------------------------------------------------------

    try:

        import tempfile

        with tempfile.NamedTemporaryFile(
            delete=False
        ) as temp:

            temp.write(b"hello")

            temp_path = temp.name

        digest = calculate_sha256(
            temp_path
        )

        os.unlink(
            temp_path
        )

        expected = (
            "2cf24dba5fb0a30e26e83b2ac5b9e29"
            "e1b161e5c1fa7425e73043362938b9824"
        )

        if digest == expected:

            print("[PASS] SHA-256")

            passed += 1

        else:

            print("[FAIL] SHA-256")

            failed += 1

    except Exception as e:

        print(
            f"[FAIL] SHA-256: {e}"
        )

        failed += 1

    # --------------------------------------------------------
    # Test 3 - Filename Sanitization
    # --------------------------------------------------------

    try:

        result = safe_filename(
            "../../secret.txt"
        )

        if result == "secret.txt":

            print(
                "[PASS] Filename sanitization"
            )

            passed += 1

        else:

            print(
                "[FAIL] Filename sanitization"
            )

            failed += 1

    except Exception as e:

        print(
            f"[FAIL] Filename sanitization: {e}"
        )

        failed += 1

    # --------------------------------------------------------
    # Test 4 - JSON Protocol
    # --------------------------------------------------------

    try:

        left, right = socket.socketpair()

        payload = {
            "type": "test",
            "message": "hello",
            "number": 123
        }

        send_frame(
            left,
            payload
        )

        received = receive_frame(
            right
        )

        left.close()
        right.close()

        if received == payload:

            print(
                "[PASS] JSON protocol"
            )

            passed += 1

        else:

            print(
                "[FAIL] JSON protocol"
            )

            failed += 1

    except Exception as e:

        print(
            f"[FAIL] JSON protocol: {e}"
        )

        failed += 1

    # --------------------------------------------------------
    # Test 5 - Rate Limiter
    # --------------------------------------------------------

    try:

        limiter = RateLimiter(
            0
        )

        if limiter.limit == 0:

            print(
                "[PASS] Rate limiter"
            )

            passed += 1

        else:

            print(
                "[FAIL] Rate limiter"
            )

            failed += 1

    except Exception as e:

        print(
            f"[FAIL] Rate limiter: {e}"
        )

        failed += 1

    # --------------------------------------------------------
    # Test 6 - QUIC TLS Configuration
    # --------------------------------------------------------

    try:
        server_configuration = create_server_configuration(
            "localhost",
            False,
            "",
            "",
            60,
        )
        client_configuration = create_client_configuration(
            None,
            60,
        )

        if (
            server_configuration.certificate is not None
            and server_configuration.private_key is not None
            and server_configuration.alpn_protocols == ["netcat-v3"]
            and client_configuration.verify_mode == ssl.CERT_NONE
        ):
            print("[PASS] QUIC TLS configuration")
            passed += 1
        else:
            print("[FAIL] QUIC TLS configuration")
            failed += 1

    except Exception as e:
        print(
            f"[FAIL] QUIC TLS configuration: {e}"
        )
        failed += 1

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    print()
    print("=" * 55)

    print(
        f"Passed: {passed}"
    )

    print(
        f"Failed: {failed}"
    )

    print("=" * 55)
    print()

    return failed == 0


# ============================================================
# Argument Parser
# ============================================================

def create_parser():

    parser = argparse.ArgumentParser(
        prog="netcat.py",
        description=(
            "NetCat V3 - "
            "Educational TCP/QUIC Client/Server Tool"
        ),
        formatter_class=(
            argparse.ArgumentDefaultsHelpFormatter
        )
    )

    # ========================================================
    # General
    # ========================================================

    parser.add_argument(
        "--version",
        action="version",
        version=f"NetCat V3 {VERSION}"
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in self tests"
    )

    # ========================================================
    # Mode
    # ========================================================

    parser.add_argument(
        "-l",
        "--listen",
        action="store_true",
        help="Run as a server (TCP by default; QUIC over UDP with --udp)"
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help=(
            "Enable interactive server console"
        )
    )

    parser.add_argument(
        "--udp",
        action="store_true",
        help="Use reliable, encrypted QUIC streams over UDP instead of TCP"
    )

    # ========================================================
    # Network
    # ========================================================

    parser.add_argument(
        "-t",
        "--host",
        default=DEFAULT_HOST,
        help="Server/listen host"
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="TCP or QUIC/UDP server/listen port"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Socket timeout in seconds"
    )

    parser.add_argument(
        "--backlog",
        type=int,
        default=DEFAULT_BACKLOG,
        help="TCP listen backlog"
    )

    # ========================================================
    # Protocol
    # ========================================================

    parser.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX_SIZE,
        help="Maximum frame/file size"
    )

    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="File transfer chunk size"
    )

    # ========================================================
    # Clients
    # ========================================================

    parser.add_argument(
        "--max-clients",
        type=int,
        default=DEFAULT_MAX_CLIENTS,
        help="Maximum simultaneous clients"
    )

    # ========================================================
    # Heartbeat
    # ========================================================

    parser.add_argument(
        "--heartbeat-interval",
        type=int,
        default=DEFAULT_HEARTBEAT_INTERVAL,
        help="Heartbeat interval in seconds"
    )

    parser.add_argument(
        "--heartbeat-timeout",
        type=int,
        default=DEFAULT_HEARTBEAT_TIMEOUT,
        help="Heartbeat timeout in seconds"
    )

    # ========================================================
    # Rate Limiting
    # ========================================================

    parser.add_argument(
        "--rate-limit",
        type=int,
        default=0,
        help=(
            "Per-client transfer limit "
            "in bytes/sec. 0 = unlimited"
        )
    )

    # ========================================================
    # Files
    # ========================================================

    parser.add_argument(
        "--output",
        default="uploads",
        help="File transfer directory"
    )

    parser.add_argument(
        "--no-file-transfer",
        action="store_true",
        help="Disable upload/download"
    )

    # ========================================================
    # Security
    # ========================================================

    parser.add_argument(
        "--tls",
        action="store_true",
        help="Enable TCP TLS (QUIC mode always uses TLS 1.3)"
    )

    parser.add_argument(
        "--cert",
        default="server.crt",
        help="TLS certificate"
    )

    parser.add_argument(
        "--key",
        default="server.key",
        help="TLS private key"
    )

    parser.add_argument(
        "--ca-file",
        default=None,
        help=(
            "CA certificate used to verify the server"
        )
    )

    # ========================================================
    # Authentication
    # ========================================================

    parser.add_argument(
        "--auth",
        action="store_true",
        help="Enable username/password authentication"
    )

    parser.add_argument(
        "--username",
        default="admin",
        help="Authentication username"
    )

    parser.add_argument(
        "--password",
        default=None,
        help="Authentication password"
    )

    # ========================================================
    # Client Reconnect
    # ========================================================

    parser.add_argument(
        "--reconnect",
        action="store_true",
        help="Automatically reconnect client"
    )

    parser.add_argument(
        "--reconnect-delay",
        type=int,
        default=5,
        help="Reconnect delay in seconds"
    )

    # ========================================================
    # UI
    # ========================================================

    parser.add_argument(
        "--banner",
        action="store_true",
        help="Show startup banner"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce console output"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--color",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable terminal colors"
    )

    # ========================================================
    # Logging
    # ========================================================

    parser.add_argument(
        "--log-file",
        default="netcat.log",
        help="Log file path"
    )

    return parser


# ============================================================
# Argument Validation
# ============================================================

def validate_args(args):

    if args.port < 1 or args.port > 65535:

        raise ValueError(
            "Port must be between 1 and 65535"
        )

    if args.timeout <= 0:

        raise ValueError(
            "Timeout must be greater than zero"
        )

    if args.backlog <= 0:

        raise ValueError(
            "Backlog must be greater than zero"
        )

    if args.max_size <= 0:

        raise ValueError(
            "Max size must be greater than zero"
        )

    if args.chunk_size <= 0:

        raise ValueError(
            "Chunk size must be greater than zero"
        )

    if args.max_clients <= 0:

        raise ValueError(
            "Max clients must be greater than zero"
        )

    if args.heartbeat_interval <= 0:

        raise ValueError(
            "Heartbeat interval must be greater than zero"
        )

    if args.heartbeat_timeout <= 0:

        raise ValueError(
            "Heartbeat timeout must be greater than zero"
        )

    if args.rate_limit < 0:

        raise ValueError(
            "Rate limit cannot be negative"
        )

    if args.reconnect_delay < 1:

        raise ValueError(
            "Reconnect delay must be >= 1"
        )

    if (
        args.verbose
        and
        args.quiet
    ):

        raise ValueError(
            "--verbose and --quiet "
            "cannot be used together"
        )

    # --------------------------------------------------------
    # Interactive mode
    # --------------------------------------------------------

    if (
        args.interactive
        and
        not args.listen
    ):

        print(
            "Warning: "
            "--interactive is mainly useful "
            "in server mode."
        )

    # --------------------------------------------------------
    # TLS validation
    # --------------------------------------------------------

    if args.listen and args.tls:

        if not os.path.exists(
            args.cert
        ):

            raise FileNotFoundError(
                f"TLS certificate not found: "
                f"{args.cert}"
            )

        if not os.path.exists(
            args.key
        ):

            raise FileNotFoundError(
                f"TLS private key not found: "
                f"{args.key}"
            )

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if args.listen and args.auth:

        if not args.password:

            print(
                "Authentication is enabled."
            )

            args.password = (
                getpass.getpass(
                    "Server password: "
                )
            )

            if not args.password:

                raise ValueError(
                    "Password cannot be empty"
                )

    # --------------------------------------------------------
    # Client auth
    # --------------------------------------------------------

    if (
        not args.listen
        and
        args.auth
        and
        not args.username
    ):

        raise ValueError(
            "Username is required"
        )


# ============================================================
# Banner
# ============================================================

def print_banner(
    color_enabled=True
):

    print()

    print(
        color(
            "╔══════════════════════════════════════════╗",
            Colors.CYAN,
            color_enabled
        )
    )

    print(
        color(
            "║              NetCat V3                  ║",
            Colors.BOLD,
            color_enabled
        )
    )

    print(
        color(
            "║     TCP / QUIC Client / Server Tool      ║",
            Colors.CYAN,
            color_enabled
        )
    )

    print(
        color(
            f"║              Version {VERSION:<15}║",
            Colors.CYAN,
            color_enabled
        )
    )

    print(
        color(
            "╚══════════════════════════════════════════╝",
            Colors.CYAN,
            color_enabled
        )
    )

    print()


# ============================================================
# Quick Start
# ============================================================

def print_quick_start():

    print(
        """
Quick Start
-----------

Server:

    python netcat.py -l -t 0.0.0.0 -p 5555 --interactive

Client:

    python netcat.py -t 127.0.0.1 -p 5555

Server console:

    list
    info <id>
    send <id> <message>
    broadcast <message>
    kick <id>
    stats
    exit

Client commands:

    help
    info
    stats
    list
    ping
    upload <file>
    download <file>
    exit

Run:

    python netcat.py --help

Self test:

    python netcat.py --self-test

QUIC server and client over UDP:

    python netcat.py -l --udp -t 0.0.0.0 -p 5555
    python netcat.py --udp -t 127.0.0.1 -p 5555
"""
    )


# ============================================================
# Main
# ============================================================

def main():

    parser = create_parser()

    # --------------------------------------------------------
    # No Arguments
    # --------------------------------------------------------

    if len(sys.argv) == 1:

        print_banner()

        print_quick_start()

        return 0

    # --------------------------------------------------------
    # Parse
    # --------------------------------------------------------

    args = parser.parse_args()

    # --------------------------------------------------------
    # Self Test
    # --------------------------------------------------------

    if args.self_test:

        success = run_self_tests()

        return 0 if success else 1

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    try:

        validate_args(args)

    except Exception as e:

        parser.error(
            str(e)
        )

    # --------------------------------------------------------
    # Banner
    # --------------------------------------------------------

    if args.banner:

        print_banner(
            args.color
        )

    # --------------------------------------------------------
    # Server
    # --------------------------------------------------------

    if args.listen:

        server = NetCatServer(
            args
        )

        try:

            server.listen()

        except KeyboardInterrupt:

            print()

            print(
                "Stopping server..."
            )

            server.shutdown()

        except Exception as e:

            print(
                color(
                    f"Server error: {e}",
                    Colors.RED,
                    args.color
                )
            )

            server.shutdown()

            return 1

        return 0

    # --------------------------------------------------------
    # Client
    # --------------------------------------------------------

    client = NetCatClient(
        args
    )

    try:

        client.run()

    except KeyboardInterrupt:

        print()

        print(
            "Stopping client..."
        )

    except Exception as e:

        print(
            color(
                f"Client error: {e}",
                Colors.RED,
                args.color
            )
        )

        return 1

    finally:

        client.running = False

        client.close_socket()

    return 0


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )
