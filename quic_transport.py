"""Synchronous socket adapters for reliable QUIC streams over UDP."""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import queue
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ALPN_PROTOCOL = "netcat-v3"
QUIC_CLIENT_GREETING = b"NetCat V3 QUIC"


def create_server_configuration(
    host: str,
    use_certificate_files: bool,
    cert_file: str,
    key_file: str,
    idle_timeout: float,
) -> QuicConfiguration:
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=[ALPN_PROTOCOL],
        idle_timeout=idle_timeout,
    )

    if use_certificate_files:
        configuration.load_cert_chain(cert_file, key_file)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, host),
            ]
        )
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
        )

        subject_alt_names = [
            x509.DNSName("localhost"),
            x509.DNSName(socket.gethostname()),
        ]
        try:
            subject_alt_names.append(
                x509.IPAddress(ipaddress.ip_address(host))
            )
        except ValueError:
            if host not in {"0.0.0.0", "::"}:
                subject_alt_names.append(x509.DNSName(host))

        certificate = (
            builder
            .add_extension(
                x509.SubjectAlternativeName(subject_alt_names),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        configuration.certificate = certificate
        configuration.private_key = private_key

    return configuration


def create_client_configuration(
    ca_file: Optional[str],
    idle_timeout: float,
) -> QuicConfiguration:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=[ALPN_PROTOCOL],
        idle_timeout=idle_timeout,
    )

    if ca_file:
        configuration.load_verify_locations(cafile=ca_file)
    else:
        configuration.verify_mode = ssl.CERT_NONE

    return configuration


class QuicStreamSocket:
    """Expose a QUIC stream through the socket methods used by NetCat."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: Optional[float],
        address,
        owner: Optional["QuicClientConnection"] = None,
        protocol: Optional[QuicConnectionProtocol] = None,
    ) -> None:
        self._loop = loop
        self._reader = reader
        self._writer = writer
        self._timeout = timeout
        self._address = address
        self._owner = owner
        self._protocol = protocol
        self._closed = False
        self._send_lock = threading.Lock()

    def settimeout(self, timeout: Optional[float]) -> None:
        self._timeout = timeout

    def getpeername(self):
        return self._address

    def sendall(self, data: bytes) -> None:
        if self._closed:
            raise OSError("QUIC stream is closed")

        async def write_data() -> None:
            self._writer.write(data)
            await self._writer.drain()

        with self._send_lock:
            self._submit(write_data())

    def recv(self, size: int) -> bytes:
        if size <= 0:
            return b""

        async def read_data() -> bytes:
            return await asyncio.wait_for(
                self._reader.read(size),
                timeout=self._timeout,
            )

        try:
            return self._submit(read_data())
        except (
            asyncio.TimeoutError,
            concurrent.futures.TimeoutError,
        ) as error:
            raise socket.timeout("QUIC stream read timed out") from error

    def shutdown(self, how: int) -> None:
        if self._closed or how == socket.SHUT_RD:
            return

        async def finish_stream() -> None:
            self._writer.write_eof()
            await self._writer.drain()

        try:
            self._submit(finish_stream())
        except (OSError, RuntimeError):
            if how != socket.SHUT_RDWR:
                raise

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        if self._owner is not None:
            self._owner.close()
            return

        if self._protocol is not None:
            self._loop.call_soon_threadsafe(self._protocol.close)
            return

        async def close_stream() -> None:
            self._writer.close()
            try:
                await asyncio.wait_for(
                    self._writer.wait_closed(),
                    timeout=1,
                )
            except (asyncio.TimeoutError, OSError):
                pass

        try:
            self._submit(close_stream(), timeout=2)
        except (OSError, RuntimeError, concurrent.futures.TimeoutError):
            pass

    def _submit(self, coroutine, timeout: Optional[float] = None):
        if self._loop.is_closed():
            coroutine.close()
            raise OSError("QUIC event loop is closed")

        future = asyncio.run_coroutine_threadsafe(
            coroutine,
            self._loop,
        )
        result_timeout = timeout
        if result_timeout is None and self._timeout is not None:
            result_timeout = self._timeout + 1

        try:
            return future.result(timeout=result_timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise


class QuicClientConnection:
    def __init__(
        self,
        host: str,
        port: int,
        configuration: QuicConfiguration,
        timeout: float,
    ) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="netcat-quic-client",
            daemon=True,
        )
        self._thread.start()
        self._context = None
        self._protocol = None
        self._closed = False

        try:
            reader, writer = asyncio.run_coroutine_threadsafe(
                self._open(host, port, configuration),
                self._loop,
            ).result(timeout=timeout)
        except Exception:
            self._stop_loop()
            raise

        self.stream = QuicStreamSocket(
            self._loop,
            reader,
            writer,
            timeout,
            (host, port),
            owner=self,
        )
        self.stream.sendall(QUIC_CLIENT_GREETING)

    async def _open(
        self,
        host: str,
        port: int,
        configuration: QuicConfiguration,
    ):
        self._context = connect(
            host,
            port,
            configuration=configuration,
        )
        self._protocol = await self._context.__aenter__()
        return await self._protocol.create_stream()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()
        pending = asyncio.all_tasks(self._loop)
        for task in pending:
            task.cancel()
        if pending:
            self._loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        self._loop.close()

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        if self._context is not None:
            async def close_context() -> None:
                await self._context.__aexit__(None, None, None)

            try:
                asyncio.run_coroutine_threadsafe(
                    close_context(),
                    self._loop,
                ).result(timeout=3)
            except (OSError, RuntimeError, concurrent.futures.TimeoutError):
                pass

        self._stop_loop()

    def _stop_loop(self) -> None:
        if self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread.is_alive():
            self._thread.join(timeout=3)


class SingleStreamQuicProtocol(QuicConnectionProtocol):
    """Limit each NetCat peer to one bidirectional application stream."""

    def __init__(self, quic, stream_handler=None, **kwargs) -> None:
        self._netcat_stream_handler = stream_handler
        self._netcat_remote_address = None
        super().__init__(
            quic,
            stream_handler=self._handle_stream,
            **kwargs,
        )
        self._netcat_stream_id: Optional[int] = None

    def datagram_received(self, data, addr) -> None:
        self._netcat_remote_address = addr
        super().datagram_received(data, addr)

    def _handle_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if self._netcat_stream_handler is not None:
            self._netcat_stream_handler(
                reader,
                writer,
                self._netcat_remote_address,
                self,
            )

    def quic_event_received(self, event) -> None:
        if isinstance(event, StreamDataReceived):
            if self._netcat_stream_id is None:
                self._netcat_stream_id = event.stream_id
            elif event.stream_id != self._netcat_stream_id:
                self.close(reason_phrase="Only one NetCat stream is allowed")
                return

        super().quic_event_received(event)


class QuicServer:
    def __init__(
        self,
        host: str,
        port: int,
        configuration: QuicConfiguration,
        timeout: float,
        max_clients: int,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._configuration = configuration
        self._incoming = queue.Queue(maxsize=max_clients)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="netcat-quic-server",
            daemon=True,
        )
        self._server = None
        self._closed = False

    def start(self) -> None:
        self._thread.start()
        try:
            self._server = asyncio.run_coroutine_threadsafe(
                serve(
                    self.host,
                    self.port,
                    configuration=self._configuration,
                    create_protocol=self._create_protocol,
                    retry=True,
                ),
                self._loop,
            ).result(timeout=self.timeout)
        except Exception:
            self._stop_loop()
            raise

    def _create_protocol(
        self,
        quic,
        stream_handler=None,
    ) -> SingleStreamQuicProtocol:
        def handle_stream(reader, writer, address, protocol) -> None:
            if stream_handler is not None:
                stream_handler(reader, writer)
            self._handle_stream(
                reader,
                writer,
                address,
                protocol,
            )

        return SingleStreamQuicProtocol(
            quic,
            stream_handler=handle_stream,
        )

    def _handle_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        address,
        protocol: SingleStreamQuicProtocol,
    ) -> None:
        address = address or writer.get_extra_info("peername") or (
            "QUIC peer",
            0,
        )
        stream = QuicStreamSocket(
            self._loop,
            reader,
            writer,
            self.timeout,
            address,
            protocol=protocol,
        )

        async def receive_greeting() -> None:
            try:
                greeting = await asyncio.wait_for(
                    reader.readexactly(len(QUIC_CLIENT_GREETING)),
                    timeout=self.timeout,
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                writer.close()
                protocol.close()
                return

            if greeting != QUIC_CLIENT_GREETING:
                writer.close()
                protocol.close()
                return

            try:
                self._incoming.put_nowait(stream)
            except queue.Full:
                writer.close()
                protocol.close()

        asyncio.create_task(receive_greeting())

    def accept(self) -> QuicStreamSocket:
        try:
            return self._incoming.get(timeout=1)
        except queue.Empty as error:
            raise socket.timeout("No QUIC streams available") from error

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        if self._server is not None and self._loop.is_running():
            async def close_server() -> None:
                self._server.close()
                await asyncio.sleep(0)

            try:
                asyncio.run_coroutine_threadsafe(
                    close_server(),
                    self._loop,
                ).result(timeout=3)
            except (OSError, RuntimeError, concurrent.futures.TimeoutError):
                pass

        self._stop_loop()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()
        pending = asyncio.all_tasks(self._loop)
        for task in pending:
            task.cancel()
        if pending:
            self._loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        self._loop.close()

    def _stop_loop(self) -> None:
        if self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread.is_alive():
            self._thread.join(timeout=3)
