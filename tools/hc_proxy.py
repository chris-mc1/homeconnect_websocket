from __future__ import annotations

import asyncio
import logging
import ssl
from argparse import ArgumentParser
from base64 import urlsafe_b64decode
from pathlib import Path

from aiohttp import web

from homeconnect_websocket.hc_socket import AesSocket, TlsSocket
from homeconnect_websocket.testutils import AesServerEncryption

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)
_LOGGER = logging.getLogger()

TLS_PORT = 443
AES_PORT = 80


async def tls_recv_task(
    device_socket: TlsSocket, app_socket: web.WebSocketResponse
) -> None:
    """Receive Task for TSL."""
    async for message_str in device_socket:
        await app_socket.send_str(message_str)


async def aes_recv_task(
    device_socket: AesSocket,
    app_socket: web.WebSocketResponse,
    encryption: AesServerEncryption,
) -> None:
    """Receive Task for AES."""
    async for message_str in device_socket:
        enc_msg = encryption.encrypt(message_str)
        await app_socket.send_bytes(enc_msg)


class Proxy:
    """HomeConnect Proxy."""

    _aes_site: web.TCPSite | None = None
    _tls_site: web.TCPSite | None = None

    def __init__(self, host: str, psk64: str, iv64: str | None = None) -> None:
        """
        HomeConnect Proxy.

        Args:
        ----
            host (str): Host
            psk64 (str): urlsafe base64 encoded psk key
            iv64 (Optional[str]): urlsafe base64 encoded iv64 key (only AES)

        """
        self.host = host
        self.psk64 = psk64
        self.iv64 = iv64
        self._tasks = set()
        app = web.Application()
        app.add_routes(
            [
                web.get("/homeconnect", self._websocket_handler),
            ]
        )
        self._runner = web.AppRunner(app)

    async def run(self) -> None:
        """Start proxy."""
        _LOGGER.info("Starting Proxy")
        await self._runner.setup()

        psk = urlsafe_b64decode(self.psk64 + "===")
        psk.hex()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.set_ciphers("ALL")
        ssl_context.check_hostname = False
        ssl_context.set_psk_server_callback(lambda _: psk)
        self._tls_site = web.TCPSite(
            self._runner, port=TLS_PORT, ssl_context=ssl_context
        )
        await self._tls_site.start()

        if self.iv64 is not None:
            self._aes_site = web.TCPSite(self._runner, port=AES_PORT)
            await self._aes_site.start()

    async def _websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        _LOGGER.info("Incomming connection from %s", request.remote)
        app_socket = web.WebSocketResponse(heartbeat=2)
        await app_socket.prepare(request)
        if request.url.port == AES_PORT:
            # AES
            device_socket = AesSocket(self.host, self.psk64, self.iv64)
            encryption = AesServerEncryption(psk64=self.psk64, iv64=self.iv64)

            await device_socket.connect()
            task = asyncio.create_task(
                aes_recv_task(device_socket, app_socket, encryption)
            )
            self._tasks.add(task)
            task.add_done_callback(self._tasks.remove)

            async for message in app_socket:
                message_str = encryption.decrypt(message.data)
                await device_socket.send(message_str)
        else:
            # TLS
            device_socket = TlsSocket(self.host, self.psk64)
            await device_socket.connect()
            task = asyncio.create_task(tls_recv_task(device_socket, app_socket))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.remove)

            async for message in app_socket:
                message_str = str(message.data)
                await device_socket.send(message_str)

        _LOGGER.info("Connection from %s closed", request.remote)
        await device_socket.close()
        return app_socket


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("host", type=str, help="Appliance Host")
    parser.add_argument("-psk", type=str, dest="psk", help="Appliance PSK Key")
    parser.add_argument(
        "-iv", type=str, dest="iv", default=None, help="Appliance AES IV"
    )
    parser.add_argument("-o", type=Path, default=None, dest="log_file", help="Log file")
    args = parser.parse_args()
    if args.log_file:
        _LOGGER.addHandler(logging.FileHandler(filename="proxy.log"))

    loop = asyncio.new_event_loop()
    proxy = Proxy(args.host, args.psk, args.iv)
    loop.run_until_complete(proxy.run())
    loop.run_forever()
