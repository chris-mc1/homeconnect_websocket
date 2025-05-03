from __future__ import annotations

from asyncio import Lock

import aiohttp
from aiohttp import web
from homeconnect_websocket.hc_socket import MINIMUM_MESSAGE_LENGTH
from homeconnect_websocket.message import Action, Message, load_message
from homeconnect_websocket.testutils import AesServerEncryption

from const import (
    CLIENT_MESSAGE_ID,
    DESCRIPTION_CHANGES,
    MANDATORY_VALUES,
    NZ_INFO,
    SERVER_MESSAGE_ID,
    SERVICE_VERSIONS,
    SESSION_ID,
)


class ApplianceServer:
    """Appliance Server."""

    ws: web.WebSocketResponse = None
    host: str = None

    def __init__(self, psk64: str) -> None:
        """Fake Appliance."""
        self.psk64 = psk64
        self._lock = Lock()
        self.messages = []

    async def websocket_handler(self, request: web.Request) -> None:
        """Handle aiohttp websocket requests."""
        if self.ws is not None:
            msg = "More then one connection to TestServer"
            raise RuntimeError(msg)
        self.ws = web.WebSocketResponse()
        await self.ws.prepare(request)
        await self.init_handler()
        async for msg in self.ws:
            decode_msg = await self._receive(msg)
            try:
                hc_msg = load_message(decode_msg)
            except (ValueError, AttributeError):
                self.messages.append(decode_msg)
            else:
                self.messages.append(hc_msg)
                await self.message_handler(hc_msg)
        return self.ws

    def _reset(self) -> None:
        self.mid = SERVER_MESSAGE_ID

    async def _send(self, message: str) -> None:
        await self.ws.send_str(message)

    async def _receive(self, message: aiohttp.WSMessage) -> str:
        return str(message.data)

    async def init_handler(self) -> None:
        """Handle init message."""
        self._reset()
        msg = Message(
            sid=SESSION_ID,
            msg_id=self.mid,
            resource="/ei/initialValues",
            version=2,
            action=Action.POST,
            data=[{"edMsgID": CLIENT_MESSAGE_ID}],
        )
        self.mid = +1
        await self._send(msg.dump())

    async def message_handler(self, msg: Message) -> None:
        """Handle other messages."""
        response_msg = None
        if msg.resource == "/ci/services":
            response_msg = msg.responde(SERVICE_VERSIONS)
        elif msg.resource in ("/iz/info", "/ci/info"):
            response_msg = msg.responde(NZ_INFO)
        elif msg.resource == "/ro/allDescriptionChanges":
            response_msg = msg.responde(DESCRIPTION_CHANGES)
        elif msg.resource in ("/ro/allMandatoryValues", "/ro/values"):
            response_msg = msg.responde(MANDATORY_VALUES)
        if response_msg:
            await self._send(response_msg.dump())


class ApplianceServerAes(ApplianceServer):
    """Appliance Server with AES."""

    def __init__(self, psk64: str, iv64: str) -> None:
        """Appliance Server with AES."""
        self.iv64 = iv64
        self.encryption = AesServerEncryption(psk64, iv64)
        super().__init__(psk64)

    async def websocket_handler(self, request: web.Request) -> None:
        """Handle aiohttp websocket requests."""
        self.encryption.reset()
        return await super().websocket_handler(request)

    async def _send(self, message: str) -> None:
        enc_msg = self.encryption.encrypt(message)
        await self.ws.send_bytes(enc_msg)

    async def _receive(self, message: aiohttp.WSMessage) -> str:
        buf = message.data
        if len(buf) < MINIMUM_MESSAGE_LENGTH:
            msg = "Message to short"
            raise ValueError(msg)
        if len(buf) % 16 != 0:
            msg = "Unaligned Message"
            raise ValueError(msg)

        return self.encryption.decrypt(buf)
