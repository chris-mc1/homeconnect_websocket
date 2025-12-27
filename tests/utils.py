from __future__ import annotations

import hmac
from asyncio import Lock
from base64 import urlsafe_b64decode
from copy import copy

import aiohttp
from aiohttp import web
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from homeconnect_websocket.hc_socket import MINIMUM_MESSAGE_LENGTH
from homeconnect_websocket.message import Message, load_message

from const import (
    SERVER_MESSAGE_ID,
    SESSION_ID,
)

SERVER_ENCRYPT_DIRECTION = b"\x43"  # 'C' in ASCII
SERVER_DECRYPT_DIRECTION = b"\x45"  # 'E' in ASCII


class ApplianceServer:
    """Appliance Server."""

    ws: web.WebSocketResponse = None
    host: str = None

    def __init__(self, message_set: dict, psk64: str) -> None:
        """Fake Appliance."""
        self.psk64 = psk64
        self.message_set = message_set
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
        ws = self.ws
        self.ws = None
        return ws

    def _reset(self) -> None:
        self.mid = SERVER_MESSAGE_ID

    async def _send(self, message: str) -> None:
        await self.ws.send_str(message)

    async def _receive(self, message: aiohttp.WSMessage) -> str:
        return str(message.data)

    def _set_message_info(self, message: Message) -> None:
        """Set Message infos. called before sending message."""
        # Set sID
        if message.sid is None:
            message.sid = SESSION_ID

        # Set msgID
        if message.msg_id is None:
            message.msg_id = self.mid
            self.mid += 1

    async def init_handler(self) -> None:
        """Handle init message."""
        self._reset()
        msg = copy(self.message_set["init"])
        self._set_message_info(msg)
        await self._send(msg.dump())

    async def message_handler(self, msg: Message) -> None:
        """Handle other messages."""
        response_msg = None
        if msg.resource == "/ci/services":
            response_msg = msg.responde(self.message_set["services"])
        elif (
            response_data := self.message_set["responses"].get(msg.resource) is not None
        ):
            response_msg = msg.responde(response_data)
        else:
            response_msg = msg.responde()
            response_msg.code = 404
        if response_msg:
            self._set_message_info(response_msg)
            await self._send(response_msg.dump())


class ApplianceServerAes(ApplianceServer):
    """Appliance Server with AES."""

    def __init__(self, message_set: dict, psk64: str, iv64: str) -> None:
        """Appliance Server with AES."""
        self.iv64 = iv64
        self.encryption = AesServerEncryption(psk64, iv64)
        super().__init__(message_set, psk64)

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


class AesServerEncryption:
    """Class implementing AES Server-side encryption."""

    def __init__(self, psk64: str, iv64: str) -> None:
        """
        Class implementing AES Server-side encryption.

        Args:
        ----
        psk64 (str): urlsafe base64 encoded psk key
        iv64 (Optional[str]): urlsafe base64 encoded iv64 key (only AES)

        """
        psk = urlsafe_b64decode(psk64 + "===")
        self.iv = urlsafe_b64decode(iv64 + "===")

        self.enckey = hmac.digest(psk, b"ENC", digest="sha256")
        self.mackey = hmac.digest(psk, b"MAC", digest="sha256")
        self.reset()

    def reset(self) -> None:
        """Reset cipher and hmac."""
        self.last_rx_hmac = bytes(16)
        self.last_tx_hmac = bytes(16)

        self.aes_encrypt = AES.new(self.enckey, AES.MODE_CBC, self.iv)
        self.aes_decrypt = AES.new(self.enckey, AES.MODE_CBC, self.iv)

    def encrypt(self, clear_msg: str | bytes) -> bytes:
        """Encrypt message."""
        if isinstance(clear_msg, str):
            clear_msg = bytes(clear_msg, "utf-8")

        pad_len = 16 - (len(clear_msg) % 16)
        if pad_len == 1:
            pad_len += 16
        clear_msg = (
            clear_msg + b"\x00" + get_random_bytes(pad_len - 2) + bytearray([pad_len])
        )

        enc_msg = self.aes_encrypt.encrypt(clear_msg)
        self.last_tx_hmac = self.hmac_encrypt(enc_msg)

        return enc_msg + self.last_tx_hmac

    def hmac_encrypt(self, enc_msg: bytes) -> bytes:
        """Calculate hmac for encrypted message."""
        hmac_msg = self.iv + SERVER_ENCRYPT_DIRECTION + self.last_tx_hmac + enc_msg
        return hmac.digest(self.mackey, hmac_msg, digest="sha256")[0:16]

    def decrypt(self, message: bytes) -> str:
        """Decrypt message."""
        enc_msg = message[0:-16]
        recv_hmac = message[-16:]

        calculated_hmac = self.hmac_decrypt(enc_msg)

        if not hmac.compare_digest(recv_hmac, calculated_hmac):
            msg = "HMAC Failure"
            raise ValueError(msg)

        self.last_rx_hmac = recv_hmac

        msg = self.aes_decrypt.decrypt(enc_msg)
        pad_len = msg[-1]
        if len(msg) < pad_len:
            msg = "Padding Error"
            raise ValueError(msg)
        return msg[0:-pad_len].decode("utf-8")

    def hmac_decrypt(self, enc_msg: bytes) -> bytes:
        """Calculate hmac for decrypted message."""
        hmac_msg = self.iv + SERVER_DECRYPT_DIRECTION + self.last_rx_hmac + enc_msg
        return hmac.digest(self.mackey, hmac_msg, digest="sha256")[0:16]
