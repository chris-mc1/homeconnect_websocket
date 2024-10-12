from __future__ import annotations

import hmac
import logging
import ssl
import sys
from abc import abstractmethod
from base64 import urlsafe_b64decode

import aiohttp
import sslpsk3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from sslpsk3.sslpsk3 import _ssl_set_psk_client_callback, _ssl_set_psk_server_callback

_LOGGER = logging.getLogger(__name__)

# Monkey patch for sslpsk
# see https://github.com/maovidal/paho_sslpsk2_demo/blob/main/paho_sslpsk2_demo.py
def _sslobj(sock):
    if (3, 5) <= sys.version_info <= (3, 7):
        return sock._sslobj._sslobj
    return sock._sslobj


sslpsk3.sslpsk3._sslobj = _sslobj


def _ssl_setup_psk_callbacks(sslobj):
    psk = sslobj.context.psk
    hint = sslobj.context.hint
    if psk:
        if sslobj.server_side:
            cb = psk if callable(psk) else lambda _identity: psk
            _ssl_set_psk_server_callback(sslobj, cb, hint)
        else:
            cb = (
                psk
                if callable(psk)
                else lambda _hint: psk if isinstance(psk, tuple) else (psk, b"")
            )
            _ssl_set_psk_client_callback(sslobj, cb)


class SSLPSKContext(ssl.SSLContext):
    @property
    def psk(self):
        return getattr(self, "_psk", None)

    @psk.setter
    def psk(self, psk):
        self._psk = psk

    @property
    def hint(self):
        return getattr(self, "_hint", None)

    @hint.setter
    def hint(self, hint):
        self._hint = hint


class SSLPSKObject(ssl.SSLObject):
    def do_handshake(self, *args, **kwargs):
        if not hasattr(self, "_did_psk_setup"):
            _ssl_setup_psk_callbacks(self)
            self._did_psk_setup = True
        super().do_handshake(*args, **kwargs)


class SSLPSKSocket(ssl.SSLSocket):
    def do_handshake(self, *args, **kwargs):
        if not hasattr(self, "_did_psk_setup"):
            _ssl_setup_psk_callbacks(self)
            self._did_psk_setup = True
        super().do_handshake(*args, **kwargs)


SSLPSKContext.sslobject_class = SSLPSKObject
SSLPSKContext.sslsocket_class = SSLPSKSocket


class HCSocket:
    """Socket Base class."""

    _URL_FORMAT = "ws://{host}:80/homeconnect"
    _session: aiohttp.ClientSession
    _websocket: aiohttp.ClientWebSocketResponse | None = None

    def __init__(self, host: str) -> None:
        """
        Initialize.

        Args:
        ----
        host (str): Host.

        """
        self._url = self._URL_FORMAT.format(host=host)
        self._session = aiohttp.ClientSession()

    @abstractmethod
    async def connect(self) -> None:
        """Connect to websocket."""
        _LOGGER.debug("Socket connecting to %s, mode=NONE", self._url)
        self._websocket = await self._session.ws_connect(self._url, heartbeat=20)

    @abstractmethod
    async def send(self, message: str) -> None:
        """Send message."""
        _LOGGER.debug("Send     %s: %s", self._url, message)
        await self._websocket.send_str(message)

    @abstractmethod
    async def _receive(self, message: aiohttp.WSMessage) -> str:
        """Recive message."""
        _LOGGER.debug("Received %s: %s", self._url, str(message.data))
        return str(message.data)

    async def close(self) -> None:
        """Close websocket."""
        _LOGGER.debug("Closing socket %s", self._url)
        if self._websocket:
            await self._websocket.close()
        await self._session.close()

    @property
    def closed(self) -> bool:
        """True if underlying websocket is closed."""
        if self._websocket:
            return self._websocket.closed
        return True

    def __aiter__(self) -> HCSocket:
        return self

    async def __anext__(self) -> str:
        msg = await self._websocket.__anext__()
        return await self._receive(msg)


class TlsSocket(HCSocket):
    """TLS (wss) Socket."""

    _URL_FORMAT = "wss://{host}:443/homeconnect"
    _ssl_context: SSLPSKContext

    def __init__(self, host: str, psk64: str) -> None:
        """
        TLS Socket.

        Args:
        ----
        host (str): Host
        psk64 (str): psk64 key

        """
        # setup sslcontext
        self._ssl_context = SSLPSKContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_context.options |= ssl.OP_NO_TLSv1_3
        self._ssl_context.set_ciphers("ALL")
        self._ssl_context.psk = urlsafe_b64decode(psk64 + "===")
        self._ssl_context.check_hostname = False
        self._ssl_context.suppress_ragged_eofs = True
        super().__init__(host)

    async def connect(self) -> None:
        """Connect to websocket."""
        _LOGGER.debug("Socket connecting to %s, mode=TLS", self._url)
        self._websocket = await self._session.ws_connect(
            self._url, ssl=self._ssl_context, heartbeat=20
        )

    async def send(self, message: str) -> None:
        """Send message."""
        _LOGGER.debug("Send     %s: %s", self._url, message)
        await self._websocket.send_str(message)

    async def _receive(self, message: aiohttp.WSMessage) -> str:
        _LOGGER.debug("Received %s: %s", self._url, str(message.data))
        return str(message.data)


ENCRYPT_DIRECTION = b"\x45"  # 'E' in ASCII
DECRYPT_DIRECTION = b"\x43"  # 'C' in ASCII
MINIMUM_MESSAGE_LENGTH = 32


class AesSocket(HCSocket):
    """
    AES Socket.

    Args:
    ----
    host (str): Host
    psk64 (str): psk64 key
    iv64 (str): iv64

    """

    _URL_FORMAT = "ws://{host}:80/homeconnect"
    _last_rx_hmac: bytes
    _last_tx_hmac: bytes

    def __init__(self, host: str, psk64: str, iv64: str) -> None:
        """
        AES Socket.

        Args:
        ----
            host (str): Host
            psk64 (str): psk64 key
            iv64 (str): iv64

        """
        psk = urlsafe_b64decode(psk64 + "===")
        self._iv = urlsafe_b64decode(iv64 + "===")
        self._enckey = hmac.digest(psk, b"ENC", digest="sha256")
        self._mackey = hmac.digest(psk, b"MAC", digest="sha256")

        super().__init__(host)

    async def connect(self) -> None:
        """Connect to websocket."""
        self._last_rx_hmac = bytes(16)
        self._last_tx_hmac = bytes(16)

        self._aes_encrypt = AES.new(self._enckey, AES.MODE_CBC, self._iv)
        self._aes_decrypt = AES.new(self._enckey, AES.MODE_CBC, self._iv)

        _LOGGER.debug("Socket connecting to %s, mode=AES", self._url)
        self._websocket = await self._session.ws_connect(self._url, heartbeat=20)

    async def send(self, clear_msg: str) -> None:
        """Recive message."""
        if isinstance(clear_msg, str):
            clear_msg = bytes(clear_msg, "utf-8")

        pad_len = 16 - (len(clear_msg) % 16)
        if pad_len == 1:
            pad_len += 16
        clear_msg = (
            clear_msg + b"\x00" + get_random_bytes(pad_len - 2) + bytearray([pad_len])
        )

        enc_msg = self._aes_encrypt.encrypt(clear_msg)

        hmac_msg = self._iv + ENCRYPT_DIRECTION + self._last_tx_hmac + enc_msg
        self._last_tx_hmac = hmac.digest(self._mackey, hmac_msg, digest="sha256")[0:16]

        await self._websocket.send_bytes(enc_msg + self._last_tx_hmac)

    async def _receive(self, message: aiohttp.WSMessage) -> str:
        if message.type != aiohttp.WSMsgType.BINARY:
            msg = "Message not of Type binary"
            _LOGGER.warning(msg)
            raise ValueError(msg)

        buf = message.data
        if len(buf) < MINIMUM_MESSAGE_LENGTH:
            msg = "Message to short"
            _LOGGER.warning(msg)
            raise ValueError(msg)
        if len(buf) % 16 != 0:
            msg = "Unaligned Message"
            _LOGGER.warning(msg)
            raise ValueError(msg)

        enc_msg = buf[0:-16]
        recv_hmac = buf[-16:]

        hmac_msg = self._iv + DECRYPT_DIRECTION + self._last_rx_hmac + enc_msg
        calculated_hmac = hmac.digest(self._mackey, hmac_msg, digest="sha256")[0:16]

        if not hmac.compare_digest(recv_hmac, calculated_hmac):
            msg = "HMAC Failure"
            _LOGGER.warning(msg)
            raise ValueError(msg)

        self._last_rx_hmac = recv_hmac

        msg = self._aes_decrypt.decrypt(enc_msg)
        pad_len = msg[-1]
        if len(msg) < pad_len:
            msg = "Padding Error"
            _LOGGER.warning(msg)
            raise ValueError(msg)

        return msg[0:-pad_len].decode("utf-8")
