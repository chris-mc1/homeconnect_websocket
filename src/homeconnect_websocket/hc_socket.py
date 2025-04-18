from __future__ import annotations

import hmac
import logging
import ssl
from abc import abstractmethod
from base64 import urlsafe_b64decode

import aiohttp
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class HCSocket:
    """Socket Base class."""

    _URL_FORMAT = "ws://{host}:80/homeconnect"
    _session: aiohttp.ClientSession
    _websocket: aiohttp.ClientWebSocketResponse | None = None
    _owned_session: bool = False

    def __init__(
        self,
        host: str,
        session: aiohttp.ClientSession | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        Initialize.

        Args:
        ----
        host (str): Host
        session (Optional[aiohttp.ClientSession]): ClientSession
        logger (Optional[Logger]): Logger

        """
        if ":" in host:
            # is ipv6 address
            host = f"[{host}]"
        self._url = self._URL_FORMAT.format(host=host)
        if session is None:
            session = aiohttp.ClientSession()
            self._owned_session = True
        self._session = session
        if logger is None:
            self._logger = logging.getLogger(__name__)
        else:
            self._logger = logger.getChild("socket")

    @abstractmethod
    async def connect(self) -> None:
        """Connect to websocket."""
        self._logger.debug("Socket connecting to %s, mode=NONE", self._url)
        self._websocket = await self._session.ws_connect(self._url, heartbeat=20)

    @abstractmethod
    async def send(self, message: str) -> None:
        """Send message."""
        self._logger.debug("Send     %s: %s", self._url, message)
        await self._websocket.send_str(message)

    @abstractmethod
    async def _receive(self, message: aiohttp.WSMessage) -> str:
        """Recive message."""
        self._logger.debug("Received %s: %s", self._url, str(message.data))
        return str(message.data)

    async def close(self) -> None:
        """Close websocket."""
        self._logger.debug("Closing socket %s", self._url)
        if self._websocket:
            await self._websocket.close()
        if self._owned_session:
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
    _ssl_context: ssl.SSLContext

    def __init__(
        self,
        host: str,
        psk64: str,
        session: aiohttp.ClientSession | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        TLS Socket.

        Args:
        ----
        host (str): Host
        psk64 (str): psk64 key
        session (Optional[aiohttp.ClientSession]): ClientSession
        logger (Optional[Logger]): Logger

        """
        # setup sslcontext
        psk = urlsafe_b64decode(psk64 + "===")
        self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        self._ssl_context.set_ciphers("PSK")
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        self._ssl_context.set_psk_client_callback(lambda _: (None, psk))
        super().__init__(host, session, logger)

    async def connect(self) -> None:
        """Connect to websocket."""
        self._logger.debug("Socket connecting to %s, mode=TLS", self._url)
        self._websocket = await self._session.ws_connect(
            self._url, ssl=self._ssl_context, heartbeat=20
        )

    async def send(self, message: str) -> None:
        """Send message."""
        self._logger.debug("Send     %s: %s", self._url, message)
        await self._websocket.send_str(message)

    async def _receive(self, message: aiohttp.WSMessage) -> str:
        self._logger.debug("Received %s: %s", self._url, str(message.data))
        if message.type == aiohttp.WSMsgType.ERROR:
            raise message.data
        return str(message.data)


ENCRYPT_DIRECTION = b"\x45"  # 'E' in ASCII
DECRYPT_DIRECTION = b"\x43"  # 'C' in ASCII
MINIMUM_MESSAGE_LENGTH = 32


class AesSocket(HCSocket):
    """AES Socket."""

    _URL_FORMAT = "ws://{host}:80/homeconnect"
    _last_rx_hmac: bytes
    _last_tx_hmac: bytes

    def __init__(
        self,
        host: str,
        psk64: str,
        iv64: str,
        session: aiohttp.ClientSession | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        AES Socket.

        Args:
        ----
            host (str): Host
            psk64 (str): psk64 key
            iv64 (str): iv64
            session (Optional[aiohttp.ClientSession]): ClientSession
            logger (Optional[Logger]): Logger

        """
        psk = urlsafe_b64decode(psk64 + "===")
        self._iv = urlsafe_b64decode(iv64 + "===")
        self._enckey = hmac.digest(psk, b"ENC", digest="sha256")
        self._mackey = hmac.digest(psk, b"MAC", digest="sha256")

        super().__init__(host, session, logger)

    async def connect(self) -> None:
        """Connect to websocket."""
        self._last_rx_hmac = bytes(16)
        self._last_tx_hmac = bytes(16)

        self._aes_encrypt = AES.new(self._enckey, AES.MODE_CBC, self._iv)
        self._aes_decrypt = AES.new(self._enckey, AES.MODE_CBC, self._iv)

        self._logger.debug("Socket connecting to %s, mode=AES", self._url)
        self._websocket = await self._session.ws_connect(self._url, heartbeat=20)

    async def send(self, clear_msg: str) -> None:
        """Recive message."""
        self._logger.debug("Send     %s: %s", self._url, clear_msg)
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
            msg = "Message not of Type binary %s"
            msg.format(str(message))
            self._logger.warning(msg)
            raise ValueError(msg)

        buf = message.data
        if len(buf) < MINIMUM_MESSAGE_LENGTH:
            msg = "Message to short: %s"
            msg.format(str(message))
            self._logger.warning(msg)
            raise ValueError(msg)
        if len(buf) % 16 != 0:
            msg = "Unaligned Message %s"
            msg.format(str(message))
            self._logger.warning(msg)
            raise ValueError(msg)

        enc_msg = buf[0:-16]
        recv_hmac = buf[-16:]

        hmac_msg = self._iv + DECRYPT_DIRECTION + self._last_rx_hmac + enc_msg
        calculated_hmac = hmac.digest(self._mackey, hmac_msg, digest="sha256")[0:16]

        if not hmac.compare_digest(recv_hmac, calculated_hmac):
            msg = "HMAC Failure: %s"
            msg.format(str(message))
            self._logger.warning(msg)
            raise ValueError(msg)

        self._last_rx_hmac = recv_hmac

        msg = self._aes_decrypt.decrypt(enc_msg)
        pad_len = msg[-1]
        if len(msg) < pad_len:
            msg = "Padding Error %s"
            msg.format(str(message))
            self._logger.warning(msg)
            raise ValueError(msg)
        decoded_msg = msg[0:-pad_len].decode("utf-8")

        self._logger.debug("Received %s: %s", self._url, decoded_msg)
        return decoded_msg
