from __future__ import annotations

import asyncio
import contextlib
import logging
from abc import abstractmethod
from base64 import urlsafe_b64encode
from enum import StrEnum, auto
from json import JSONDecodeError
from typing import TYPE_CHECKING

import aiohttp
from Crypto.Random import get_random_bytes

from homeconnect_websocket.task_manager import TaskManager

from .const import DEFAULT_SEND_TIMEOUT, ERROR_CODES
from .errors import (
    AllreadyConnectedError,
    CodeResponsError,
    ConnectionFailedError,
    DisconnectedError,
    HCHandshakeError,
    NotConnectedError,
)
from .hc_socket import AesSocket, HCSocket, TlsSocket
from .message import Action, Message, load_message

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class ConnectionState(StrEnum):
    """Session connection state."""

    CONNECTING = auto()
    """Session is connecting"""
    HANDSHAKE = auto()
    """Socket connected, running handshake"""
    CONNECTED = auto()
    """Session is connected"""
    RECONNECTING = auto()
    """Session is disconnected, trying to reconnect"""
    CLOSING = auto()
    """Session is closing"""
    CLOSED = auto()
    """Session is closed"""
    ABNORMAL_CLOSURE = auto()
    """Session closed abnormally"""


class HCSessionBase:
    """HomeConnect Session."""

    connection_state: ConnectionState = ConnectionState.CLOSED
    _host: str
    _psk64: str
    _iv64: str | None
    _socket: HCSocket
    _logger: logging.Logger
    _connection_state_callback: Callable[[ConnectionState], Awaitable[None]] | None
    _task_manager: TaskManager

    def __init__(  # noqa: PLR0913
        self,
        host: str,
        psk64: str,
        iv64: str | None = None,
        *,
        aiohttp_session: aiohttp.ClientSession | None = None,
        logger: logging.Logger | None = None,
        connection_state_callback: Callable[[ConnectionState], Awaitable[None]]
        | None = None,
        task_manager: TaskManager | None = None,
    ) -> None:
        """HomeConnect Session Baseclass."""
        self._host = host
        self._psk64 = psk64
        self._iv64 = iv64
        self._connection_state_callback = connection_state_callback
        self._task_manager = TaskManager() if task_manager is None else task_manager

        self._loop = asyncio.get_event_loop()

        if logger is None:
            self._logger = logging.getLogger(__name__)
        else:
            self._logger = logger.getChild("session")

        # create socket
        if self._iv64:
            self._logger.debug("Got iv64, using AES socket")
            self._socket = AesSocket(
                self._host, self._psk64, self._iv64, aiohttp_session, logger
            )
        elif self._psk64:
            self._logger.debug("No iv64, using TLS socket")
            self._socket = TlsSocket(self._host, self._psk64, aiohttp_session, logger)
        else:  # For Testing
            self._logger.warning("Using unencrypted socket")
            self._socket = HCSocket(self._host, aiohttp_session, logger)

    @property
    def connected(self) -> bool:
        """Is connected."""
        return (
            not self._socket.closed
            and self.connection_state == ConnectionState.CONNECTED
        )

    @abstractmethod
    async def _message_handler(self, message: Message) -> None:
        pass

    def _set_connection_state(self, new_state: ConnectionState) -> None:
        """
        Set connection state and execute callback on change.

        Args:
        ----
        new_state (ConnectionState): new connection state

        """
        state_change = self.connection_state != new_state
        self.connection_state = new_state
        if state_change and self._connection_state_callback:
            self._task_manager.create_task(
                self._wrap_connection_state_callback(new_state)
            )

    async def _wrap_connection_state_callback(self, new_state: ConnectionState) -> None:
        """Call the external message handler."""
        try:
            await self._connection_state_callback(new_state)
        except Exception:
            self._logger.exception("Exception in connection state callback")

    async def _wrap_recv_loop(self) -> None:
        try:
            await self._recv_loop()
        except (aiohttp.ClientConnectionError, aiohttp.ServerTimeoutError) as exc:
            self._logger.debug(exc)
            raise ConnectionFailedError from exc
        except asyncio.CancelledError:
            self._logger.debug("Receive loop cancelled")
            raise
        except Exception:
            self._logger.exception("Receive loop Exception")
        finally:
            if self._socket.closed:
                self._logger.debug(
                    "Socket closed with code %s",
                    self._socket._websocket.close_code,  # noqa: SLF001
                    exc_info=self._socket._websocket.exception(),  # noqa: SLF001
                )
                self._set_connection_state(ConnectionState.ABNORMAL_CLOSURE)

    async def _recv_loop(self) -> None:
        self._logger.debug("Starting receive loop")
        async for message in self._socket:
            # recv messages
            try:
                message_obj = load_message(message)
                await self._message_handler(message_obj)
            except (JSONDecodeError, KeyError):
                self._logger.warning("Can't decode message: %s", message)


class HCSession(HCSessionBase):
    """HomeConnect Session Baseclass."""

    service_versions: dict
    _sid: int | None = None
    _last_msg_id: int | None = None
    _device_info: dict
    _response_queues: dict[int, asyncio.Queue]
    _send_lock: asyncio.Lock
    _response_lock: asyncio.Lock
    _do_handshake: bool
    _ext_message_handler: Callable[[Message], Awaitable[None]] | None = None

    def __init__(  # noqa: PLR0913
        self,
        host: str,
        app_name: str,
        app_id: str,
        psk64: str,
        iv64: str | None = None,
        message_handler: Callable[[Message], Awaitable[None]] | None = None,
        *,
        aiohttp_session: aiohttp.ClientSession | None = None,
        logger: logging.Logger | None = None,
        handshake: bool = True,
        connection_state_callback: Callable[[ConnectionState], Awaitable[None]]
        | None = None,
        task_manager: TaskManager | None = None,
    ) -> None:
        """
        HomeConnect Session.

        Args:
        ----
        host (str): Host.
        app_name (str): Name used to identify this App
        app_id (str): ID used to identify this App
        psk64 (str): urlsafe base64 encoded psk key
        iv64 (Optional[str]): urlsafe base64 encoded iv64 key (only AES)
        message_handler (Callable[[Message], Awaitable[None]]): called for each message
        aiohttp_session (Optional[aiohttp.ClientSession]): ClientSession
        logger (Optional[Logger]): Logger
        handshake (bool): Automatic Handshake
        connection_state_callback (Optional[Callable[[ConnectionState], Awaitable[None]]]): Called when connection state changes
        task_manager (Optional[TaskManager]): Task manager

        """  # noqa: E501
        super().__init__(
            host=host,
            psk64=psk64,
            iv64=iv64,
            aiohttp_session=aiohttp_session,
            logger=logger,
            connection_state_callback=connection_state_callback,
            task_manager=task_manager,
        )
        self._app_name = app_name
        self._app_id = app_id
        self._do_handshake = handshake
        self._ext_message_handler = message_handler

        self.service_versions = {}
        self._response_queues = {}
        self._send_lock = asyncio.Lock()
        self._response_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Open Connection with Appliance."""
        if self.connection_state in (
            ConnectionState.CONNECTING,
            ConnectionState.HANDSHAKE,
            ConnectionState.CONNECTED,
        ):
            raise AllreadyConnectedError

        self._logger.info("Connecting to %s", self._host)
        self._set_connection_state(ConnectionState.CONNECTING)

        try:
            await self._socket.connect()
        except (aiohttp.ClientConnectionError, aiohttp.ClientConnectorSSLError) as exc:
            msg = "Failed to connect to Appliance"
            self._logger.debug(msg, exc_info=True)
            self._set_connection_state(ConnectionState.ABNORMAL_CLOSURE)
            raise ConnectionFailedError(msg) from exc

        if self._do_handshake:
            init_message = await self._pre_handshake()
            self._task_manager.create_background_task(
                self._wrap_recv_loop(), eager_start=True
            )
            await self._handshake(init_message)
        else:
            self._task_manager.create_background_task(
                self._wrap_recv_loop(), eager_start=True
            )
            self._logger.info("Connected, no handshake")
            self._set_connection_state(ConnectionState.CONNECTED)

    async def close(self) -> None:
        """Close connction."""
        self._logger.info("Closing connection to %s", self._host)
        if self.connection_state not in (
            ConnectionState.CLOSED,
            ConnectionState.CLOSING,
            ConnectionState.ABNORMAL_CLOSURE,
        ):
            self._set_connection_state(ConnectionState.CLOSING)
            await self._socket.close()
            await self._task_manager.block_till_done()  # Wait for all pending callbacks
            self._set_connection_state(ConnectionState.CLOSED)

        await self._task_manager.block_till_done()  # Wait for connection state callback

    async def send(self, message: Message) -> None:
        """Send message to Appliance, returns immediately."""
        async with self._send_lock:
            self._set_message_info(message)
            await self._socket.send(message.dump())

    async def send_sync(
        self,
        send_message: Message,
        timeout: float = DEFAULT_SEND_TIMEOUT,  # noqa: ASYNC109
    ) -> Message | None:
        """Send message to Appliance, returns Response Message."""
        response_queue: asyncio.Queue[Message] = asyncio.Queue(maxsize=1)

        async with self._send_lock:
            self._set_message_info(send_message)

        try:
            async with self._response_lock:
                self._response_queues[send_message.msg_id] = response_queue

            # send message
            await self._socket.send(send_message.dump())
            response_message = await asyncio.wait_for(response_queue.get(), timeout)
            # Check for error code in response message
            if response_message.code:
                self._logger.debug(
                    "Received Code %s: %s for Message %s, resource: %s",
                    response_message.code,
                    ERROR_CODES.get(response_message.code, "Unknown"),
                    send_message.msg_id,
                    response_message.resource,
                )
                raise CodeResponsError(response_message.code, response_message.resource)

        except asyncio.QueueShutDown:
            self._logger.debug(
                "Client disconnected while waiting for response %s", send_message.msg_id
            )
            raise DisconnectedError from None
        else:
            return response_message
        finally:
            async with self._response_lock:
                with contextlib.suppress(KeyError):
                    self._response_queues.pop(send_message.msg_id)

    async def _message_handler(self, message: Message) -> None:
        if message.action == Action.RESPONSE:
            try:
                async with self._response_lock:
                    self._response_queues[message.msg_id].put_nowait(message)
            except KeyError:
                self._logger.debug(
                    "Received response for unkown Msg ID %s", message.msg_id
                )
            except asyncio.QueueFull:
                self._logger.warning(
                    "Queue for response message %s is allready full",
                    message.msg_id,
                )
            except asyncio.QueueShutDown:
                self._logger.warning(
                    "Queue for response message %s is shutdown",
                    message.msg_id,
                )

        else:
            self._task_manager.create_task(self._wrap_message_handler(message))

    async def _wrap_message_handler(self, message: Message) -> None:
        """Call the external message handler."""
        try:
            await self._ext_message_handler(message)
        except Exception:
            self._logger.exception("Exception in external message handler")

    async def _pre_handshake(self) -> Message:
        try:
            message = await self._socket.receive()
            message_obj = load_message(message)

            if message_obj.resource == "/ei/initialValues":
                self._logger.info("Got init message, beginning handshake")
                self._sid = message_obj.sid
                self._last_msg_id = message_obj.data[0]["edMsgID"]
                return message_obj

            msg = "First received message is not init message"
            self._logger.error(msg)
            raise ConnectionFailedError(msg)

        except (JSONDecodeError, KeyError, IndexError) as exc:
            msg = f"Invalid init message: {message}"
            self._logger.warning(msg)
            raise HCHandshakeError(msg) from exc

    async def _handshake(self, message_init: Message) -> None:
        self._set_connection_state(ConnectionState.HANDSHAKE)
        try:
            # responde to init message
            await self.send(
                message_init.responde(
                    {
                        "deviceType": 2 if message_init.version == 1 else "Application",
                        "deviceName": self._app_name,
                        "deviceID": self._app_id,
                    }
                )
            )

            # request available services
            message_services = Message(resource="/ci/services", version=1)
            response_services = await self.send_sync(message_services)
            self._set_service_versions(response_services)
            self._task_manager.create_task(
                self._wrap_message_handler(response_services)
            )

            if self.service_versions.get("ci", 1) < 3:  # noqa: PLR2004
                # authenticate
                token = urlsafe_b64encode(get_random_bytes(32)).decode("UTF-8")
                token = token.replace("=", "")
                message_authentication = Message(
                    resource="/ci/authentication", data={"nonce": token}
                )
                await self.send_sync(message_authentication)

                # request device info
                with contextlib.suppress(CodeResponsError):
                    message_info = Message(resource="/ci/info")
                    response_info = await self.send_sync(message_info)
                    self._task_manager.create_task(
                        self._wrap_message_handler(response_info)
                    )

            if "iz" in self.service_versions:
                message_info = Message(resource="/iz/info")
                response_info = await self.send_sync(message_info)
                self._task_manager.create_task(
                    self._wrap_message_handler(response_info)
                )

            if self.service_versions.get("ei", 1) == 2:  # noqa: PLR2004
                # report device ready
                message_ready = Message(
                    resource="/ei/deviceReady", action=Action.NOTIFY
                )
                await self.send(message_ready)

            if "ni" in self.service_versions:
                message_ready = Message(resource="/ni/info")
                await self.send_sync(message_ready)

            self._logger.info("Handshake completed")
            self._set_connection_state(ConnectionState.CONNECTED)

        except asyncio.CancelledError:
            self._logger.debug("Handshake cancelled")
            raise
        except (NotConnectedError, DisconnectedError) as exc:
            msg = "Client disconnected during Handshake"
            self._logger.exception(msg)
            raise HCHandshakeError from exc
        except CodeResponsError as exc:
            msg = "Received Code response during Handshake"
            self._logger.exception(msg)
            raise HCHandshakeError(msg) from exc
        except Exception as exc:
            msg = "Unknown Exception during Handshake"
            self._logger.exception(msg)
            raise HCHandshakeError(msg) from exc

    def _set_service_versions(self, message: Message) -> None:
        """Set service versions from a '/ci/services' Response."""
        self._logger.debug("Setting Service versions")
        if message.data is not None:
            for service in message.data:
                self.service_versions[service["service"]] = service["version"]
        else:
            msg = "No Data in Message"
            raise ValueError(msg)

    def _set_message_info(self, message: Message) -> None:
        """Set Message infos. called before sending message."""
        # Set service version
        if message.version is None:
            service = message.resource[1:3]
            message.version = self.service_versions.get(service, 1)

        # Set sID
        if message.sid is None:
            message.sid = self._sid

        # Set msgID
        if message.msg_id is None:
            message.msg_id = self._last_msg_id
            self._last_msg_id += 1

    async def _reset(self) -> None:
        """Rest connction state."""
        self.service_versions.clear()

        async with self._response_lock:
            while self._response_queues:
                self._response_queues.popitem()[1].shutdown()


class HCSessionReconnect(HCSession):
    """HomeConnect Session with reconnect."""

    _reconnect: bool = True

    async def connect(self) -> None:
        """Open Connection with Appliance."""
        self._reconnect = True
        if self.connection_state in (ConnectionState.RECONNECTING):
            raise AllreadyConnectedError

        await super().connect()

    async def close(self) -> None:
        """Close connction."""
        self._reconnect = False
        await super().close()

    async def _reconnect_loop(self) -> None:
        while self._reconnect:
            try:
                await self._socket.connect()

                if self._do_handshake:
                    init_message = await self._pre_handshake()
                    self._task_manager.create_background_task(
                        self._wrap_recv_loop(), eager_start=True
                    )
                    await self._handshake(init_message)
                    break

                self._task_manager.create_background_task(
                    self._wrap_recv_loop(), eager_start=True
                )
                self._logger.info("Connected, no handshake")
                self._set_connection_state(ConnectionState.CONNECTED)
                break

            except (ConnectionFailedError, aiohttp.ClientError):
                self._logger.debug("Reconnect failed")
                continue
            except HCHandshakeError:
                self._logger.debug("Reconnect failed")
                self._set_connection_state(ConnectionState.CLOSING)
                break
            except asyncio.CancelledError:
                self._logger.debug("Reconnect cancelled")
                raise
            except Exception:
                self._logger.exception("Reconnect exception")
                await self.close()
                break

    async def _wrap_recv_loop(self) -> None:
        try:
            await self._recv_loop()
        except (aiohttp.ClientConnectionError, aiohttp.ServerTimeoutError) as exc:
            self._logger.debug(exc)
        except asyncio.CancelledError:
            self._logger.debug("Receive loop cancelled")
            self._reconnect = False  # Disable reconnect on cancel
            raise
        except Exception:
            self._logger.exception("Receive loop Exception")
        finally:
            if self._socket.closed:
                self._logger.debug(
                    "Socket closed with code %s",
                    self._socket._websocket.close_code,  # noqa: SLF001
                    exc_info=self._socket._websocket.exception(),  # noqa: SLF001
                )
                if self._reconnect:
                    self._set_connection_state(ConnectionState.RECONNECTING)
                    self._task_manager.create_background_task(self._reconnect_loop())
                else:
                    self._set_connection_state(ConnectionState.ABNORMAL_CLOSURE)
