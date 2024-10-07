from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import aiohttp

from .const import DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_SEND_TIMEOUT
from .exceptions import CodeResponsError
from .message import Action, Message, load_message
from .socket import AesSocket, HCSocket, TlsSocket

if TYPE_CHECKING:
    from collections.abc import Callable

_LOGGER = logging.getLogger(__name__)


class HCSession:
    """HomeConnect Session."""

    handshake: bool
    """Automatic Handshake"""
    service_versions: dict
    _sid: int | None = None
    _last_msg_id: int | None = None
    _host: str
    _psk64: str
    _iv64: str | None
    _device_info: dict
    _msg_queues: dict[int, asyncio.Queue]
    _msg_events: dict[int, asyncio.Event]
    _socket: HCSocket = None
    _connected: asyncio.Event
    _recv_task: asyncio.Task = None
    _tasks: set[asyncio.Task]
    _ext_message_handler: Callable[[Message], None] | None = None

    def __init__(
        self,
        host: str,
        app_name: str,
        device_id: str,
        psk64: str,
        iv64: str | None = None,
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

        """
        self._host = host
        self._psk64 = psk64
        self._iv64 = iv64
        self._device_info = {
            "deviceType": "Application",
            "deviceName": app_name,
            "deviceID": device_id,
        }
        self._connected = asyncio.Event()
        self.handshake = True
        self._msg_queues = {}
        self._msg_events = {}
        self.service_versions = {}
        self._tasks = set()

    @property
    def connected(self) -> bool:
        """Is connected."""
        if self._socket:
            return self._connected.is_set() and not self._socket.closed
        return False

    async def connect(
        self,
        message_handler: Callable[[Message], None],
        timeout: int = DEFAULT_HANDSHAKE_TIMEOUT,
    ) -> None:
        """
        Open Connection with Appliance.

        Args:
        ----
        message_handler (Callable): called for each message
        timeout (int): timeout (Default: 60).

        """
        _LOGGER.info("Connecting to %s", self._host)
        self._ext_message_handler = message_handler
        self._reset()

        # create socket
        if self._iv64:
            _LOGGER.debug("Got iv64, using AES socket")
            self._socket = AesSocket(self._host, self._psk64, self._iv64)
        elif self._psk64:
            _LOGGER.debug("No iv64, using TLS socket")
            self._socket = TlsSocket(self._host, self._psk64)
        else:
            _LOGGER.warning("Using unencrypted socket")
            self._socket = HCSocket(self._host)
        try:
            await self._socket.connect()
            self._recv_task = asyncio.create_task(self._recv_loop())
            await asyncio.wait_for(self._connected.wait(), timeout)
        except (aiohttp.ClientConnectionError, aiohttp.ClientConnectorSSLError):
            _LOGGER.exception("Error connecting to Appliance")
            raise
        except TimeoutError as ex:
            if self._recv_task.done():
                self._recv_task.cancel()
            task_exc = self._recv_task.exception()
            if task_exc:
                _LOGGER.exception("Handshake Exception")
                raise task_exc from ex

            _LOGGER.exception("Handshake Timeout")
            raise

    def _reset(self) -> None:
        """Rest connction state."""
        self.service_versions.clear()
        self._msg_queues.clear()
        self._msg_events.clear()
        self._connected.clear()

    async def _recv_loop(self) -> None:
        while self._socket:
            try:
                if self._socket.closed:
                    _LOGGER.debug("Socket closed, opening")
                    self._reset()
                    await self._socket.connect()
                async for message in self._socket:
                    # recv messages
                    message_obj = load_message(message)
                    await self._message_handler(message_obj)
            except aiohttp.ClientConnectionError as ex:
                _LOGGER.warning(ex)
                raise
            except asyncio.CancelledError:
                raise

    async def _message_handler(self, message: Message) -> None:
        """Handle recived message."""
        if message.resource == "/ei/initialValues":
            # connection reset/reconncted
            if self._connected.is_set():
                _LOGGER.info("Got init message while connected, resetting")
                self._reset()
            # set new sID, msgID
            self._sid = message.sid
            self._last_msg_id = message.data[0]["edMsgID"]
            if self.handshake:
                # start handshake
                _LOGGER.info("Got init message, beginning handshake")
                task = asyncio.create_task(self._handshake(message))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            else:
                _LOGGER.info("Connected, no handshake")
                self._connected.set()
                await self._call_ext_message_handler(message)

        elif message.msg_id in self._msg_events:
            try:
                self._msg_queues[message.msg_id].put_nowait(message)
                self._msg_events[message.msg_id].set()
            except asyncio.QueueFull:
                # should never happen
                _LOGGER.warning("Msg ID %s was received more then once", message.msg_id)
        else:
            # call external message handler
            await self._call_ext_message_handler(message)

    async def _call_ext_message_handler(self, message: Message) -> None:
        """Call the external message handler."""
        task = asyncio.create_task(self._ext_message_handler(message))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handshake(self, message_init: Message) -> None:
        try:
            # responde to init message
            await self.send(message_init.responde(self._device_info))

            # request available services
            message_services = Message(resource="/ci/services", version=1)
            response_services = await self.send_sync(message_services)
            self.set_service_versions(response_services)
            await self._call_ext_message_handler(response_services)

            # request device info
            message_info = Message(resource="/iz/info")
            response_info = await self.send_sync(message_info)
            await self._call_ext_message_handler(response_info)

            # report device ready
            message_ready = Message(resource="/ei/deviceReady", action=Action.NOTIFY)
            await self.send(message_ready)

            # request description changes
            message_description_changes = Message(resource="/ro/allDescriptionChanges")
            response_description_changes = await self.send_sync(
                message_description_changes
            )
            await self._call_ext_message_handler(response_description_changes)

            # request mandatory values
            message_mandatory_values = Message(resource="/ro/allMandatoryValues")
            response_mandatory_values = await self.send_sync(message_mandatory_values)
            await self._call_ext_message_handler(response_mandatory_values)

            # handshake completed
            self._connected.set()
            _LOGGER.info("Handshake completed")
        except asyncio.CancelledError:
            _LOGGER.exception("Handshake cancelled")
        except CodeResponsError:
            _LOGGER.exception("Received Code respons during Handshake")

    async def close(self) -> None:
        """Close connction."""
        _LOGGER.info("Closing connection to %s", self._host)
        if self._recv_task:
            self._recv_task.cancel()
        if self._socket:
            await self._socket.close()
        self._socket = None

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

    def set_service_versions(self, message: Message) -> None:
        """Set service versions from a '/ci/services' Response."""
        _LOGGER.debug("Setting Service versions")
        if message.data is not None:
            for service in message.data:
                self.service_versions[service["service"]] = service["version"]
        else:
            msg = "No Data in Message"
            raise ValueError(msg)

    async def send_sync(
        self, send_message: Message, timeout: float = DEFAULT_SEND_TIMEOUT
    ) -> Message | None:
        """Send message to Appliance, returns Response Message."""
        response_message: Message | None = None

        self._set_message_info(send_message)

        # add queue for response
        response_queue = asyncio.Queue(maxsize=1)
        self._msg_queues[send_message.msg_id] = response_queue

        response_event = asyncio.Event()
        self._msg_events[send_message.msg_id] = response_event

        # send message
        await self._socket.send(send_message.dump())

        try:
            await asyncio.wait_for(response_event.wait(), timeout)
            response_message = await response_queue.get()
            response_queue.task_done()

        except TimeoutError:
            _LOGGER.warning("Timeout for message %s", send_message.msg_id)
            raise

        finally:
            self._msg_queues.pop(send_message.msg_id)
            self._msg_events.pop(send_message.msg_id)

        if response_message.code:
            _LOGGER.warning(
                "Received Code %s for Message %s",
                response_message.code,
                send_message.msg_id,
            )
            raise CodeResponsError(response_message.code)
        return response_message

    async def send(self, message: Message) -> None:
        """Send message to Appliance, returns immediately."""
        self._set_message_info(message)
        # Make sure socket is open
        await self._socket.send(message.dump())
