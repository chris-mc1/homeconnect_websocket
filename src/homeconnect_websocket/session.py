from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from base64 import urlsafe_b64encode
from json import JSONDecodeError
from typing import TYPE_CHECKING

import aiohttp
from Crypto.Random import get_random_bytes

from .const import (
    DEFAULT_HANDSHAKE_TIMEOUT,
    DEFAULT_SEND_TIMEOUT,
    MAX_CONNECT_TIMEOUT,
    TIMEOUT_INCREASE_FACTOR,
)
from .errors import CodeResponsError, NotConnectedError
from .hc_socket import AesSocket, HCSocket, TlsSocket
from .message import Action, Message, load_message

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


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
    _response_messages: dict[int, Message]
    _response_events: dict[int, asyncio.Event]
    _send_lock: asyncio.Lock
    _socket: HCSocket = None
    _recv_loop_event: asyncio.Event
    _connected: bool = False
    _recv_task: asyncio.Task = None
    _handshake_task: asyncio.Task = None
    _tasks: set[asyncio.Task]
    _ext_message_handler: Callable[[Message], None | Awaitable[None]] | None = None

    def __init__(  # noqa: PLR0913
        self,
        host: str,
        app_name: str,
        app_id: str,
        psk64: str,
        iv64: str | None = None,
        session: aiohttp.ClientSession | None = None,
        logger: logging.Logger | None = None,
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
        session (Optional[aiohttp.ClientSession]): ClientSession
        logger (Optional[Logger]): Logger

        """
        self._host = host
        self._psk64 = psk64
        self._iv64 = iv64
        self._device_info = {
            "deviceType": "Application",
            "deviceName": app_name,
            "deviceID": app_id,
        }

        self._recv_loop_event = asyncio.Event()
        self.handshake = True
        self._response_messages = {}
        self._response_events = {}
        self._response_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self.service_versions = {}
        self._tasks = set()
        self._retry_count = 0

        if logger is None:
            self._logger = logging.getLogger(__name__)
        else:
            self._logger = logger.getChild("session")

        # create socket
        if self._iv64:
            self._logger.debug("Got iv64, using AES socket")
            self._socket = AesSocket(
                self._host, self._psk64, self._iv64, session, logger
            )
        elif self._psk64:
            self._logger.debug("No iv64, using TLS socket")
            self._socket = TlsSocket(self._host, self._psk64, session, logger)
        else:  # For Testing
            self._logger.warning("Using unencrypted socket")
            self._socket = HCSocket(self._host, session, logger)

    @property
    def connected(self) -> bool:
        """Is connected."""
        if self._socket:
            return self._connected and not self._socket.closed
        return False

    async def connect(
        self,
        message_handler: Callable[[Message], Awaitable[None]],
        timeout: int = DEFAULT_HANDSHAKE_TIMEOUT,  # noqa: ASYNC109
    ) -> None:
        """
        Open Connection with Appliance.

        Args:
        ----
        message_handler (Callable[[Message], Awaitable[None]]): called for each message
        timeout (int): timeout (Default: 60).

        """
        self._logger.info("Connecting to %s", self._host)
        self._ext_message_handler = message_handler
        await self._reset()

        try:
            await self._socket.connect()
            self._recv_task = asyncio.create_task(self._recv_loop())
            self._recv_task.add_done_callback(self._recv_loop_done_callback)
            await asyncio.wait_for(self._recv_loop_event.wait(), timeout)
            if not self._connected:
                # loop event received, but not connected
                if self._recv_task.done():
                    # loop exited
                    self._logger.error("Receive loop exited unexpectedly")
                elif self._handshake_task.done():
                    # loop running, handshake eexited
                    if task_exc := self._handshake_task.exception():
                        self._logger.exception("Handshake Exception", exc_info=task_exc)
                        raise task_exc
                    self._logger.error("Handshake exited unexpectedly")
                await self.close()

        except (aiohttp.ClientConnectionError, aiohttp.ClientConnectorSSLError):
            self._logger.exception("Error connecting to Appliance")
            raise
        except TimeoutError:
            if self._recv_task.cancel():
                with contextlib.suppress(asyncio.CancelledError):
                    await self._recv_task
            if self._handshake_task.cancel():
                with contextlib.suppress(asyncio.CancelledError):
                    await self._handshake_task
            self._logger.error("Connection Error")  # noqa: TRY400
            raise

    async def _reset(self) -> None:
        """Rest connction state."""
        self.service_versions.clear()
        self._recv_loop_event.clear()
        self._connected = False
        self._response_messages.clear()
        # Set all response events
        async with self._response_lock:
            for event in self._response_events.values():
                event.set()
            self._response_events.clear()

    async def _recv_loop(self) -> None:
        while self._socket:
            try:
                if self._socket.closed:
                    self._logger.debug(
                        "Socket closed with code %s, opening",
                        self._socket._websocket.close_code,  # noqa: SLF001
                        exc_info=self._socket._websocket.exception(),  # noqa: SLF001
                    )
                    await self._reset()
                    await self._socket.connect()
                async for message in self._socket:
                    # recv messages
                    message_obj = load_message(message)
                    await self._message_handler(message_obj)
            except (aiohttp.ClientConnectionError, aiohttp.ServerTimeoutError) as ex:
                self._logger.warning(ex)
                timeout = TIMEOUT_INCREASE_FACTOR**self._retry_count
                self._retry_count += 1
                await asyncio.sleep(min(timeout, MAX_CONNECT_TIMEOUT))
            except (JSONDecodeError, KeyError):
                self._logger.warning("Can't decode message: %s", message)
            except asyncio.CancelledError:
                self._logger.debug("Receive loop cancelled")
                raise
            except Exception:
                self._logger.exception("Receive loop Exception")

    async def _message_handler(self, message: Message) -> None:
        """Handle recived message."""
        if message.resource == "/ei/initialValues":
            # connection reset/reconncted
            if self._recv_loop_event.is_set():
                self._logger.info("Got init message while connected, resetting")
                await self._reset()
            # set new sID, msgID
            self._sid = message.sid
            self._last_msg_id = message.data[0]["edMsgID"]
            if self.handshake:
                # start handshake
                self._logger.info("Got init message, beginning handshake")
                self._handshake_task = asyncio.create_task(self._handshake(message))
                self._handshake_task.add_done_callback(self._recv_loop_done_callback)
            else:
                self._logger.info("Connected, no handshake")
                self._connected = True
                self._recv_loop_event.set()
                self._retry_count = 0
                await self._call_ext_message_handler(message)

        elif message.action == Action.RESPONSE:
            try:
                async with self._response_lock:
                    if self._response_events[message.msg_id].is_set():
                        # should never happen
                        self._logger.warning(
                            "Response for Msg ID %s was received more then once",
                            message.msg_id,
                        )
                    else:
                        self._response_messages[message.msg_id] = message
                        self._response_events[message.msg_id].set()
            except KeyError:
                self._logger.debug(
                    "Received response for unkown Msg ID %s", message.msg_id
                )

        else:
            # call external message handler
            await self._call_ext_message_handler(message)

    async def _call_ext_message_handler(self, message: Message) -> None:
        """Call the external message handler."""
        task = asyncio.create_task(self._ext_message_handler(message))
        self._tasks.add(task)
        task.add_done_callback(self._done_callback)

    def _done_callback(self, task: asyncio.Task) -> None:
        if exc := task.exception():
            self._logger.exception("Exception in Session callback", exc_info=exc)
        self._tasks.discard(task)

    def _recv_loop_done_callback(self, _: asyncio.Task) -> None:
        self._recv_loop_event.set()

    async def _handshake(self, message_init: Message) -> None:
        try:
            # responde to init message
            await self.send(message_init.responde(self._device_info))

            # request available services
            message_services = Message(resource="/ci/services", version=1)
            response_services = await self.send_sync(message_services)
            self.set_service_versions(response_services)
            await self._call_ext_message_handler(response_services)

            token = urlsafe_b64encode(get_random_bytes(32)).decode("UTF-8")
            token = re.sub(r"=", "", token)
            message_authentication = Message(
                resource="/ci/authentication", data={"nonce": token}
            )
            await self.send(message_authentication)

            # request device info
            with contextlib.suppress(CodeResponsError):
                message_info = Message(resource="/ci/info")
                response_info = await self.send_sync(message_info)
                await self._call_ext_message_handler(response_info)

            with contextlib.suppress(CodeResponsError):
                message_info = Message(resource="/iz/info")
                response_info = await self.send_sync(message_info)
                await self._call_ext_message_handler(response_info)

            # report device ready
            message_ready = Message(resource="/ei/deviceReady", action=Action.NOTIFY)
            await self.send(message_ready)

            message_ready = Message(resource="/ni/info")
            await self.send(message_ready)

            # request mandatory values
            message_mandatory_values = Message(resource="/ro/allMandatoryValues")
            response_mandatory_values = await self.send_sync(message_mandatory_values)
            await self._call_ext_message_handler(response_mandatory_values)

            # request values
            with contextlib.suppress(CodeResponsError):
                message_values = Message(resource="/ro/values")
                response_values = await self.send_sync(message_values)
                await self._call_ext_message_handler(response_values)

            # request description changes
            message_description_changes = Message(resource="/ro/allDescriptionChanges")
            response_description_changes = await self.send_sync(
                message_description_changes
            )
            await self._call_ext_message_handler(response_description_changes)

            # handshake completed
            self._connected = True
            self._recv_loop_event.set()
            self._retry_count = 0
            self._logger.info("Handshake completed")
        except asyncio.CancelledError:
            self._logger.exception("Handshake cancelled")
            raise
        except CodeResponsError:
            self._logger.exception("Received Code response during Handshake")
            raise
        except Exception:
            self._logger.exception("Unknown Exception during Handshake")
            raise

    async def close(self) -> None:
        """Close connction."""
        self._logger.info("Closing connection to %s", self._host)
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
        self._logger.debug("Setting Service versions")
        if message.data is not None:
            for service in message.data:
                self.service_versions[service["service"]] = service["version"]
        else:
            msg = "No Data in Message"
            raise ValueError(msg)

    async def send_sync(
        self,
        send_message: Message,
        timeout: float = DEFAULT_SEND_TIMEOUT,  # noqa: ASYNC109
    ) -> Message | None:
        """Send message to Appliance, returns Response Message."""
        response_message: Message | None = None

        async with self._send_lock:
            self._set_message_info(send_message)

            response_event = asyncio.Event()
            async with self._response_lock:
                self._response_events[send_message.msg_id] = response_event

            # send message
            await self._socket.send(send_message.dump())

        try:
            await asyncio.wait_for(response_event.wait(), timeout)
            response_message = self._response_messages[send_message.msg_id]
        except TimeoutError:
            self._logger.warning("Timeout for message %s", send_message.msg_id)
            raise
        except KeyError:
            if not self._connected:
                raise NotConnectedError from None
        finally:
            async with self._response_lock:
                with contextlib.suppress(KeyError):
                    self._response_events.pop(send_message.msg_id)

        if response_message.code:
            self._logger.warning(
                "Received Code %s for Message %s, resource: %s",
                response_message.code,
                send_message.msg_id,
                response_message.resource,
            )
            raise CodeResponsError(response_message.code, response_message.resource)
        return response_message

    async def send(self, message: Message) -> None:
        """Send message to Appliance, returns immediately."""
        async with self._send_lock:
            self._set_message_info(message)
            await self._socket.send(message.dump())
