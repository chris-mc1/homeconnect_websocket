from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import ANY, AsyncMock, call

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer
from homeconnect_websocket import (
    AllreadyConnectedError,
    AuthenticationError,
    ConnectionFailedError,
    ConnectionState,
    HCSession,
    HCSessionReconnect,
)
from homeconnect_websocket import session as session_module
from homeconnect_websocket.message import Action, Message
from homeconnect_websocket.task_manager import TaskManager
from homeconnect_websocket.testutils import TEST_APP_ID, TEST_APP_NAME

from const import (
    CLIENT_MESSAGE_ID,
    DEVICE_MESSAGE_SET_1,
    DEVICE_MESSAGE_SET_2,
    DEVICE_MESSAGE_SET_3,
    SERVER_MESSAGE_ID,
    SESSION_ID,
)
from utils import ApplianceServer

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

    from tests.utils import ApplianceServerAes


@pytest.mark.asyncio
async def test_session_connect_tls(
    appliance_server_tls: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session connection."""
    appliance_server = await appliance_server_tls(DEVICE_MESSAGE_SET_1)
    connection_callback = AsyncMock()
    message_handler = AsyncMock()

    session = HCSession(
        appliance_server.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=appliance_server.psk64,
        message_handler=message_handler,
        handshake=False,
        connection_state_callback=connection_callback,
    )

    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED
    await session.connect()
    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await session.close()
    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )
    message_handler.assert_called_once_with(
        Message(
            sid=SESSION_ID,
            msg_id=SERVER_MESSAGE_ID,
            resource="/ei/initialValues",
            version=2,
            action=Action.POST,
            data=[{"edMsgID": CLIENT_MESSAGE_ID}],
            code=None,
        )
    )


@pytest.mark.asyncio
async def test_session_connect_aes(
    appliance_server_aes: Callable[..., Awaitable[ApplianceServerAes]],
) -> None:
    """Test Session connection failing."""
    appliance_server = await appliance_server_aes(DEVICE_MESSAGE_SET_1)
    connection_callback = AsyncMock()
    message_handler = AsyncMock()

    session = HCSession(
        appliance_server.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=appliance_server.psk64,
        iv64=appliance_server.iv64,
        message_handler=message_handler,
        handshake=False,
        connection_state_callback=connection_callback,
    )

    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED
    await session.connect()
    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await session.close()
    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )
    message_handler.assert_called_once_with(
        Message(
            sid=SESSION_ID,
            msg_id=SERVER_MESSAGE_ID,
            resource="/ei/initialValues",
            version=2,
            action=Action.POST,
            data=[{"edMsgID": CLIENT_MESSAGE_ID}],
            code=None,
        )
    )


@pytest.mark.asyncio
async def test_session_handshake_1(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session Handshake with Message set 1."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_1)
    connection_callback = AsyncMock()
    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        connection_state_callback=connection_callback,
    )

    await session.connect()
    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.HANDSHAKE),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )

    assert appliance.messages[0] == Message(
        sid=10,
        msg_id=20,
        resource="/ei/initialValues",
        version=2,
        action=Action.RESPONSE,
        data=[
            {
                "deviceType": "Application",
                "deviceName": "Test Device",
                "deviceID": "c6683b15",
            }
        ],
    )
    assert list(appliance.messages[0].data[0].items()) == list(
        {
            "deviceType": "Application",
            "deviceName": "Test Device",
            "deviceID": "c6683b15",
        }.items()
    )

    assert appliance.messages[1] == Message(
        sid=10, msg_id=30, resource="/ci/services", version=1, action=Action.GET
    )

    assert appliance.messages[2] == Message(
        sid=10, msg_id=31, resource="/iz/info", version=1, action=Action.GET
    )

    assert appliance.messages[3] == Message(
        sid=10, msg_id=32, resource="/ei/deviceReady", version=2, action=Action.NOTIFY
    )

    assert appliance.messages[4] == Message(
        sid=10, msg_id=33, resource="/ni/info", version=1, action=Action.GET
    )


@pytest.mark.asyncio
async def test_session_handshake_2(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session Handshake with Message set 2."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_2)
    connection_callback = AsyncMock()

    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        connection_state_callback=connection_callback,
    )

    await session.connect()
    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.HANDSHAKE),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )

    assert appliance.messages[0] == Message(
        sid=10,
        msg_id=20,
        resource="/ei/initialValues",
        version=1,
        action=Action.RESPONSE,
        data=[
            {
                "deviceType": 2,
                "deviceName": "Test Device",
                "deviceID": "c6683b15",
            }
        ],
    )
    assert list(appliance.messages[0].data[0].items()) == list(
        {
            "deviceType": 2,
            "deviceName": "Test Device",
            "deviceID": "c6683b15",
        }.items()
    )

    assert appliance.messages[1] == Message(
        sid=10, msg_id=30, resource="/ci/services", version=1, action=Action.GET
    )

    assert appliance.messages[2] == Message(
        sid=10,
        msg_id=31,
        resource="/ci/authentication",
        version=1,
        action=Action.GET,
        data=[{"nonce": ANY}],
    )

    assert appliance.messages[3] == Message(
        sid=10, msg_id=32, resource="/ci/info", version=1, action=Action.GET
    )


@pytest.mark.asyncio
async def test_session_handshake_3(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session Handshake with Message set 2."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_3)
    connection_callback = AsyncMock()

    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        connection_state_callback=connection_callback,
    )

    await session.connect()
    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.HANDSHAKE),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )

    assert appliance.messages[0] == Message(
        sid=10,
        msg_id=20,
        resource="/ei/initialValues",
        version=2,
        action=Action.RESPONSE,
        data=[
            {
                "deviceType": "Application",
                "deviceName": "Test Device",
                "deviceID": "c6683b15",
            }
        ],
    )
    assert list(appliance.messages[0].data[0].items()) == list(
        {
            "deviceType": "Application",
            "deviceName": "Test Device",
            "deviceID": "c6683b15",
        }.items()
    )

    assert appliance.messages[1] == Message(
        sid=10, msg_id=30, resource="/ci/services", version=1, action=Action.GET
    )

    assert appliance.messages[2] == Message(
        sid=10,
        msg_id=31,
        resource="/ci/authentication",
        version=2,
        action=Action.GET,
        data=[{"nonce": ANY}],
    )

    assert appliance.messages[3] == Message(
        sid=10, msg_id=32, resource="/ci/info", version=2, action=Action.GET
    )

    assert appliance.messages[4] == Message(
        sid=10, msg_id=33, resource="/ei/deviceReady", version=2, action=Action.NOTIFY
    )

    assert appliance.messages[5] == Message(
        sid=10, msg_id=34, resource="/ni/info", version=1, action=Action.GET
    )


@pytest.mark.asyncio
async def test_session_connect_failed() -> None:
    """Test Session connction failing."""
    connection_callback = AsyncMock()

    session = HCSession(
        "127.0.0.1",
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        connection_state_callback=connection_callback,
    )

    with pytest.raises(ConnectionFailedError):
        await session.connect()

    assert not session.connected
    assert session.connection_state == ConnectionState.ABNORMAL_CLOSURE

    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.ABNORMAL_CLOSURE),
        ]
    )


@pytest.mark.asyncio
async def test_session_connect_http_error() -> None:
    """Test Session connection refused with HTTP error (e.g. 503 while switched off)."""
    app = web.Application()
    app.add_routes([web.get("/homeconnect", lambda _: web.Response(status=503))])
    test_server = TestServer(app, port=80)
    await test_server.start_server()
    connection_callback = AsyncMock()

    session = HCSession(
        test_server.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        connection_state_callback=connection_callback,
    )

    with pytest.raises(ConnectionFailedError, match="503"):
        await session.connect()

    assert not session.connected
    assert session.connection_state == ConnectionState.ABNORMAL_CLOSURE

    await session.close()
    await test_server.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.ABNORMAL_CLOSURE),
        ]
    )


@pytest.mark.asyncio
async def test_session_auth_error_tls(
    appliance_server_tls: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session connction failing."""
    appliance_server = await appliance_server_tls(DEVICE_MESSAGE_SET_1)

    session = HCSession(
        appliance_server.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64="DucPCx_bN2d0fP07ptJDas_umP6YK63aAsrgl7kUWZk",
    )

    with pytest.raises(AuthenticationError):
        await session.connect()

    await session.close()


@pytest.mark.asyncio
async def test_session_auth_error_aes(
    appliance_server_aes: Callable[..., Awaitable[ApplianceServerAes]],
) -> None:
    """Test Session connction failing."""
    appliance_server = await appliance_server_aes(DEVICE_MESSAGE_SET_1)

    session = HCSession(
        appliance_server.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64="DucPCx_bN2d0fP07ptJDas_umP6YK63aAsrgl7kUWZk",
        iv64="8sJeiM2Hofw3XA7M1WB91E==",
    )

    with pytest.raises(AuthenticationError):
        await session.connect()

    await session.close()


@pytest.mark.asyncio
async def test_session_allready_connected(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session connction failing."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_3)
    connection_callback = AsyncMock()

    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        handshake=False,
        connection_state_callback=connection_callback,
    )

    await session.connect()
    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    with pytest.raises(AllreadyConnectedError):
        await session.connect()

    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )


@pytest.mark.asyncio
async def test_session_connection_closed(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session connection."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_3)
    connection_callback = AsyncMock()

    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        handshake=False,
        connection_state_callback=connection_callback,
    )

    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED

    await session.connect()

    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await appliance.ws.close()

    await asyncio.sleep(1)

    assert not session.connected
    assert session.connection_state == ConnectionState.ABNORMAL_CLOSURE

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.ABNORMAL_CLOSURE),
        ]
    )

    await session.close()


@pytest.mark.asyncio
async def test_session_reconnect_manual(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session connection."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_1)
    connection_callback = AsyncMock()

    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        handshake=False,
        connection_state_callback=connection_callback,
    )

    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED
    await session.connect()
    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await appliance.ws.close()

    await asyncio.sleep(1)

    assert not session.connected
    assert session.connection_state == ConnectionState.ABNORMAL_CLOSURE

    await session.connect()

    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.ABNORMAL_CLOSURE),
            call(ConnectionState.CONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )


@pytest.mark.asyncio
async def test_session_reconnect_auto(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session connection."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_1)
    connection_callback = AsyncMock()

    session = HCSessionReconnect(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        handshake=False,
        connection_state_callback=connection_callback,
    )

    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED

    await session.connect()

    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await appliance.ws.close()

    await asyncio.sleep(0)

    assert not session.connected
    assert session.connection_state == ConnectionState.RECONNECTING

    await asyncio.sleep(1)

    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.RECONNECTING),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )


@pytest.mark.asyncio
async def test_session_reconnect_auto_handshake(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session connection."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_1)
    connection_callback = AsyncMock()

    session = HCSessionReconnect(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        handshake=True,
        connection_state_callback=connection_callback,
    )

    assert not session.connected
    assert session.connection_state == ConnectionState.CLOSED

    await session.connect()

    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await appliance.ws.close()

    await asyncio.sleep(0)

    assert not session.connected
    assert session.connection_state == ConnectionState.RECONNECTING

    await asyncio.sleep(1)

    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED

    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.HANDSHAKE),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.RECONNECTING),
            call(ConnectionState.HANDSHAKE),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )


class FlakyApplianceServer(ApplianceServer):
    """Appliance Server failing selected connections."""

    def __init__(self, message_set: dict) -> None:
        """Appliance Server failing selected connections."""
        super().__init__(message_set, None)
        self.connections = 0
        self.invalid_init: set[int] = set()
        self.refuse = False

    async def websocket_handler(self, request: web.Request) -> web.StreamResponse:
        """Answer with 503 while refusing connections."""
        if self.refuse:
            return web.Response(status=503)
        self.connections += 1
        return await super().websocket_handler(request)

    async def init_handler(self) -> None:
        """Send an invalid init message on selected connections."""
        if self.connections in self.invalid_init:
            await self._send("invalid")
            return
        await super().init_handler()


@pytest_asyncio.fixture
async def flaky_appliance_server() -> AsyncGenerator[FlakyApplianceServer]:
    """Appliance Server failing selected connections."""
    appliance = FlakyApplianceServer(DEVICE_MESSAGE_SET_1)
    app = web.Application()
    app.add_routes([web.get("/homeconnect", appliance.websocket_handler)])
    test_server = TestServer(app, port=80)
    await test_server.start_server()
    appliance.host = test_server.host
    yield appliance
    await test_server.close()


@pytest.mark.asyncio
async def test_session_reconnect_handshake_error(
    flaky_appliance_server: FlakyApplianceServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test reconnect continues after a handshake error."""
    monkeypatch.setattr(session_module, "INITIAL_RECONNECT_DELAY", 0.1)
    appliance = flaky_appliance_server
    # First reconnect attempt receives "invalid" as init message
    appliance.invalid_init = {2}
    connection_callback = AsyncMock()

    session = HCSessionReconnect(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        connection_state_callback=connection_callback,
    )
    await session.connect()
    assert session.connected

    await appliance.ws.close()
    await asyncio.sleep(1)

    assert session.connected
    assert session.connection_state == ConnectionState.CONNECTED
    assert appliance.connections == 3

    await session.close()

    connection_callback.assert_has_awaits(
        [
            call(ConnectionState.CONNECTING),
            call(ConnectionState.HANDSHAKE),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.RECONNECTING),
            call(ConnectionState.HANDSHAKE),
            call(ConnectionState.CONNECTED),
            call(ConnectionState.CLOSING),
            call(ConnectionState.CLOSED),
        ]
    )


@pytest.mark.asyncio
async def test_session_close_while_reconnecting(
    flaky_appliance_server: FlakyApplianceServer,
) -> None:
    """Test close doesn't wait for the reconnect delay."""
    appliance = flaky_appliance_server
    task_manager = TaskManager()

    session = HCSessionReconnect(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
        task_manager=task_manager,
    )
    await session.connect()
    assert session.connected

    # Appliance switched off: connection lost, reconnect refused with 503
    appliance.refuse = True
    await appliance.ws.close()
    await asyncio.sleep(0.5)
    assert session.connection_state == ConnectionState.RECONNECTING

    async with asyncio.timeout(1):
        await session.close()
        await task_manager.shutdown()

    assert session.connection_state == ConnectionState.CLOSED
