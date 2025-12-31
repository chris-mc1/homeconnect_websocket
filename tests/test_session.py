from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import ANY, AsyncMock, call

import pytest
from homeconnect_websocket import (
    AllreadyConnectedError,
    ConnectionFailedError,
    ConnectionState,
    HCSession,
    HCSessionReconnect,
)
from homeconnect_websocket.message import Action, Message
from homeconnect_websocket.testutils import TEST_APP_ID, TEST_APP_NAME

from const import (
    CLIENT_MESSAGE_ID,
    DEVICE_MESSAGE_SET_1,
    DEVICE_MESSAGE_SET_2,
    DEVICE_MESSAGE_SET_3,
    SERVER_MESSAGE_ID,
    SESSION_ID,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from tests.utils import ApplianceServerAes

    from utils import ApplianceServer


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
