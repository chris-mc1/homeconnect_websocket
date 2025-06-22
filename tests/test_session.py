from __future__ import annotations

from typing import (
    TYPE_CHECKING,
)
from unittest.mock import ANY, AsyncMock

import aiohttp
import pytest
from homeconnect_websocket.message import Action, Message
from homeconnect_websocket.session import HCSession
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
    session = HCSession(
        appliance_server.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=appliance_server.psk64,
    )
    session.handshake = False
    message_handler = AsyncMock()

    assert not session.connected
    await session.connect(message_handler)
    assert session.connected

    await session.close()
    assert not session.connected

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
    session = HCSession(
        appliance_server.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=appliance_server.psk64,
        iv64=appliance_server.iv64,
    )
    session.handshake = False
    message_handler = AsyncMock()

    assert not session.connected
    await session.connect(message_handler)
    assert session.connected

    await session.close()
    assert not session.connected

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
    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
    )
    message_handler = AsyncMock()
    await session.connect(message_handler)
    await session.close()

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

    assert appliance.messages[5] == Message(
        sid=10,
        msg_id=34,
        resource="/ro/allDescriptionChanges",
        version=1,
        action=Action.GET,
    )

    assert appliance.messages[6] == Message(
        sid=10,
        msg_id=35,
        resource="/ro/allMandatoryValues",
        version=1,
        action=Action.GET,
    )


@pytest.mark.asyncio
async def test_session_handshake_2(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session Handshake with Message set 2."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_2)
    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
    )
    message_handler = AsyncMock()
    await session.connect(message_handler)
    await session.close()

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

    assert appliance.messages[4] == Message(
        sid=10,
        msg_id=33,
        resource="/ro/allDescriptionChanges",
        version=1,
        action=Action.GET,
    )

    assert appliance.messages[5] == Message(
        sid=10,
        msg_id=34,
        resource="/ro/allMandatoryValues",
        version=1,
        action=Action.GET,
    )


@pytest.mark.asyncio
async def test_session_handshake_3(
    appliance_server: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test Session Handshake with Message set 2."""
    appliance = await appliance_server(DEVICE_MESSAGE_SET_3)
    session = HCSession(
        appliance.host,
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
    )
    message_handler = AsyncMock()
    await session.connect(message_handler)
    await session.close()

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

    assert appliance.messages[6] == Message(
        sid=10,
        msg_id=35,
        resource="/ro/allDescriptionChanges",
        version=1,
        action=Action.GET,
    )

    assert appliance.messages[7] == Message(
        sid=10,
        msg_id=36,
        resource="/ro/allMandatoryValues",
        version=1,
        action=Action.GET,
    )


@pytest.mark.asyncio
async def test_session_connect_failed() -> None:
    """Test Session connction failing."""
    session = HCSession(
        "127.0.0.1",
        app_name=TEST_APP_NAME,
        app_id=TEST_APP_ID,
        psk64=None,
    )
    with pytest.raises(aiohttp.ClientConnectionError):
        await session.connect(AsyncMock())
    assert not session.connected
