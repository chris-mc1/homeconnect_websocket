from __future__ import annotations

import json
from base64 import urlsafe_b64encode
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest
from aiohttp import WSMessage, WSMsgType
from Crypto.Random import get_random_bytes
from homeconnect_websocket.hc_socket import AesSocket, TlsSocket
from homeconnect_websocket.testutils import TEST_IV64, TEST_PSK64

from const import CLIENT_MESSAGE_ID, DEVICE_MESSAGE_SET_1, SERVER_MESSAGE_ID, SESSION_ID
from utils import AesServerEncryption, ApplianceServer, ApplianceServerAes

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


@pytest.mark.asyncio
async def test_connect_tls(
    appliance_server_tls: Callable[..., Awaitable[ApplianceServer]],
) -> None:
    """Test TLS Socket connect."""
    appliance_server = await appliance_server_tls(DEVICE_MESSAGE_SET_1)
    socket = TlsSocket(appliance_server.host, psk64=appliance_server.psk64)
    assert socket.closed
    await socket.connect()

    assert not socket.closed
    async for msg in socket:
        assert json.loads(msg) == {
            "sID": SESSION_ID,
            "msgID": SERVER_MESSAGE_ID,
            "resource": "/ei/initialValues",
            "version": 2,
            "action": "POST",
            "data": [{"edMsgID": CLIENT_MESSAGE_ID}],
        }
        break
    assert not socket.closed

    await socket.send("Pong")
    await socket.close()
    assert socket.closed

    assert appliance_server.messages[0] == "Pong"


@pytest.mark.asyncio
async def test_connect_aes(
    appliance_server_aes: Callable[..., Awaitable[ApplianceServerAes]],
) -> None:
    """Test AES Socket connect."""
    appliance_server = await appliance_server_aes(DEVICE_MESSAGE_SET_1)
    socket = AesSocket(
        host=appliance_server.host,
        psk64=appliance_server.psk64,
        iv64=appliance_server.iv64,
    )
    assert socket.closed
    await socket.connect()

    assert not socket.closed
    async for msg in socket:
        assert json.loads(msg) == {
            "sID": SESSION_ID,
            "msgID": SERVER_MESSAGE_ID,
            "resource": "/ei/initialValues",
            "version": 2,
            "action": "POST",
            "data": [{"edMsgID": CLIENT_MESSAGE_ID}],
        }
        break
    assert not socket.closed

    await socket.send("Pong")
    await socket.close()
    assert socket.closed

    assert appliance_server.messages[0] == "Pong"


@pytest.mark.asyncio
async def test_ase_padding(
    appliance_server_aes: Callable[..., Awaitable[ApplianceServerAes]],
) -> None:
    """Test AES Socket padding."""
    appliance_server = await appliance_server_aes(DEVICE_MESSAGE_SET_1)
    socket = AesSocket(
        host=appliance_server.host,
        psk64=appliance_server.psk64,
        iv64=appliance_server.iv64,
    )
    await socket.connect()

    messages = [  # len/padding
        "",  # 0/16
        "a",  # 1/15
        "ab",  # 2/14
        "abcdefghijklmno",  # 15/17
        "abcdefghijklmnop",  # 16/16
    ]
    for msg in messages:
        await socket.send(msg)
    await socket.close()

    assert appliance_server.messages == messages


@pytest.mark.asyncio
async def test_ase_padding_error() -> None:
    """Test AES Socket with padding error."""
    encryption = AesServerEncryption(psk64=TEST_PSK64, iv64=TEST_IV64)

    socket = AesSocket("", psk64=TEST_PSK64, iv64=TEST_IV64)
    socket._session = AsyncMock()
    await socket.connect()

    clear_msg = get_random_bytes(32)
    pad_len = 16 - (len(clear_msg) % 16)
    if pad_len == 1:
        pad_len += 16
    clear_msg = clear_msg + b"\x00" + get_random_bytes(pad_len - 2) + bytearray([64])

    enc_msg = encryption.aes_encrypt.encrypt(clear_msg)
    enc_msg += encryption.hmac_encrypt(enc_msg)

    msg = WSMessage(type=WSMsgType.BINARY, data=enc_msg, extra=None)
    with pytest.raises(ValueError, match="Padding Error"):
        await socket._receive(msg)


@pytest.mark.asyncio
async def test_ase_wrong_msg_type() -> None:
    """Test AES Socket with Message not of type binary."""
    psk64 = urlsafe_b64encode(get_random_bytes(32)).decode()
    iv64 = urlsafe_b64encode(get_random_bytes(16)).decode()
    socket = AesSocket("", psk64=psk64, iv64=iv64)

    msg = WSMessage(type=WSMsgType.PING, data=None, extra=None)
    with pytest.raises(ValueError, match="Message not of Type binary"):
        await socket._receive(msg)


@pytest.mark.asyncio
async def test_ase_msg_to_short() -> None:
    """Test AES Socket with Message to short."""
    encryption = AesServerEncryption(psk64=TEST_PSK64, iv64=TEST_IV64)
    encryption.reset()

    msg_data = encryption.encrypt(get_random_bytes(2))

    socket = AesSocket("", psk64=TEST_PSK64, iv64=TEST_IV64)
    socket._session = AsyncMock()
    await socket.connect()

    msg = WSMessage(type=WSMsgType.BINARY, data=msg_data[:-16], extra=None)
    with pytest.raises(ValueError, match="Message to short"):
        await socket._receive(msg)


@pytest.mark.asyncio
async def test_ase_msg_unaligned() -> None:
    """Test AES Socket with unaligned Message."""
    encryption = AesServerEncryption(psk64=TEST_PSK64, iv64=TEST_IV64)
    encryption.reset()

    msg_data = encryption.encrypt(get_random_bytes(32))
    msg = WSMessage(type=WSMsgType.BINARY, data=msg_data[:-1], extra=None)

    socket = AesSocket("", psk64=TEST_PSK64, iv64=TEST_IV64)
    socket._session = AsyncMock()
    await socket.connect()

    with pytest.raises(ValueError, match="Unaligned Message"):
        await socket._receive(msg)


@pytest.mark.asyncio
async def test_ase_hmac_failure() -> None:
    """Test AES Socket with HMAC failure."""
    encryption = AesServerEncryption(psk64=TEST_PSK64, iv64=TEST_IV64)
    encryption.reset()

    socket = AesSocket("", psk64=TEST_PSK64, iv64=TEST_IV64)
    socket._session = AsyncMock()
    await socket.connect()

    msg_data = encryption.encrypt(get_random_bytes(32))
    msg_data = msg_data[:-16] + get_random_bytes(16)

    msg = WSMessage(type=WSMsgType.BINARY, data=msg_data, extra=None)
    with pytest.raises(ValueError, match="HMAC Failure"):
        await socket._receive(msg)
