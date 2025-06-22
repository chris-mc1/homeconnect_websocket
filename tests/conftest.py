from __future__ import annotations

import ssl
from base64 import urlsafe_b64decode
from typing import TYPE_CHECKING

import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer
from homeconnect_websocket.testutils import TEST_IV64, TEST_PSK64

from utils import ApplianceServer, ApplianceServerAes

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

pytest_plugins = ["aiohttp.pytest_plugin", "homeconnect_websocket.testutils"]


@pytest_asyncio.fixture
async def appliance_server() -> AsyncGenerator[
    Callable[..., Awaitable[ApplianceServer]]
]:
    """Appliance Server with TLS."""
    servers: list[TestServer] = []

    async def go(message_set: dict, port: int = 80) -> ApplianceServer:
        appliance = ApplianceServer(message_set, None)

        app = web.Application()
        app.add_routes([web.get("/homeconnect", appliance.websocket_handler)])
        test_server = TestServer(app, port=port)
        await test_server.start_server()
        appliance.host = test_server.host

        servers.append(test_server)
        return appliance

    yield go

    while servers:
        await servers.pop().close()


@pytest_asyncio.fixture
async def appliance_server_tls() -> AsyncGenerator[
    Callable[..., Awaitable[ApplianceServer]]
]:
    """Appliance Server with TLS."""
    servers: list[TestServer] = []

    async def go(
        message_set: dict, psk64: str = TEST_PSK64, port: int = 443
    ) -> ApplianceServer:
        appliance = ApplianceServer(message_set, psk64)

        psk = urlsafe_b64decode(psk64 + "===")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.set_ciphers("ALL")
        ssl_context.check_hostname = False
        ssl_context.set_psk_server_callback(lambda _: psk)

        app = web.Application()
        app.add_routes([web.get("/homeconnect", appliance.websocket_handler)])
        test_server = TestServer(app, port=port)
        await test_server.start_server(ssl=ssl_context)
        appliance.host = test_server.host

        servers.append(test_server)
        return appliance

    yield go

    while servers:
        await servers.pop().close()


@pytest_asyncio.fixture
async def appliance_server_aes() -> AsyncGenerator[
    Callable[..., Awaitable[ApplianceServerAes]]
]:
    """Appliance Server with AES."""
    servers: list[TestServer] = []

    async def go(
        message_set: dict,
        psk64: str = TEST_PSK64,
        iv64: str = TEST_IV64,
        port: int = 80,
    ) -> ApplianceServer:
        appliance = ApplianceServerAes(message_set, psk64, iv64)

        app = web.Application()
        app.add_routes([web.get("/homeconnect", appliance.websocket_handler)])
        test_server = TestServer(app, port=port)
        await test_server.start_server()
        appliance.host = test_server.host

        servers.append(test_server)
        return appliance

    yield go

    while servers:
        await servers.pop().close()
