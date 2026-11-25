"""Tests with Appliances that close, stall or drop the connection."""

from __future__ import annotations

import asyncio
import json
import os
import time
from itertools import pairwise
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
import yarl
from aiohttp import web
from homeconnect_websocket import ConnectionFailedError, ConnectionState, hc_socket, session
from homeconnect_websocket.session import HCSession, HCSessionReconnect

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

    from homeconnect_websocket.message import Message

MAX_LOOP_BLOCK = 0.1

INIT_MESSAGE = {
    "sID": 1,
    "msgID": 1,
    "resource": "/ei/initialValues",
    "version": 2,
    "action": "POST",
    "data": [{"edMsgID": 10}],
}
SERVICES = [{"service": "ci", "version": 3}, {"service": "ei", "version": 2}]


class MisbehavingAppliance:
    """
    Appliance with selectable behaviour.

    tcp_close:   close the connection right after accepting it
    tcp_silent:  accept the connection, then do nothing
    ws_silent:   accept the websocket, never send the init message
    no_response: send the init message, never answer a request
    drop:        complete the handshake, then close the connection
    ok:          complete the handshake and stay connected
    """

    def __init__(self) -> None:
        """Create the Appliance."""
        self.behaviour = "ok"
        self.port: int = 0
        self.connect_times: list[float] = []
        self.open_connections = 0
        self._stalled: set[asyncio.Task] = set()
        self._websockets: set[web.WebSocketResponse] = set()

    @property
    def connections(self) -> int:
        """Number of connections made."""
        return len(self.connect_times)

    async def websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """Handle a connection."""
        self.connect_times.append(time.monotonic())
        if self.behaviour == "tcp_close":
            request.transport.close()
            return web.Response()
        self.open_connections += 1
        ws = web.WebSocketResponse()
        try:
            if self.behaviour == "tcp_silent":
                self._stalled.add(asyncio.current_task())
                await asyncio.Event().wait()
            await ws.prepare(request)
            self._websockets.add(ws)
            if self.behaviour != "ws_silent":
                await ws.send_str(json.dumps(INIT_MESSAGE))
            async for raw in ws:
                if self.behaviour in ("ws_silent", "no_response"):
                    continue
                message = json.loads(raw.data)
                if message["action"] == "NOTIFY" and self.behaviour == "drop":
                    break  # "/ei/deviceReady" is the last message of the handshake
                if message["action"] != "GET":
                    continue
                message["action"] = "RESPONSE"
                message["data"] = SERVICES if message["resource"] == "/ci/services" else []
                await ws.send_str(json.dumps(message))
        finally:
            self.open_connections -= 1
            self._websockets.discard(ws)
        return ws

    async def stop(self) -> None:
        """Close all open connections."""
        for task in self._stalled:
            task.cancel()
        for ws in list(self._websockets):
            await ws.close()


@pytest_asyncio.fixture
async def appliance(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[Callable[[str], Awaitable[MisbehavingAppliance]]]:
    """Start a misbehaving Appliance on an unprivileged port."""
    cleanup: list[Callable[[], Awaitable[None]]] = []

    async def go(behaviour: str) -> MisbehavingAppliance:
        appliance = MisbehavingAppliance()
        appliance.behaviour = behaviour
        app = web.Application()
        app.add_routes([web.get("/homeconnect", appliance.websocket_handler)])
        runner = web.AppRunner(app, handler_cancellation=True)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        appliance.port = site._server.sockets[0].getsockname()[1]

        async def close_runner() -> None:
            await appliance.stop()
            await runner.cleanup()

        cleanup.append(close_runner)

        monkeypatch.setattr(
            hc_socket,
            "_make_url",
            lambda host, ssl: yarl.URL.build(  # noqa: ARG005
                scheme="ws", host=host, port=appliance.port, path="/homeconnect"
            ),
        )
        return appliance

    yield go

    for close in cleanup:
        await close()


@pytest.fixture
def short_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink timeouts and delays."""
    monkeypatch.setattr(session, "DEFAULT_CONNECT_TIMEOUT", 0.2)
    monkeypatch.setattr(session, "DEFAULT_HANDSHAKE_TIMEOUT", 0.2)
    monkeypatch.setattr(session, "INITIAL_RECONNECT_DELAY", 0.01)
    monkeypatch.setattr(session, "MAX_RECONNECT_DELAY", 0.08)
    monkeypatch.setattr(session, "RECONNECT_JITTER", 0)


class LoopMonitor:
    """Measure the longest time the event loop did not run."""

    def __init__(self) -> None:
        """Start measuring."""
        self.max_block = 0.0
        self.ticks = 0
        self._task = asyncio.ensure_future(self._run())

    async def _run(self) -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(0.001)
            now = time.monotonic()
            self.max_block = max(self.max_block, now - last)
            self.ticks += 1
            last = now

    def stop(self) -> None:
        """Stop measuring."""
        self._task.cancel()


def open_fds() -> int:
    """Return the number of open file descriptors of this process."""
    for path in ("/proc/self/fd", "/dev/fd"):
        if Path(path).is_dir():
            return len(os.listdir(path))  # noqa: PTH208
    pytest.skip("Can't count file descriptors")
    return 0


async def message_handler(message: Message) -> None:
    """Ignore messages."""


async def wait_for(condition: Callable[[], bool], timeout: float = 10) -> None:  # noqa: ASYNC109
    """Wait until condition is true."""
    async with asyncio.timeout(timeout):
        while not condition():  # noqa: ASYNC110
            await asyncio.sleep(0.001)


@pytest.mark.asyncio
@pytest.mark.usefixtures("short_timeouts")
@pytest.mark.parametrize(
    ("behaviour", "error"),
    [
        ("tcp_close", ConnectionFailedError),
        ("tcp_silent", ConnectionFailedError),
        ("ws_silent", TimeoutError),
        ("no_response", TimeoutError),
    ],
)
async def test_connect_fails_within_timeout(
    appliance: Callable[[str], Awaitable[MisbehavingAppliance]],
    behaviour: str,
    error: type[Exception],
) -> None:
    """Connecting to an Appliance that does not answer fails within the timeout."""
    await appliance(behaviour)
    hc_session = HCSession("127.0.0.1", "Test", "Test", None, None, message_handler)
    monitor = LoopMonitor()

    start = time.monotonic()
    with pytest.raises(error):
        await hc_session.connect()
    assert time.monotonic() - start < 2
    assert not hc_session.connected

    await hc_session.close()
    assert hc_session._socket.closed
    monitor.stop()
    assert monitor.max_block < MAX_LOOP_BLOCK


@pytest.mark.asyncio
@pytest.mark.usefixtures("short_timeouts")
@pytest.mark.parametrize("behaviour", ["tcp_close", "drop"])
async def test_connect_close_cycles_do_not_leak(
    appliance: Callable[[str], Awaitable[MisbehavingAppliance]],
    behaviour: str,
) -> None:
    """1000 failed connect/close cycles leave no tasks or sockets behind."""
    server = await appliance(behaviour)
    hc_session = HCSession("127.0.0.1", "Test", "Test", None, None, message_handler)

    async def cycle() -> None:
        try:
            await hc_session.connect()
            await wait_for(lambda: hc_session._socket.closed)
        except ConnectionFailedError:
            pass
        await hc_session.close()

    for _ in range(20):
        await cycle()
    tasks_before = len(asyncio.all_tasks())
    fds_before = open_fds()
    monitor = LoopMonitor()

    for _ in range(1000):
        await cycle()

    monitor.stop()
    assert monitor.max_block < MAX_LOOP_BLOCK
    await wait_for(lambda: server.open_connections == 0)
    await wait_for(lambda: len(asyncio.all_tasks()) <= tasks_before)
    assert open_fds() <= fds_before + 2


@pytest.mark.asyncio
@pytest.mark.usefixtures("short_timeouts")
async def test_reconnect_backoff_when_connection_drops_after_handshake(
    appliance: Callable[[str], Awaitable[MisbehavingAppliance]],
) -> None:
    """An Appliance that drops every connection after the handshake is not hammered."""
    server = await appliance("drop")
    states: list[ConnectionState] = []

    async def state_callback(state: ConnectionState) -> None:
        states.append(state)

    hc_session = HCSessionReconnect(
        "127.0.0.1",
        "Test",
        "Test",
        None,
        None,
        message_handler,
        connection_state_callback=state_callback,
    )
    monitor = LoopMonitor()
    await hc_session.connect()

    await wait_for(lambda: server.connections >= 8)

    monitor.stop()
    assert monitor.max_block < MAX_LOOP_BLOCK
    gaps = [b - a for a, b in pairwise(server.connect_times)]
    # First reconnect is immediate, then 0.01 s, 0.02 s, 0.04 s, 0.08 s, 0.08 s, ...
    assert gaps[1] >= 0.009, gaps
    assert gaps[2] >= 0.018, gaps
    assert gaps[3] >= 0.036, gaps
    assert all(gap >= 0.07 for gap in gaps[4:]), gaps
    assert server.open_connections <= 1
    assert hc_session._reconnect_task is not None
    assert (
        len([task for task in hc_session._task_manager._background_tasks if not task.done()]) <= 2
    )

    await hc_session.close()
    connections = server.connections
    await asyncio.sleep(0.2)
    assert server.connections == connections
    assert all(task.done() for task in hc_session._task_manager._background_tasks)
    assert states[-1] == ConnectionState.CLOSED


@pytest.mark.asyncio
@pytest.mark.usefixtures("short_timeouts")
@pytest.mark.parametrize("behaviour", ["tcp_close", "tcp_silent", "ws_silent", "no_response"])
async def test_reconnect_to_dead_appliance(
    appliance: Callable[[str], Awaitable[MisbehavingAppliance]],
    behaviour: str,
) -> None:
    """Reconnect attempts back off, are bounded and close their sockets."""
    server = await appliance("ok")
    hc_session = HCSessionReconnect("127.0.0.1", "Test", "Test", None, None, message_handler)
    await hc_session.connect()
    assert hc_session.connected
    tasks_before = len(asyncio.all_tasks())

    server.behaviour = behaviour
    monitor = LoopMonitor()
    await server.stop()
    await wait_for(lambda: server.connections >= 12)

    monitor.stop()
    assert monitor.max_block < MAX_LOOP_BLOCK
    assert not hc_session.connected
    assert hc_session.connection_state in (
        ConnectionState.RECONNECTING,
        ConnectionState.HANDSHAKE,
    )
    # aiohttp retries a request once when the server closes the connection
    # without an answer: only look at the first connection of an attempt.
    attempts = server.connect_times[1:2]
    for connect_time in server.connect_times[2:]:
        if connect_time - attempts[-1] > 0.005:
            attempts.append(connect_time)
    gaps = [b - a for a, b in pairwise(attempts)]
    assert len(gaps) >= 3
    assert all(gap >= 0.009 for gap in gaps), gaps
    assert all(gap >= 0.07 for gap in gaps[3:]), gaps
    # Failed attempts don't accumulate connections or tasks
    assert server.open_connections <= 1
    assert len(asyncio.all_tasks()) <= tasks_before + 3

    # The Appliance is back
    server.behaviour = "ok"
    await wait_for(lambda: hc_session.connected)
    assert server.open_connections == 1

    await hc_session.close()
    await wait_for(lambda: server.open_connections == 0)
    assert all(task.done() for task in hc_session._task_manager._background_tasks)
