from __future__ import annotations

import asyncio
import contextlib

import pytest
from homeconnect_websocket import task_manager as task_manager_module
from homeconnect_websocket.task_manager import TaskManager


@pytest.mark.asyncio
async def test_shutdown_cancels_tasks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test shutdown cancels tasks still running after the timeout."""
    monkeypatch.setattr(task_manager_module, "BLOCK_TIMEOUT", 0.2)
    task_manager = TaskManager()
    task = task_manager.create_background_task(asyncio.sleep(3600))

    heartbeats = 0

    async def heartbeat() -> None:
        nonlocal heartbeats
        while True:
            heartbeats += 1
            await asyncio.sleep(0.01)

    heartbeat_task = asyncio.create_task(heartbeat())
    async with asyncio.timeout(2):
        await task_manager.shutdown()
    beats_after_shutdown = heartbeats
    await asyncio.sleep(0.1)

    assert task.cancelled()
    # Event loop kept running during and after shutdown
    assert beats_after_shutdown > 0
    assert heartbeats > beats_after_shutdown
    heartbeat_task.cancel()


@pytest.mark.asyncio
async def test_shutdown_task_ignoring_cancel(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Test shutdown returns if a task doesn't finish after cancel."""
    monkeypatch.setattr(task_manager_module, "BLOCK_TIMEOUT", 0.2)
    task_manager = TaskManager()

    async def stubborn() -> None:
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(3600)
        await asyncio.sleep(3600)

    task = task_manager.create_background_task(stubborn())

    async with asyncio.timeout(2):
        await task_manager.shutdown()

    assert not task.done()
    assert "1 task(s) not finished after cancel" in caplog.text
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
