from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from homeconnect_websocket.task_manager import TaskManager

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from types import TracebackType

    from homeconnect_websocket.entities import Entity


class CallbackManager:
    """Manage and batch Entity callbacks."""

    _task_manager: TaskManager
    _scheduled_callbacks: set[tuple[Callable[[Entity], Coroutine], Entity]]
    _lock: asyncio.Lock

    def __init__(
        self,
        task_manager: TaskManager | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        Manage and batch Entity callbacks.

        Args:
        ----
            task_manager (Optional[TaskManager]): Task manager
            logger (Optional[Logger]): Logger

        """
        self._task_manager = TaskManager() if task_manager is None else task_manager
        self._logger = logger
        self._lock = asyncio.Lock()
        self._tasks = set()
        self._count = 0
        self._scheduled_callbacks = set()

        if logger is None:
            self._logger = logging.getLogger(__name__)
        else:
            self._logger = logger.getChild("callbacks")

    async def schedule_callback(
        self, callback: Callable[[Entity], Coroutine], entity: Entity
    ) -> None:
        """
        Schedule a new Entity callback.

        Args:
        ----
            callback (Callable[[Entity], Coroutine]): Callback function
            entity (Entity): Entity making the callback

        """
        async with self._lock:
            if self._count > 0:
                self._scheduled_callbacks.add((callback, entity))
            else:
                self._task_manager.create_task(self._wrap_callback(callback, entity))

    async def acquire(self) -> None:
        """Increase counter and start collecting callbacks."""
        async with self._lock:
            self._count += 1

    async def release(self) -> None:
        """Decrease counter."""
        async with self._lock:
            if self._count > 0:
                self._count -= 1

            if self._count == 0:
                self._execute_scheduled_callbacks()

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.release()

    async def _wrap_callback(
        self, callback: Callable[[Entity], Coroutine], entity: Entity
    ) -> None:
        """Call the external message handler."""
        try:
            await callback(entity)
        except Exception:
            self._logger.exception("Exception in external message handler")

    def _execute_scheduled_callbacks(self) -> None:
        if not self._lock.locked():
            msg = "Lock not acquired"
            raise RuntimeError(msg)

        while self._scheduled_callbacks:
            callback, entity = self._scheduled_callbacks.pop()
            self._task_manager.create_task(self._wrap_callback(callback, entity))
