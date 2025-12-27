"""Helper functions."""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable, Coroutine
    from types import TracebackType

    from .entities import Entity


def convert_bool(obj: str | bool | float) -> bool:  # noqa: FBT001
    """Convert a string to as bool."""
    if isinstance(obj, str):
        if obj.lower() == "true":
            return True
        if obj.lower() == "false":
            return False
        with contextlib.suppress(ValueError):
            obj = float(obj)
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float | int):
        return bool(obj)
    msg = "Can't convert %s to bool"
    raise TypeError(msg, obj)


def load_object(obj_str: str) -> dict:
    """Load complex objects from json strings."""
    if isinstance(obj_str, str):
        try:
            return json.loads(obj_str)
        except json.JSONDecodeError as exc:
            msg = "Can't decode JSON"
            raise TypeError(msg) from exc
    return obj_str


TYPE_MAPPING: Final[dict[str, type]] = {
    "Boolean": convert_bool,
    "Integer": int,
    "Float": float,
    "String": str,
    "Object": load_object,
    None: lambda value: value,
}


class CallbackManager:
    """Manage and batch Entity callbacks."""

    _tasks: set[asyncio.Task]
    _scheduled_callbacks: set[tuple[Callable[[Entity], Coroutine], Entity]]
    _lock: asyncio.Lock

    def __init__(self, logger: logging.Logger) -> None:
        """
        Manage and batch Entity callbacks.

        Args:
        ----
            logger (Optional[Logger]): Logger

        """
        self._logger = logger
        self._lock = asyncio.Lock()
        self._tasks = set()
        self._count = 0
        self._scheduled_callbacks = set()

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
                self._execute_callback(callback, entity)

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
                await self._execute_scheduled_callbacks()

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.release()

    async def _execute_scheduled_callbacks(self) -> None:
        if not self._lock.locked():
            msg = "Lock not acquired"
            raise RuntimeError(msg)

        while self._scheduled_callbacks:
            callback, entity = self._scheduled_callbacks.pop()
            self._execute_callback(callback, entity)

    def _execute_callback(
        self, callback: Callable[[Entity], Coroutine], entity: Entity
    ) -> None:
        try:
            task = asyncio.create_task(callback(entity))
            self._tasks.add(task)
            task.add_done_callback(self._done_callback)
        except Exception:
            self._logger.exception("Callback for %s raised an Exception", entity.name)

    def _done_callback(self, task: asyncio.Task) -> None:
        if exc := task.exception():
            self._logger.exception("Exception in callback for entity %s", exc_info=exc)
        self._tasks.discard(task)
