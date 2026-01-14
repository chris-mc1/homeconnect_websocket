from __future__ import annotations

import asyncio
import logging
from time import monotonic
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Coroutine

BLOCK_TIMEOUT = 20


class TaskManager:
    """Manage asyncio Task."""

    _tasks: set[asyncio.Future[Any]]
    _loop: asyncio.AbstractEventLoop

    def __init__(
        self,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        Manage asyncio Task.

        Args:
        ----
            logger (Optional[Logger]): Logger

        """
        self._loop = asyncio.get_event_loop()
        self._tasks = set()
        self._background_tasks = set()

        if logger is None:
            self._logger = logging.getLogger(__name__)
        else:
            self._logger = logger.getChild("tasks")

    def create_task[R](
        self, target: Coroutine[Any, Any, R], *, eager_start: bool = False
    ) -> asyncio.Task[R]:
        """Create a new Task."""
        task: asyncio.Task[R] = self._loop.create_task(target, eager_start=eager_start)
        if eager_start and task.done():
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.remove)

    def create_background_task[R](
        self, target: Coroutine[Any, Any, R], *, eager_start: bool = False
    ) -> asyncio.Task[R]:
        """Create a new background Task."""
        task: asyncio.Task[R] = self._loop.create_task(target, eager_start=eager_start)
        if eager_start and task.done():
            return
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.remove)

    async def block_till_done(self, *, wait_background_tasks: bool = False) -> None:
        """
        Block until all task are done or Timeout reached.

        Args:
        ----
            wait_background_tasks (Optional[bool]): Also wait for background Tasks

        """
        await asyncio.sleep(0)
        current_task = asyncio.current_task()
        start_time = monotonic()
        while tasks := [
            task
            for task in (
                self._tasks | self._background_tasks
                if wait_background_tasks
                else self._tasks
            )
            if task is not current_task
        ]:
            _, pending = await asyncio.wait(tasks, timeout=BLOCK_TIMEOUT)
            if pending and monotonic() - start_time > BLOCK_TIMEOUT:
                raise TimeoutError

    async def shutdown(self) -> None:
        """
        Shutdown the task manager.

        Wait for all Tasks including background Tasks to finish.

        """
        current_task = asyncio.current_task()
        try:
            self.block_till_done(wait_background_tasks=True)
        except TimeoutError:
            while tasks := [
                task
                for task in (self._tasks | self._background_tasks)
                if task is not current_task
            ]:
                for task in tasks:
                    task.cancel()
