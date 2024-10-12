from __future__ import annotations

import asyncio
import logging
from abc import ABC
from enum import StrEnum
from typing import TYPE_CHECKING, Any, TypedDict

from .errors import AccessError
from .message import Action, Message

if TYPE_CHECKING:
    from collections.abc import Callable

    from .appliance import HomeAppliance

_LOGGER = logging.getLogger(__name__)


class Access(StrEnum):
    """Access levels."""

    NONE = "none"
    READ = "read"
    READ_WRITE = "readwrite"
    WRITE_ONLY = "writeonly"
    READ_STATIC = "readstatic"


class EventLevel(StrEnum):
    """Event Levels."""

    INFO = "info"
    HINT = "hint"
    WARNING = "warning"
    ALERT = "alert"
    CRITOCAL = "critical"


class EventHandling(StrEnum):
    """Event handling types."""

    NONE = "none"
    ACKNOWLEDGE = "acknowledge"
    DECISION = "decision"


class Execution(StrEnum):
    """Execution types."""

    NONE = "none"
    SELECT_ONLY = "selectonly"
    START_ONLY = "startonly"
    SELECT_AND_START = "selectandstart"


class DeviceInfo(TypedDict):
    """Typing for Device info."""

    brand: str
    type: str
    model: str
    version: int
    revision: int


class OptionDescription(TypedDict):
    """Typing for Option Description."""

    access: Access
    available: bool
    liveUpdate: bool
    refUID: int
    default: Any


class EntityDescription(TypedDict):
    """Typing for Entity Description."""

    uid: int
    name: str
    type: Any
    enumeration: dict | None
    available: bool
    access: Access
    min: int | float
    max: int | float
    stepSize: int | float
    notifyOnChange: bool
    initValue: Any
    passwordProtected: bool
    handling: EventHandling
    level: EventLevel
    default: Any
    liveUpdate: bool
    refUID: int
    options: list[OptionDescription]
    execution: Execution
    fullOptionSet: bool
    validate: bool


class DeviceDescription(TypedDict):
    """Typing for DeviceDescription."""

    info: DeviceInfo
    status: list[EntityDescription]
    setting: list[EntityDescription]
    event: list[EntityDescription]
    command: list[EntityDescription]
    option: list[EntityDescription]
    program: list[EntityDescription]
    activeProgram: ActiveProgram
    selectedProgram: SelectedProgram


class Entity(ABC):
    """BaseEntity Class."""

    _appliance: HomeAppliance
    _uid: int
    _name: str
    _callbacks: set[Callable[[Entity], None]]
    _access: Access = None
    _available: bool = None
    _value: Any | None = None
    _enumeration: dict = None
    _rev_enumeration: dict = None

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        """BaseEntity Class."""
        self._appliance: HomeAppliance = appliance
        self._uid = description["uid"]
        self._name = description["name"]
        self._callbacks = set()
        self._tasks = set()
        if "available" in description:
            self._available = description["available"]
        if "access" in description:
            self._access = Access(description["access"])
        if "enumeration" in description:
            self._enumeration = {
                int(k): v for k, v in description["enumeration"].items()
            }
            self._rev_enumeration = {
                v: int(k) for k, v in description["enumeration"].items()
            }
        if "initValue" in description:
            self._value = description["initValue"]
        if "default" in description:
            self._value = description["default"]

    async def update(self, values: dict) -> None:
        """Update the entity state and execute callbacks."""
        if "available" in values:
            self._available = bool(values["available"])
        if "access" in values:
            self._access = Access(values["access"].lower())
        if "value" in values:
            self._value = values["value"]

        for callback in self._callbacks:
            try:
                task = asyncio.create_task(callback(self))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            except Exception:
                _LOGGER.exception("Callback for %s raised an Exception", self.name)

    def register_callback(self, callback: Callable[[Entity], None]) -> None:
        """Register update callback."""
        if callback not in self._callbacks:
            self._callbacks.add(callback)

    def unregister_callback(self, callback: Callable[[Entity], None]) -> None:
        """Unregister update callback."""
        self._callbacks.remove(callback)

    @property
    def uid(self) -> int:
        """Entity uid."""
        return self._uid

    @property
    def name(self) -> str:
        """Entity name."""
        return self._name

    @property
    def available(self) -> bool | None:
        """Current Available state."""
        return self._available

    @property
    def access(self) -> Access | None:
        """Current Access state."""
        return self._access

    @property
    def value(self) -> Any | None:
        """
        Current Value of the Entity.

        if the Entity is an Enum entity the value will be resolve to the actual value.
        """
        if self._enumeration and self._value is not None:
            return self._enumeration[self._value]
        return self._value

    async def set_value(self, value: str | int | bool) -> None:
        """
        Set the Value of the Entity.

        if the Entity is an Enum entity the value will be resolve to the reference Value
        """
        if self._enumeration:
            await self.set_value_raw(self._rev_enumeration[value])
        else:
            await self.set_value_raw(value)

    @property
    def value_raw(self) -> Any | None:
        """Current raw Value."""
        return self._value

    async def set_value_raw(self, value_raw: str | int | bool) -> None:
        """Set the raw Value."""
        if self._access not in [Access.READ_WRITE, Access.WRITE_ONLY]:
            msg = "Not Writable"
            raise AccessError(msg)

        if not self._available:
            msg = "Not Available"
            raise AccessError(msg)

        message = Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": self._uid, "value": value_raw},
        )
        await self._appliance.session.send_sync(message)

    @property
    def enum(self) -> dict[int, str] | None:
        """The internal enumeration."""
        return self._enumeration


class Status(Entity):
    """Represents an Settings Entity."""


class Setting(Entity):
    """Represents an Settings Entity."""


class Event(Entity):
    """Represents an Event Entity."""

    async def acknowledge(self) -> None:
        """Acknowledge Event."""
        await self._appliance.commands["BSH.Common.Command.AcknowledgeEvent"].execute(
            self._uid
        )

    async def reject(self) -> None:
        """Reject Event."""
        await self._appliance.commands["BSH.Common.Command.RejectEvent"].execute(
            self._uid
        )


class Command(Entity):
    """Represents an Command Entity."""

    async def execute(self, value: str | int | bool) -> None:
        """Execute command."""
        if self._access not in [Access.READ_WRITE, Access.WRITE_ONLY]:
            msg = "Not Writable"
            raise AccessError(msg)

        if not self._available:
            msg = "Not Available"
            raise AccessError(msg)

        message = Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": self._uid, "value": value},
        )
        await self._appliance.session.send_sync(message)


class Option(Entity):
    """Represents an Option Entity."""


class Program(Entity):
    """Represents an Program Entity."""

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        super().__init__(description, appliance)
        self._options: list[Option] = []
        for option in description["options"]:
            self._options.append(appliance.entities_uid[option["refUID"]])

    async def select(self) -> None:
        """Select this Program."""
        message = Message(
            resource="/ro/selectedProgram",
            action=Action.POST,
            data={"program": self._uid, "options": []},
        )
        await self._appliance.session.send_sync(message)

    async def start(self) -> None:
        """Start this Program, select might be required first."""
        options = [
            {"uid": option.uid, "value": option.value_raw}
            for option in self._options
            if option.access == Access.READ_WRITE
        ]
        message = Message(
            resource="/ro/activeProgram",
            action=Action.POST,
            data={"program": self._uid, "options": options},
        )
        await self._appliance.session.send_sync(message)


class ActiveProgram(Entity):
    """Represents the Active_Program Entity."""


class SelectedProgram(Entity):
    """Represents the Selected_Program Entity."""


class ProtectionPort(Entity):
    """Represents an Protection_Port Entity."""
