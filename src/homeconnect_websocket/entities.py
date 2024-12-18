from __future__ import annotations

import asyncio
import logging
from abc import ABC
from enum import StrEnum
from typing import TYPE_CHECKING, Any, TypedDict

from .errors import AccessError
from .message import Action, Message

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

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
    deviceID: str
    eNumber: str
    vib: str
    mac: str
    haVersion: str
    swVersion: str
    hwVersion: str
    deviceType: str
    deviceInfo: str
    customerIndex: str
    serialNumber: str
    fdString: str
    shipSki: str


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
    activeProgram: EntityDescription
    selectedProgram: EntityDescription


class Entity(ABC):
    """BaseEntity Class."""

    _appliance: HomeAppliance
    _uid: int
    _name: str
    _callbacks: set[Callable[[Entity], None | Awaitable[None]]]
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
        if "value" in values:
            self._value = values["value"]

        for callback in self._callbacks:
            try:
                task = asyncio.create_task(callback(self))
                self._tasks.add(task)
                task.add_done_callback(self._done_callback)
            except Exception:
                _LOGGER.exception("Callback for %s raised an Exception", self.name)

    def _done_callback(self, task: asyncio.Task) -> None:
        if exc := task.exception():
            _LOGGER.exception(
                "Exception in callback for entity %s", self.name, exc_info=exc
            )
        self._tasks.discard(task)

    def register_callback(
        self, callback: Callable[[Entity], None | Awaitable[None]]
    ) -> None:
        """Register update callback."""
        if callback not in self._callbacks:
            self._callbacks.add(callback)

    def unregister_callback(
        self, callback: Callable[[Entity], None | Awaitable[None]]
    ) -> None:
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
        try:
            if self._access not in [Access.READ_WRITE, Access.WRITE_ONLY]:
                msg = "Not Writable"
                raise AccessError(msg)
        except AttributeError:
            pass

        try:
            if not self._available:
                msg = "Not Available"
                raise AccessError(msg)
        except AttributeError:
            pass

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


class AccessMixin(Entity):
    """Mixin for Entities with access attribute."""

    _access: Access = None

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        self._access = description.get("access", self._access)
        super().__init__(description, appliance)

    async def update(self, values: dict) -> None:
        """Update the entity state and execute callbacks."""
        if "access" in values:
            self._access = Access(values["access"].lower())
        await super().update(values)

    @property
    def access(self) -> Access | None:
        """Current Access state."""
        return self._access


class AvailableMixin(Entity):
    """Mixin for Entities with available attribute."""

    _available: bool = None

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        self._available = description.get("available", self._available)
        super().__init__(description, appliance)

    async def update(self, values: dict) -> None:
        """Update the entity state and execute callbacks."""
        if "available" in values:
            self._available = bool(values["available"])
        await super().update(values)

    @property
    def available(self) -> bool | None:
        """Current Available state."""
        return self._available


class MinMaxMixin(Entity):
    """Mixin for Entities with available Min and Max values."""

    _min: float = None
    _max: float = None
    _step: float = None

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        if "min" in description:
            self._min = int(description["min"])
        if "max" in description:
            self._max = int(description["max"])
        if "stepSize" in description:
            self._step = int(description["stepSize"])
        super().__init__(description, appliance)

    @property
    def min(self) -> bool | None:
        """Minimum value."""
        return self._min

    @property
    def max(self) -> bool | None:
        """Maximum value."""
        return self._max

    @property
    def step(self) -> bool | None:
        """Minimum value."""
        return self._step


class Status(AccessMixin, AvailableMixin, MinMaxMixin, Entity):
    """Represents an Settings Entity."""


class Setting(AccessMixin, AvailableMixin, MinMaxMixin, Entity):
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


class Command(AccessMixin, AvailableMixin, MinMaxMixin, Entity):
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


class Option(AccessMixin, AvailableMixin, MinMaxMixin, Entity):
    """Represents an Option Entity."""


class Program(AvailableMixin, Entity):
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


class ActiveProgram(AccessMixin, AvailableMixin, Entity):
    """Represents the Active_Program Entity."""

    _available = True


class SelectedProgram(AccessMixin, AvailableMixin, Entity):
    """Represents the Selected_Program Entity."""

    _available = True


class ProtectionPort(AccessMixin, AvailableMixin, Entity):
    """Represents an Protection_Port Entity."""

    _available = False
