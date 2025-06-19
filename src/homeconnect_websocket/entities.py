from __future__ import annotations

import asyncio
import logging
from abc import ABC
from enum import StrEnum
from typing import TYPE_CHECKING, Any, TypedDict

from .errors import AccessError
from .helpers import TYPE_MAPPING
from .message import Action, Message

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

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


class DeviceInfo(TypedDict, total=False):
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


class OptionDescription(TypedDict, total=False):
    """Typing for Option Description."""

    access: Access
    available: bool
    liveUpdate: bool
    refUID: int
    default: Any


class EntityDescription(TypedDict, total=False):
    """Typing for Entity Description."""

    uid: int
    name: str
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
    refCID: int
    refDID: int
    protocolType: str
    contentType: str


class DeviceDescription(TypedDict, total=False):
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
    protectionPort: EntityDescription


class Entity(ABC):
    """BaseEntity Class."""

    _appliance: HomeAppliance
    _uid: int
    _name: str
    _callbacks: set[Callable[[Entity], Coroutine]]
    _value: Any | None = None
    _value_shadow: Any | None = None
    _enumeration: dict | None = None
    _rev_enumeration: dict

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        """BaseEntity Class."""
        self._appliance: HomeAppliance = appliance
        self._uid = description["uid"]
        self._name = description["name"]
        self._callbacks = set()
        self._tasks = set()
        self._type = TYPE_MAPPING.get(
            description.get("protocolType"), lambda value: value
        )
        if "enumeration" in description:
            self._enumeration = {
                int(k): v for k, v in description["enumeration"].items()
            }
            self._rev_enumeration = {
                v: int(k) for k, v in description["enumeration"].items()
            }
        try:
            if "initValue" in description:
                self._value = self._type(description["initValue"])
            if "default" in description:
                self._value = self._type(description["default"])
        except TypeError:
            _LOGGER.exception("Failed to set default/init Value on %s", self._name)
        self._value_shadow = self._value

    async def update(self, values: dict) -> None:
        """Update the entity state and execute callbacks."""
        if "value" in values:
            self._value = self._type(values["value"])
            self._value_shadow = self._value

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

    def register_callback(self, callback: Callable[[Entity], Coroutine]) -> None:
        """Register update callback."""
        if callback not in self._callbacks:
            self._callbacks.add(callback)

    def unregister_callback(self, callback: Callable[[Entity], Coroutine]) -> None:
        """Unregister update callback."""
        self._callbacks.remove(callback)

    def dump(self) -> dict:
        """Dump Entity state."""
        return {
            "uid": self.uid,
            "name": self.name,
            "value": self.value,
            "value_raw": self.value_raw,
            "enum": self.enum,
        }

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

    async def set_value(self, value: str | int | bool) -> None:  # noqa: FBT001
        """
        Set the Value of the Entity.

        if the Entity is an Enum entity the value will be resolve to the reference Value
        """
        if self._enumeration:
            if value not in self._rev_enumeration:
                msg = "Value not in Enum"
                raise ValueError(msg)
            await self.set_value_raw(self._rev_enumeration[value])
        else:
            await self.set_value_raw(value)

    @property
    def value_raw(self) -> Any | None:
        """Current raw Value."""
        return self._value

    @property
    def value_shadow(self) -> Any | None:
        """Shadow Value of the Entity."""
        return self._value_shadow

    async def set_value_raw(self, value_raw: str | float | bool) -> None:  # noqa: FBT001
        """Set the raw Value."""
        message = Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": self._uid, "value": self._type(value_raw)},
        )
        response = await self._appliance.session.send_sync(message)
        if response.action == Action.RESPONSE and response.code is None:
            self._value_shadow = self._type(value_raw)

    @property
    def enum(self) -> dict[int, str] | None:
        """The internal enumeration."""
        return self._enumeration


class AccessMixin(Entity):
    """Mixin for Entities with access attribute."""

    _access: Access | None = None

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        """
        Mixin for Entities with access attribute.

        Args:
        ----
            description (EntityDescription): The entity description
            appliance (HomeAppliance): Appliance

        """
        super().__init__(description, appliance)
        self._access = description.get("access", self._access)

    async def update(self, values: dict) -> None:
        """Update the entity state and execute callbacks."""
        if "access" in values:
            self._access = Access(values["access"].lower())
        await super().update(values)

    @property
    def access(self) -> Access | None:
        """Current Access state."""
        return self._access

    async def set_value_raw(self, value_raw: str | int | bool) -> None:  # noqa: FBT001
        """Set the raw Value."""
        if self._access not in [Access.READ_WRITE, Access.WRITE_ONLY]:
            msg = "Not Writable"
            raise AccessError(msg)
        await super().set_value_raw(value_raw)

    def dump(self) -> dict:
        """Dump Entity state."""
        state = super().dump()
        state["access"] = self.access
        return state


class AvailableMixin(Entity):
    """Mixin for Entities with available attribute."""

    _available: bool | None = None

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        """
        Mixin for Entities with available attribute.

        Args:
        ----
            description (EntityDescription): The entity description
            appliance (HomeAppliance): Appliance

        """
        super().__init__(description, appliance)
        self._available = description.get("available", self._available)

    async def update(self, values: dict) -> None:
        """Update the entity state and execute callbacks."""
        if "available" in values:
            self._available = bool(values["available"])
        await super().update(values)

    @property
    def available(self) -> bool | None:
        """Current Available state."""
        return self._available

    async def set_value_raw(self, value_raw: str | int | bool) -> None:  # noqa: FBT001
        """Set the raw Value."""
        if not self._available:
            msg = "Not Available"
            raise AccessError(msg)
        await super().set_value_raw(value_raw)

    def dump(self) -> dict:
        """Dump Entity state."""
        state = super().dump()
        state["available"] = self.available
        return state


class MinMaxMixin(Entity):
    """Mixin for Entities with available Min and Max values."""

    _min: float | None = None
    _max: float | None = None
    _step: float | None = None

    def __init__(
        self, description: EntityDescription, appliance: HomeAppliance
    ) -> None:
        """
        Mixin for Entities with available Min and Max values.

        Args:
        ----
            description (EntityDescription): The entity description
            appliance (HomeAppliance): Appliance

        """
        super().__init__(description, appliance)
        if "min" in description:
            self._min = float(description["min"])
        if "max" in description:
            self._max = float(description["max"])
        if "stepSize" in description:
            self._step = float(description["stepSize"])

    @property
    def min(self) -> float | None:
        """Minimum value."""
        return self._min

    @property
    def max(self) -> float | None:
        """Maximum value."""
        return self._max

    @property
    def step(self) -> float | None:
        """Minimum value."""
        return self._step

    def dump(self) -> dict:
        """Dump Entity state."""
        state = super().dump()
        state["min"] = self.min
        state["max"] = self.max
        state["step"] = self.step
        return state


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

    async def execute(self, value: int) -> None:
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
        """
        Program Entity.

        Args:
        ----
            description (EntityDescription): parsed Device description
            appliance (HomeAppliance): Host

        """
        super().__init__(description, appliance)
        self._options: list[Option] = []
        if "options" in description:
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

    async def start(self, options: dict[str, str | int | bool] | None = None) -> None:
        """Start this Program, select might be required first."""
        if options is None:
            options = {}
        _options = [
            {"uid": option.uid, "value": option.value_shadow}
            for option in self._options
            if option.access == Access.READ_WRITE and option.uid not in options
        ]
        for option_uid, option_value in options.items():
            _options.append({"uid": option_uid, "value": option_value})

        message = Message(
            resource="/ro/activeProgram",
            action=Action.POST,
            data={"program": self._uid, "options": _options},
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
