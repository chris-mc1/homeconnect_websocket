from __future__ import annotations

import logging

from .entities import (
    ActiveProgram,
    Command,
    DeviceDescription,
    Entity,
    Event,
    Option,
    Program,
    SelectedProgram,
    Setting,
    Status,
)
from .message import Action, Message
from .session import HCSession

_LOGGER = logging.getLogger(__name__)


class HomeAppliance:
    session: HCSession
    info: dict
    entities_uid: dict[int, Entity]
    "entities by uid"

    entities: dict[str, Entity]
    "entities by name"

    status: dict[str, Status]
    "status entities by name"

    settings: dict[str, Setting]
    "setting entities by name"

    events: dict[str, Event]
    "event entities by name"

    commands: dict[str, Command]
    "command entities by name"

    options: dict[str, Option]
    "option entities by name"

    programs: dict[str, Program]
    "program entities by name"

    _selected_program: SelectedProgram | None = None
    _active_program: ActiveProgram | None = None

    def __init__(
        self,
        description: DeviceDescription,
        host: str,
        app_name: str,
        app_id: str,
        psk64: str,
        iv64: str | None = None,
    ) -> None:
        """
        HomeConnect Appliance.

        Args:
        ----
            description (dict): parsed Device description
            host (str): Host
            app_name (str): Name used to identify this App
            app_id (str): ID used to identify this App
            psk64 (str): urlsafe base64 encoded psk key
            iv64 (Optional[str]): urlsafe base64 encoded iv64 key (only AES)

        """
        self.session = HCSession(host, app_name, app_id, psk64, iv64)
        self.info: dict[str, str] = description.get("info", {})

        self.entities_uid = {}
        self.entities = {}
        self.status = {}
        self.settings = {}
        self.events = {}
        self.commands = {}
        self.options = {}
        self.programs = {}
        self._create_entities(description)

    async def connect(self) -> None:
        """Open Connection with Appliance."""
        await self.session.connect(self._message_handler)

    async def close(self) -> None:
        """Close Connection with Appliance."""
        await self.session.close()

    async def _message_handler(self, message: Message) -> None:
        """Handel received messages."""
        if message.action == Action.NOTIFY:
            if message.resource in ["/ro/descriptionChange", "/ro/values"]:
                await self._update_entities(message.data)
        elif message.action == Action.RESPONSE:
            if message.resource in [
                "/ro/allDescriptionChanges",
                "/ro/allMandatoryValues",
            ]:
                await self._update_entities(message.data)
            elif message.resource == "/iz/info":
                # Update device Info
                self.info.update(message.data[0])

    async def _update_entities(self, data: dict) -> None:
        """Update entities from Message data."""
        for entity in data:
            uid = int(entity["uid"])
            if uid in self.entities_uid:
                await self.entities_uid[uid].update(entity)
            else:
                _LOGGER.info("Recived Update for unkown entity %s", uid)

    def _create_entities(self, description: DeviceDescription):
        """Create Entities from Device description."""
        for status in description["status"]:
            entity = Status(status, self)
            self.status[entity.name] = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

        for setting in description["setting"]:
            entity = Setting(setting, self)
            self.settings[entity.name] = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

        for event in description["event"]:
            entity = Event(event, self)
            self.events[entity.name] = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

        for command in description["command"]:
            entity = Command(command, self)
            self.commands[entity.name] = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

        for option in description["option"]:
            entity = Option(option, self)
            self.options[entity.name] = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

        for program in description["program"]:
            entity = Program(program, self)
            self.programs[entity.name] = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

        if "activeProgram" in description:
            entity = ActiveProgram(description["activeProgram"], self)
            self._active_program = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

        if "selectedProgram" in description:
            entity = SelectedProgram(description["selectedProgram"], self)
            self._selected_program = entity
            self.entities[entity.name] = entity
            self.entities_uid[entity.uid] = entity

    async def get_wifi_networks(self) -> list[dict]:
        """Get info on avalibel WiFi networks."""
        msg = Message(resource="/ci/wifiNetworks", action=Action.GET)
        rsp = await self.session.send_sync(msg)
        return rsp.data

    async def get_network_config(self) -> list[dict]:
        """Get current network config."""
        msg = Message(resource="/ni/info", action=Action.GET)
        rsp = await self.session.send_sync(msg)
        return rsp.data

    @property
    def active_program(self) -> Program | None:
        """Return the current Active Program entity or None if no Program is active."""
        return (
            None
            if self._active_program.value == 0 or self._active_program.value is None
            else self.entities_uid[self._active_program.value]
        )

    @property
    def selected_program(self) -> Program | None:
        """Return current selected Program entity or None if no Program is selected."""
        return (
            None
            if self._selected_program.value == 0 or self._selected_program.value is None
            else self.entities_uid[self._selected_program.value]
        )
