from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .callback_manager import CallbackManager
from .entities import (
    ActiveProgram,
    Command,
    DeviceDescription,
    DeviceInfo,
    Entity,
    EntityDescription,
    Event,
    Option,
    Program,
    SelectedProgram,
    Setting,
    Status,
)
from .message import Action, Message
from .session import ConnectionState, HCSession, HCSessionReconnect
from .task_manager import TaskManager

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from aiohttp import ClientSession


class HomeAppliance:
    """HomeConnect Appliance."""

    session: HCSession
    info: DeviceInfo
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
    _task_manager: TaskManager
    callback_manager: CallbackManager

    def __init__(  # noqa: PLR0913
        self,
        description: DeviceDescription,
        host: str,
        app_name: str,
        app_id: str,
        psk64: str,
        iv64: str | None = None,
        *,
        session: ClientSession | None = None,
        logger: logging.Logger | None = None,
        reconect: bool = True,
        connection_callback: Callable[[ConnectionState], Awaitable[None]] | None = None,
    ) -> None:
        """
        HomeConnect Appliance.

        Args:
        ----
            description (DeviceDescription): parsed Device description
            host (str): Host
            app_name (str): Name used to identify this App
            app_id (str): ID used to identify this App
            psk64 (str): urlsafe base64 encoded psk key
            iv64 (Optional[str]): urlsafe base64 encoded iv64 key (only AES)
            session (Optional[aiohttp.ClientSession]): ClientSession
            logger (Optional[Logger]): Logger
            reconect (bool): Automatic Reconect
            connection_callback (Optional[Callable[[ConnectionState], Awaitable[None]]]): Called when connection state changes

        """  # noqa: E501
        if logger is None:
            self._logger = logging.getLogger(__name__)
        else:
            self._logger = logger.getChild("appliance")

        self._task_manager = TaskManager()

        if reconect:
            self.session = HCSessionReconnect(
                host,
                app_name,
                app_id,
                psk64,
                iv64,
                message_handler=self._message_handler,
                aiohttp_session=session,
                logger=logger,
                connection_state_callback=self._connection_callback,
                task_manager=self._task_manager,
            )
        else:
            self.session = HCSession(
                host,
                app_name,
                app_id,
                psk64,
                iv64,
                message_handler=self._message_handler,
                aiohttp_session=session,
                logger=logger,
                connection_state_callback=self._connection_callback,
                task_manager=self._task_manager,
            )
        self.info = description.get("info", {})
        self.callback_manager = CallbackManager(self._task_manager, self._logger)
        self._ext_connection_state_callback = connection_callback

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
        await self.session.connect()

    async def close(self) -> None:
        """Close Connection with Appliance."""
        await self.session.close()
        await self._task_manager.shutdown()

    async def _message_handler(self, message: Message) -> None:
        """Handel received messages."""
        if message.data is None:
            return
        if message.action == Action.NOTIFY:
            if message.resource in ("/ro/descriptionChange", "/ro/values"):
                await self._update_entities(message.data)
        elif message.action == Action.RESPONSE:
            if message.resource in (
                "/ro/allDescriptionChanges",
                "/ro/allMandatoryValues",
            ):
                await self._update_entities(message.data)
            elif message.resource in ("/iz/info", "/ci/info"):
                # Update device Info
                self.info.update(message.data[0])

    async def _update_entities(self, data: list[dict]) -> None:
        """Update entities from Message data."""
        async with self.callback_manager:
            for entity in data:
                uid = int(entity["uid"])
                if uid in self.entities_uid:
                    await self.entities_uid[uid].update(entity)
                else:
                    self._logger.debug("Recived Update for unkown entity %s", uid)

    def _create_entities(self, description: DeviceDescription) -> None:
        """Create Entities from Device description."""
        for status in description.get("status", []):
            entity = self._create_entity(status, Status)
            self.status[entity.name] = entity

        for setting in description.get("setting", []):
            entity = self._create_entity(setting, Setting)
            self.settings[entity.name] = entity

        for event in description.get("event", []):
            entity = self._create_entity(event, Event)
            self.events[entity.name] = entity

        for command in description.get("command", []):
            entity = self._create_entity(command, Command)
            self.commands[entity.name] = entity

        for option in description.get("option", []):
            entity = self._create_entity(option, Option)
            self.options[entity.name] = entity

        for program in description.get("program", []):
            entity = self._create_entity(program, Program)
            self.programs[entity.name] = entity

        if "activeProgram" in description:
            entity = self._create_entity(description["activeProgram"], ActiveProgram)
            self._active_program = entity

        if "selectedProgram" in description:
            entity = self._create_entity(
                description["selectedProgram"], SelectedProgram
            )
            self._selected_program = entity

    def _create_entity(
        self, description: EntityDescription, cls: type[Entity]
    ) -> Entity:
        try:
            entity = cls(description, self)
        except Exception:
            self._logger.exception("Failed to add Entity %s", description.get("name"))
        self.entities[entity.name] = entity
        self.entities_uid[entity.uid] = entity
        return entity

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

    def dump(self) -> dict:
        """Dump Appliance state."""
        return {
            "entities": [entity.dump() for entity in self.entities.values()],
            "service_versions": self.session.service_versions,
        }

    @property
    def active_program(self) -> Program | None:
        """Return the current Active Program entity or None if no Program is active."""
        return (
            None
            if self._active_program.value_shadow == 0
            or self._active_program.value_shadow is None
            else self.entities_uid[self._active_program.value]
        )

    @property
    def selected_program(self) -> Program | None:
        """Return current selected Program entity or None if no Program is selected."""
        return (
            None
            if self._selected_program.value_shadow == 0
            or self._selected_program.value_shadow is None
            else self.entities_uid[self._selected_program.value]
        )

    async def _init(self) -> None:
        try:
            async with self.callback_manager:
                # request description changes
                description_changes = await self.session.send_sync(
                    Message(resource="/ro/allDescriptionChanges")
                )
                await self._update_entities(description_changes.data)

                # request mandatory values
                mandatory_values = await self.session.send_sync(
                    Message(resource="/ro/allMandatoryValues")
                )
                await self._update_entities(mandatory_values.data)
        except Exception:
            self._logger.exception("Exception during Appliance init")

    async def _connection_callback(self, new_state: ConnectionState) -> None:
        if new_state == ConnectionState.CONNECTED:
            await self._init()
        try:
            await self._ext_connection_state_callback(new_state)
        except Exception:
            self._logger.exception("Exception in connection state callback")
