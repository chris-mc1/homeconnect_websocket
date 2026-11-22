"""Testing Utilities."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol
from unittest.mock import AsyncMock, Mock

import pytest

from homeconnect_websocket import HomeAppliance
from homeconnect_websocket.callback_manager import CallbackManager
from homeconnect_websocket.entities import DeviceDescription, Program
from homeconnect_websocket.errors import AllreadyConnectedError
from homeconnect_websocket.session import ConnectionState, HCSession
from homeconnect_websocket.task_manager import TaskManager

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from aiohttp import ClientSession

    from homeconnect_websocket.message import Message

TEST_PSK64 = "whZJhkPa3a1hkuDdI3twHdqi1qhTxjnKE8954_zyY_E="
TEST_IV64 = "ofi7M1WB98sJeM2H1Ew3XA=="

TEST_APP_ID = "c6683b15"
TEST_APP_NAME = "Test Device"

BASE_DESCRIPTION = DeviceDescription(
    info={}, status=[], setting=[], event=[], command=[], option=[], program=[]
)


class MockSession(HCSession):
    """Mock HCSession."""

    send: AsyncMock
    send_sync: AsyncMock
    _connect: AsyncMock
    _close: AsyncMock
    _mock_init: bool = False

    def __init__(  # noqa: PLR0913
        self,
        host: str,
        app_name: str,
        app_id: str,
        psk64: str,
        iv64: str | None = None,
        message_handler: Callable[[Message], Awaitable[None]] | None = None,
        *,
        aiohttp_session: ClientSession | None = None,
        logger: logging.Logger | None = None,
        handshake: bool = True,
        connection_state_callback: Callable[[ConnectionState], Awaitable[None]] | None = None,
        task_manager: TaskManager | None = None,
    ) -> None:
        """
        HomeConnect Session.

        Args:
        ----
        host (str): Host.
        app_name (str): Name used to identify this App
        app_id (str): ID used to identify this App
        psk64 (str): urlsafe base64 encoded psk key
        iv64 (Optional[str]): urlsafe base64 encoded iv64 key (only AES)
        message_handler (Callable[[Message], Awaitable[None]]): called for each message
        aiohttp_session (Optional[aiohttp.ClientSession]): ClientSession
        logger (Optional[Logger]): Logger
        handshake (bool): Automatic Handshake
        connection_state_callback (Optional[Callable[[ConnectionState], Awaitable[None]]]): Called when connection state changes
        task_manager (Optional[TaskManager]): Task manager

        """  # noqa: E501
        self._host = host
        self._psk64 = psk64
        self._iv64 = iv64
        self._connection_state_callback = connection_state_callback
        self._app_name = app_name
        self._app_id = app_id
        self._do_handshake = handshake
        self._ext_message_handler = message_handler
        self._logger = logger
        self._aiohttp_session = aiohttp_session
        self._task_manager = TaskManager() if task_manager is None else task_manager

        self.send = AsyncMock()
        self.send_sync = AsyncMock()
        self._connect = AsyncMock()
        self._close = AsyncMock()

    async def connect(self) -> None:
        """Open Connection with Appliance."""
        if self.connection_state in (
            ConnectionState.CONNECTING,
            ConnectionState.HANDSHAKE,
            ConnectionState.CONNECTED,
        ):
            raise AllreadyConnectedError

        await self.set_connection_state(ConnectionState.CONNECTING)
        await self._connect()
        if self._do_handshake:
            await self.set_connection_state(ConnectionState.HANDSHAKE)
        await self.set_connection_state(ConnectionState.CONNECTED)

    async def close(self) -> None:
        """Close connction."""
        if self.connection_state not in (
            ConnectionState.CLOSED,
            ConnectionState.CLOSING,
            ConnectionState.ABNORMAL_CLOSURE,
            ConnectionState.AUTHENTICATION_ERROR,
        ):
            self._set_connection_state(ConnectionState.CLOSING)
            await self._close()
            await self._task_manager.block_till_done()  # Wait for all pending callbacks
            self._set_connection_state(ConnectionState.CLOSED)

        await self._task_manager.block_till_done()  # Wait for connection state callback

    @property
    def connected(self) -> bool:
        """Is connected."""
        return self.connection_state == ConnectionState.CONNECTED

    async def set_connection_state(self, new_state: ConnectionState) -> None:
        """
        Set connection state and execute callback on change.

        Args:
        ----
        new_state (ConnectionState): new connection state

        """
        state_change = self.connection_state != new_state
        self.connection_state = new_state
        if state_change and self._connection_state_callback:
            await self._connection_state_callback(new_state)

    def reset_mock(self) -> None:
        """Reset mock."""
        self.connect.reset_mock()
        self.close.reset_mock()
        self.send.reset_mock()
        self.send_sync.reset_mock()


class MockAppliance(HomeAppliance):
    """Mock HomeAppliance."""

    session: MockSession

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
        self._description = BASE_DESCRIPTION.copy()
        self._description.update(description)
        self.info = self._description.get("info", {})
        self._task_manager = TaskManager()
        self._reconect = reconect
        self._ext_connection_state_callback = connection_callback

        self.session = MockSession(
            host,
            app_name,
            app_id,
            psk64,
            iv64,
            aiohttp_session=session,
            logger=logger,
            connection_state_callback=self._connection_callback,
            task_manager=self._task_manager,
        )

        self.callback_manager = CallbackManager(self._task_manager, Mock(spec=logging.Logger))
        self.entities_uid = {}
        self.entities = {}
        self.status = {}
        self.settings = {}
        self.events = {}
        self.commands = {}
        self.options = {}
        self.programs = {}
        self._create_entities(self._description)

    def dump(self) -> dict:
        """Dump Appliance state."""
        return {
            "entities": [entity.dump() for entity in self.entities.values()],
            "service_versions": None,
        }

    @property
    def selected_program(self) -> Program | None:
        """Return the current selected Program entity or None if no Program is selected."""
        return super().selected_program

    @selected_program.setter
    def selected_program(self, program: Program) -> None:
        self.selected_program_entity._value = program.uid  # noqa: SLF001
        self.selected_program_entity._value_shadow = program.uid  # noqa: SLF001

    @property
    def active_program(self) -> Program | None:
        """Return the current Active Program entity or None if no Program is active."""
        return super().active_program

    @active_program.setter
    def active_program(self, program: Program) -> None:
        self.active_program_entity._value = program.uid  # noqa: SLF001
        self.active_program_entity._value_shadow = program.uid  # noqa: SLF001

    def reset_mock(self) -> None:
        """Reset mock."""
        self.session.reset_mock()

    async def _init(self) -> None:
        return


@pytest.fixture
def mock_homeconnect_appliance() -> MockApplianceType:
    """Mock HomeAppliance for testing."""

    async def go(
        description: DeviceDescription = DESCRIPTION,
        host: str = "127.0.0.1",
        app_name: str = TEST_APP_NAME,
        app_id: str = TEST_APP_ID,
        psk64: str = TEST_PSK64,
        iv64: str | None = TEST_IV64,
    ) -> MockAppliance:
        return MockAppliance(description, host, app_name, app_id, psk64, iv64)

    return go


DESCRIPTION = DeviceDescription(
    {
        "info": {
            "brand": "HomeConnectWS",
            "type": "Dishwasher",
            "model": "FFAA1234",
            "version": 5,
            "revision": 0,
        },
        "status": [
            {
                "access": "read",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 5,
                "name": "BSH.Common.Status.BackendConnected",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 517,
                "name": "BSH.Common.Status.RemoteControlStartAllowed",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 523,
                "name": "BSH.Common.Status.RemoteControlActive",
            },
            {
                "access": "read",
                "available": True,
                "enumeration": {"0": "Open", "1": "Closed"},
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 527,
                "name": "BSH.Common.Status.DoorState",
            },
            {
                "access": "read",
                "available": True,
                "enumeration": {
                    "0": "Inactive",
                    "1": "Ready",
                    "2": "DelayedStart",
                    "3": "Run",
                    "4": "Pause",
                    "5": "ActionRequired",
                    "6": "Finished",
                    "7": "Error",
                    "8": "Aborting",
                },
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 552,
                "name": "BSH.Common.Status.OperationState",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "identifier",
                "protocolType": "Integer",
                "uid": 592,
                "name": "BSH.Common.Status.SoftwareUpdateTransactionID",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "stringList",
                "protocolType": "Object",
                "uid": 614,
                "name": "BSH.Common.Status.ErrorCodesList",
            },
            {
                "access": "read",
                "available": False,
                "contentType": "integer",
                "protocolType": "Integer",
                "uid": 615,
                "name": "BSH.Common.Status.Program.All.Count.Started",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "programSessionSummary",
                "protocolType": "Object",
                "uid": 625,
                "name": "BSH.Common.Status.ProgramSessionSummary.Latest",
            },
            {
                "access": "read",
                "available": True,
                "enumeration": {
                    "0": "ProgramFinished",
                    "1": "ProgramAbortedByUser",
                    "2": "ProgramAbortedByAppliance",
                    "3": "ProgramAbortedByApplianceCriticalError",
                },
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 626,
                "name": "BSH.Common.Status.ProgramRunDetail.EndTrigger",
            },
            {
                "access": "read",
                "available": True,
                "enumeration": {"0": "AsList", "1": "AsButtons"},
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 32771,
                "name": "BSH.Common.Status.Favorite.Handling",
            },
        ],
        "setting": [
            {
                "access": "readwrite",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 3,
                "name": "BSH.Common.Setting.AllowBackendConnection",
            },
            {
                "access": "readwrite",
                "available": True,
                "enumeration": {"1": "Off", "2": "On"},
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 539,
                "name": "BSH.Common.Setting.PowerState",
            },
            {
                "access": "readwrite",
                "available": True,
                "enumeration": {
                    "0": "Monitoring",
                    "1": "ManualRemoteStart",
                    "2": "PermanentRemoteStart",
                },
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 15,
                "name": "BSH.Common.Setting.RemoteControlLevel",
            },
            {
                "access": "readwrite",
                "available": True,
                "enumeration": {"0": "Off", "1": "Program"},
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 32824,
                "name": "BSH.Common.Setting.Favorite.001.Functionality",
            },
            {
                "access": "readwrite",
                "available": True,
                "max": "30",
                "min": "0",
                "contentType": "string",
                "protocolType": "String",
                "uid": 32825,
                "name": "BSH.Common.Setting.Favorite.001.Name",
            },
            {
                "access": "readwrite",
                "available": True,
                "max": "1",
                "min": "0",
                "contentType": "programInstructionList",
                "protocolType": "Object",
                "uid": 32826,
                "name": "BSH.Common.Setting.Favorite.001.Program",
            },
        ],
        "event": [
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "acknowledge",
                "level": "hint",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 21,
                "name": "BSH.Common.Event.SoftwareUpdateAvailable",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "none",
                "level": "hint",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 46,
                "name": "BSH.Common.Event.ConfirmPermanentRemoteStart",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "none",
                "level": "critical",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 525,
                "name": "BSH.Common.Event.AquaStopOccured",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "none",
                "level": "hint",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 540,
                "name": "BSH.Common.Event.ProgramFinished",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "none",
                "level": "alert",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 543,
                "name": "BSH.Common.Event.LowWaterPressure",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "acknowledge",
                "level": "hint",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 545,
                "name": "BSH.Common.Event.ProgramAborted",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "none",
                "level": "warning",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 577,
                "name": "BSH.Common.Event.ConnectLocalWiFi",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "acknowledge",
                "level": "hint",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 593,
                "name": "BSH.Common.Event.SoftwareDownloadAvailable",
            },
            {
                "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
                "handling": "acknowledge",
                "level": "hint",
                "contentType": "enumeration",
                "protocolType": "Integer",
                "uid": 595,
                "name": "BSH.Common.Event.SoftwareUpdateSuccessful",
            },
        ],
        "command": [
            {
                "access": "writeonly",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 1,
                "name": "BSH.Common.Command.DeactivateWiFi",
            },
            {
                "access": "writeonly",
                "available": True,
                "contentType": "uidValue",
                "protocolType": "Integer",
                "uid": 6,
                "name": "BSH.Common.Command.AcknowledgeEvent",
            },
            {
                "access": "writeonly",
                "available": True,
                "contentType": "uidValue",
                "protocolType": "Integer",
                "uid": 16,
                "name": "BSH.Common.Command.RejectEvent",
            },
            {
                "access": "none",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 512,
                "name": "BSH.Common.Command.AbortProgram",
            },
            {
                "access": "writeonly",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 553,
                "name": "BSH.Common.Command.ApplyFactoryReset",
            },
            {
                "access": "writeonly",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 555,
                "name": "BSH.Common.Command.DeactivateRemoteControlStart",
            },
            {
                "access": "writeonly",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 611,
                "name": "BSH.Common.Command.AllowSoftwareUpdate",
            },
            {
                "access": "writeonly",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 594,
                "name": "BSH.Common.Command.AllowSoftwareDownload",
            },
            {
                "access": "writeonly",
                "available": True,
                "contentType": "waterHardness",
                "protocolType": "Integer",
                "uid": 556,
                "name": "BSH.Common.Command.SetWaterHardness",
            },
        ],
        "option": [
            {
                "access": "read",
                "available": True,
                "contentType": "percent",
                "protocolType": "Float",
                "uid": 542,
                "name": "BSH.Common.Option.ProgramProgress",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "timeSpan",
                "protocolType": "Integer",
                "uid": 544,
                "name": "BSH.Common.Option.RemainingProgramTime",
            },
            {
                "access": "read",
                "available": True,
                "initValue": "1",
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 549,
                "name": "BSH.Common.Option.RemainingProgramTimeIsEstimated",
            },
            {
                "access": "read",
                "available": True,
                "max": "86400",
                "min": "0",
                "contentType": "timeSpan",
                "protocolType": "Integer",
                "uid": 558,
                "name": "BSH.Common.Option.StartInRelative",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "percent",
                "protocolType": "Float",
                "uid": 561,
                "name": "BSH.Common.Option.EnergyForecast",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "percent",
                "protocolType": "Float",
                "uid": 562,
                "name": "BSH.Common.Option.WaterForecast",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "string",
                "protocolType": "String",
                "uid": 32772,
                "name": "BSH.Common.Option.ProgramName",
            },
            {
                "access": "readwrite",
                "available": True,
                "contentType": "uidValue",
                "protocolType": "Integer",
                "uid": 32773,
                "name": "BSH.Common.Option.BaseProgram",
            },
            {
                "access": "readwrite",
                "available": True,
                "initValue": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 10000,
                "name": "Test_Option.1",
            },
            {
                "access": "readwrite",
                "available": True,
                "initValue": "str",
                "contentType": "string",
                "protocolType": "String",
                "uid": 10001,
                "name": "Test_Option.2",
            },
            {
                "access": "read",
                "available": True,
                "contentType": "boolean",
                "protocolType": "Boolean",
                "uid": 10002,
                "name": "Test_Option.3",
            },
        ],
        "program": [
            {
                "available": True,
                "uid": 32828,
                "name": "Test_Program",
                "options": [],
            }
        ],
        "activeProgram": {
            "access": "readwrite",
            "uid": 256,
            "name": "BSH.Common.Root.ActiveProgram",
        },
        "selectedProgram": {
            "access": "readwrite",
            "fullOptionSet": False,
            "uid": 257,
            "name": "BSH.Common.Root.SelectedProgram",
        },
    }
)


class MockApplianceType(Protocol):
    """Typing for mock_homeconnect_appliance fixture."""

    async def __call__(  # noqa: D102
        self,
        description: DeviceDescription = DESCRIPTION,
        host: str = "127.0.0.1",
        app_name: str = TEST_APP_NAME,
        app_id: str = TEST_APP_ID,
        psk64: str = TEST_PSK64,
        iv64: str | None = TEST_IV64,
    ) -> MockAppliance:
        pass
