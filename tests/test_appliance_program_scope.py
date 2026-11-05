"""Tests for Option description changes scoped to a Program (parentUID)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from homeconnect_websocket.entities import Access, DeviceDescription
from homeconnect_websocket.message import Action, Message

if TYPE_CHECKING:
    from homeconnect_websocket.testutils import MockAppliance, MockApplianceType

# Based on a Bosch HMG936AB1 oven
HOT_AIR = 8208
TOP_BOTTOM = 8209
FAVORITE = 32828
SETPOINT = 5120
REMAINING = 544
ACTIVE_PROGRAM = 256
SELECTED_PROGRAM = 257
ABORT = 512
CAVITY = 6073

DESCRIPTION = DeviceDescription(
    info={"brand": "BOSCH", "type": "Oven", "model": "HMG936AB1"},
    status=[
        {
            "uid": CAVITY,
            "name": "Cooking.Oven.Status.Cavity.001.CurrentTemperature",
            "access": "read",
            "available": True,
            "protocolType": "Integer",
        },
    ],
    setting=[],
    event=[],
    command=[
        {
            "uid": ABORT,
            "name": "BSH.Common.Command.AbortProgram",
            "access": "writeonly",
            "available": True,
            "protocolType": "Boolean",
        },
    ],
    option=[
        {
            "uid": SETPOINT,
            "name": "Cooking.Oven.Option.SetpointTemperature",
            "access": "readwrite",
            "available": True,
            "min": 30,
            "max": 300,
            "protocolType": "Integer",
        },
        {
            "uid": REMAINING,
            "name": "BSH.Common.Option.RemainingProgramTime",
            "access": "read",
            "available": True,
            "protocolType": "Integer",
        },
    ],
    program=[
        {
            "uid": HOT_AIR,
            "name": "Cooking.Oven.Program.HeatingMode.HotAir",
            "options": [{"refUID": SETPOINT}, {"refUID": REMAINING}],
        },
        {
            "uid": TOP_BOTTOM,
            "name": "Cooking.Oven.Program.HeatingMode.TopBottomHeating",
            "options": [{"refUID": SETPOINT}, {"refUID": REMAINING}],
        },
        {
            "uid": FAVORITE,
            "name": "BSH.Common.Program.Favorite.001",
            "options": [{"refUID": SETPOINT}, {"refUID": REMAINING}],
        },
    ],
    activeProgram={
        "uid": ACTIVE_PROGRAM,
        "name": "BSH.Common.Root.ActiveProgram",
        "access": "readwrite",
        "available": True,
        "protocolType": "Integer",
    },
    selectedProgram={
        "uid": SELECTED_PROGRAM,
        "name": "BSH.Common.Root.SelectedProgram",
        "access": "readwrite",
        "available": True,
        "protocolType": "Integer",
    },
)


async def notify(appliance: MockAppliance, resource: str, data: list[dict]) -> None:
    """Send a NOTIFY message to the appliance."""
    await appliance._message_handler(Message(resource=resource, action=Action.NOTIFY, data=data))


async def respond(appliance: MockAppliance, resource: str, data: list[dict]) -> None:
    """Send a RESPONSE message to the appliance."""
    await appliance._message_handler(Message(resource=resource, action=Action.RESPONSE, data=data))


@pytest.mark.asyncio
async def test_change_for_other_program_is_not_applied(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """A change for a Program that is not selected does not change the Option."""
    appliance = await mock_homeconnect_appliance(DESCRIPTION)
    setpoint = appliance.entities_uid[SETPOINT]

    # The HMG936AB1 sends this for an empty favorite on every connect
    await respond(
        appliance,
        "/ro/allDescriptionChanges",
        [{"uid": SETPOINT, "parentUID": FAVORITE, "available": False, "access": "READ"}],
    )

    assert setpoint.access == Access.READ_WRITE
    assert setpoint.available is True


@pytest.mark.asyncio
async def test_change_for_selected_program_is_applied(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """A change for the selected Program changes the Option."""
    appliance = await mock_homeconnect_appliance(DESCRIPTION)
    setpoint = appliance.entities_uid[SETPOINT]

    await notify(appliance, "/ro/values", [{"uid": SELECTED_PROGRAM, "value": HOT_AIR}])
    await notify(
        appliance,
        "/ro/descriptionChange",
        [{"uid": SETPOINT, "parentUID": HOT_AIR, "access": "READ"}],
    )

    assert setpoint.access == Access.READ


@pytest.mark.asyncio
async def test_change_for_active_program_is_applied(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """A change for the active Program changes the Option."""
    appliance = await mock_homeconnect_appliance(DESCRIPTION)
    remaining = appliance.entities_uid[REMAINING]

    await notify(appliance, "/ro/values", [{"uid": ACTIVE_PROGRAM, "value": HOT_AIR}])
    await notify(
        appliance,
        "/ro/descriptionChange",
        [{"uid": REMAINING, "parentUID": HOT_AIR, "available": False}],
    )

    assert remaining.available is False


@pytest.mark.asyncio
async def test_change_is_applied_when_program_is_selected_later(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """
    A change for a Program is applied once that Program is selected.

    /ro/allDescriptionChanges is requested before /ro/allMandatoryValues, so the selected
    Program is not known yet when the changes arrive.
    """
    appliance = await mock_homeconnect_appliance(DESCRIPTION)
    setpoint = appliance.entities_uid[SETPOINT]

    await respond(
        appliance,
        "/ro/allDescriptionChanges",
        [{"uid": SETPOINT, "parentUID": HOT_AIR, "access": "READ", "min": 40}],
    )
    assert setpoint.access == Access.READ_WRITE
    assert setpoint.min == 30

    await respond(
        appliance, "/ro/allMandatoryValues", [{"uid": SELECTED_PROGRAM, "value": HOT_AIR}]
    )
    assert setpoint.access == Access.READ
    assert setpoint.min == 40


@pytest.mark.asyncio
async def test_value_for_other_program_is_not_applied(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """The value in a change for another Program is not applied, now or later."""
    appliance = await mock_homeconnect_appliance(DESCRIPTION)
    remaining = appliance.entities_uid[REMAINING]
    await notify(appliance, "/ro/values", [{"uid": REMAINING, "value": 0}])

    await notify(
        appliance,
        "/ro/descriptionChange",
        [{"uid": REMAINING, "parentUID": HOT_AIR, "available": True, "value": 3555}],
    )
    assert remaining.value == 0

    await notify(appliance, "/ro/values", [{"uid": SELECTED_PROGRAM, "value": HOT_AIR}])
    assert remaining.value == 0
    assert remaining.available is True


@pytest.mark.asyncio
async def test_select_other_program(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """
    Selecting another Program, as sent by the HMG936AB1.

    The selected Program changes first, then the appliance sends changes for the new and
    for the previous Program. Only the ones for the new Program apply.
    """
    appliance = await mock_homeconnect_appliance(DESCRIPTION)
    remaining = appliance.entities_uid[REMAINING]
    await notify(appliance, "/ro/values", [{"uid": SELECTED_PROGRAM, "value": HOT_AIR}])

    await notify(appliance, "/ro/values", [{"uid": SELECTED_PROGRAM, "value": TOP_BOTTOM}])
    await notify(
        appliance,
        "/ro/descriptionChange",
        [
            {"uid": REMAINING, "parentUID": TOP_BOTTOM, "available": False},
            {"uid": REMAINING, "parentUID": HOT_AIR, "available": True, "value": 3555},
        ],
    )

    assert remaining.available is False


@pytest.mark.asyncio
async def test_unscoped_changes_are_applied(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """Changes without a Program as parent are applied as before."""
    appliance = await mock_homeconnect_appliance(DESCRIPTION)

    await notify(
        appliance,
        "/ro/descriptionChange",
        [
            # no parentUID
            {"uid": SETPOINT, "max": 250},
            # parentUID 0
            {"uid": SETPOINT, "parentUID": 0, "min": 50},
            # parent is not a Program
            {"uid": REMAINING, "parentUID": CAVITY, "available": False},
            # not an Option
            {"uid": ABORT, "parentUID": HOT_AIR, "available": False},
        ],
    )

    assert appliance.entities_uid[SETPOINT].max == 250
    assert appliance.entities_uid[SETPOINT].min == 50
    assert appliance.entities_uid[REMAINING].available is False
    assert appliance.entities_uid[ABORT].available is False
