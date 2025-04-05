from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from homeconnect_websocket.entities import (
    EntityDescription,
    OptionDescription,
    Program,
)
from homeconnect_websocket.message import Action, Message

if TYPE_CHECKING:
    from homeconnect_websocket.testutils import MockApplianceType


@pytest.mark.asyncio
async def test_init(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """Test Progrmm Entity init."""
    description = EntityDescription(
        uid=1,
        name="Test_Program",
        options=[
            OptionDescription(refUID=10000, protocolType="Integer"),
            OptionDescription(refUID=10001, protocolType="Integer"),
            OptionDescription(refUID=10002, protocolType="Integer"),
        ],
    )
    appliance = await mock_homeconnect_appliance()
    entity = Program(description, appliance)

    assert entity._options == [
        appliance.entities_uid[10000],
        appliance.entities_uid[10001],
        appliance.entities_uid[10002],
    ]


@pytest.mark.asyncio
async def test_init_no_options(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """Test Progrmm Entity init."""
    description = EntityDescription(uid=1, name="Test_Program")

    appliance = await mock_homeconnect_appliance()
    entity = Program(description, appliance)

    assert entity._options == []


@pytest.mark.asyncio
async def test_select(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """Test select Progrmm."""
    description = EntityDescription(
        uid=1,
        name="Test_Program",
        options=[
            OptionDescription(refUID=10000),
            OptionDescription(refUID=10001),
            OptionDescription(refUID=10002),
        ],
    )
    appliance = await mock_homeconnect_appliance()
    entity = Program(description, appliance)

    await entity.select()
    appliance.session.send_sync.assert_called_once_with(
        Message(
            resource="/ro/selectedProgram",
            action=Action.POST,
            data={"program": 1, "options": []},
        )
    )


@pytest.mark.asyncio
async def test_start(
    mock_homeconnect_appliance: MockApplianceType,
) -> None:
    """Test start Progrmm."""
    description = EntityDescription(
        uid=1,
        name="Test_Program",
        options=[
            OptionDescription(refUID=10000),
            OptionDescription(refUID=10001),
            OptionDescription(refUID=10002),
        ],
    )
    appliance = await mock_homeconnect_appliance()
    entity = Program(description, appliance)

    await entity.start()
    appliance.session.send_sync.assert_called_once_with(
        Message(
            resource="/ro/activeProgram",
            action=Action.POST,
            data={
                "program": 1,
                "options": [
                    {"uid": 10000, "value": True},
                    {"uid": 10001, "value": "str"},
                ],
            },
        )
    )
