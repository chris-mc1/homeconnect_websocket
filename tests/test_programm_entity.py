from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from homeconnect_websocket.entities import (
    EntityDescription,
    OptionDescription,
    Program,
)
from homeconnect_websocket.message import Action, Message
from homeconnect_websocket.testutils import MockAppliance

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from homeconnect_websocket.testutils import MockAppliance


@pytest.mark.asyncio
async def test_init(
    mock_homeconnect_appliance: Callable[..., Awaitable[MockAppliance]],
) -> None:
    """Test Progrmm Entity init."""
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

    assert entity._options == [
        appliance.entities_uid[10000],
        appliance.entities_uid[10001],
        appliance.entities_uid[10002],
    ]


@pytest.mark.asyncio
async def test_select(
    mock_homeconnect_appliance: Callable[..., Awaitable[MockAppliance]],
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
    mock_homeconnect_appliance: Callable[..., Awaitable[MockAppliance]],
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
