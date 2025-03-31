from __future__ import annotations

from typing import ClassVar
from unittest.mock import AsyncMock

import pytest
from homeconnect_websocket.entities import EntityDescription, Event


class MockAppliance(AsyncMock):
    """Mock Appliance."""

    commands: ClassVar = {
        "BSH.Common.Command.AcknowledgeEvent": AsyncMock(),
        "BSH.Common.Command.RejectEvent": AsyncMock(),
    }


@pytest.mark.asyncio
async def test_acknowledge() -> None:
    """Test Event.acknowledge()."""
    description = EntityDescription(
        uid=1,
        name="Test_Event",
        protocolType="Integer",
    )
    appliance = MockAppliance()
    entity = Event(description, appliance)
    await entity.acknowledge()

    appliance.commands[
        "BSH.Common.Command.AcknowledgeEvent"
    ].execute.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_reject() -> None:
    """Test Event.reject()."""
    description = EntityDescription(
        uid=1,
        name="Test_Event",
        protocolType="Integer",
    )
    appliance = MockAppliance()
    entity = Event(description, appliance)
    await entity.reject()

    appliance.commands[
        "BSH.Common.Command.RejectEvent"
    ].execute.assert_called_once_with(1)
