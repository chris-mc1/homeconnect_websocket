from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from homeconnect_websocket.entities import Access, Command, EntityDescription
from homeconnect_websocket.errors import AccessError
from homeconnect_websocket.message import Action, Message


@pytest.mark.asyncio
async def test_execute() -> None:
    """Test Command.execute()."""
    description = EntityDescription(
        uid=1,
        name="Test_Command",
        access=Access.READ_WRITE,
        available=True,
        protocolType="Integer",
    )
    appliance = AsyncMock()
    entity = Command(description, appliance)
    await entity.execute(5)

    appliance.session.send_sync.assert_called_once_with(
        Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": 1, "value": 5},
        )
    )

    entity._available = False
    with pytest.raises(AccessError):
        await entity.execute(5)

    entity._available = True
    entity._access = Access.READ
    with pytest.raises(AccessError):
        await entity.execute(5)
