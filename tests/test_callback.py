from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import homeconnect_websocket.appliance
import pytest
from homeconnect_websocket.appliance import HomeAppliance
from homeconnect_websocket.entities import (
    Access,
    Entity,
    EntityDescription,
)
from homeconnect_websocket.testutils import (
    BASE_DESCRIPTION,
    TEST_APP_ID,
    TEST_APP_NAME,
    TEST_PSK64,
)


@pytest.mark.asyncio
async def test_call_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test Entity callback."""
    description = BASE_DESCRIPTION.copy()
    description["status"].append(
        EntityDescription(
            uid=1,
            name="Test_Entity",
            available=False,
            access=Access.READ,
            protocolType="Integer",
        )
    )

    monkeypatch.setattr(homeconnect_websocket.appliance, "HCSession", MagicMock())
    appliance = HomeAppliance(
        description, "127.0.0.1", TEST_APP_NAME, TEST_APP_ID, TEST_PSK64
    )
    entity = appliance.entities_uid[1]

    callback_1 = AsyncMock()
    callback_2 = AsyncMock()
    entity.register_callback(callback_1)
    entity.register_callback(callback_2)

    assert entity._callbacks == {callback_1, callback_2}

    await entity.update({"available": True, "access": Access.READ_WRITE, "value": 1})

    await appliance._task_manager.block_till_done()

    callback_1.assert_awaited_once_with(entity)
    callback_2.assert_awaited_once_with(entity)

    entity.unregister_callback(callback_1)
    entity.unregister_callback(callback_2)

    assert entity._callbacks == set()


@pytest.mark.asyncio
async def test_register_unregister_callback() -> None:
    """Test Entity register and unregister callback."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=False,
        access=Access.READ,
        protocolType="Integer",
    )

    entity = Entity(description, AsyncMock())
    callback_1 = AsyncMock()
    callback_2 = AsyncMock()

    entity.register_callback(callback_1)
    entity.register_callback(callback_2)

    assert entity._callbacks == {callback_1, callback_2}

    entity.unregister_callback(callback_1)
    entity.unregister_callback(callback_2)

    assert entity._callbacks == set()


@pytest.mark.asyncio
async def test_callback_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test Entity callback."""
    description = BASE_DESCRIPTION.copy()
    description["status"].append(
        EntityDescription(
            uid=1,
            name="Test_Entity",
            available=False,
            access=Access.READ,
            protocolType="Integer",
        )
    )

    monkeypatch.setattr(homeconnect_websocket.appliance, "HCSession", MagicMock())
    appliance = HomeAppliance(
        description, "127.0.0.1", TEST_APP_NAME, TEST_APP_ID, TEST_PSK64
    )
    entity = appliance.entities_uid[1]

    callback = AsyncMock()
    entity.register_callback(callback)

    await appliance.callback_manager.acquire()  # Acquire 1
    await appliance.callback_manager.acquire()  # Acquire 2

    await entity.update(
        {"uid": 1, "available": True, "access": Access.READ_WRITE, "value": 1}
    )
    await entity.update(
        {"uid": 1, "available": True, "access": Access.READ_WRITE, "value": 2}
    )

    await appliance._task_manager.block_till_done()
    callback.assert_not_awaited()

    await appliance.callback_manager.release()  # Release 1

    await appliance._task_manager.block_till_done()
    callback.assert_not_awaited()

    await appliance.callback_manager.release()  # Release 2

    await appliance._task_manager.block_till_done()
    callback.assert_awaited_once_with(entity)


@pytest.mark.asyncio
async def test_batch_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test Entity callback."""
    description = BASE_DESCRIPTION.copy()
    description["status"].append(
        EntityDescription(
            uid=1,
            name="Test_Entity",
            available=False,
            access=Access.READ,
            protocolType="Integer",
        )
    )

    monkeypatch.setattr(homeconnect_websocket.appliance, "HCSession", MagicMock())
    appliance = HomeAppliance(
        description, "127.0.0.1", TEST_APP_NAME, TEST_APP_ID, TEST_PSK64
    )
    entity = appliance.entities_uid[1]

    callback = AsyncMock()
    entity.register_callback(callback)

    await appliance._update_entities(
        [
            {"uid": 1, "available": True, "access": Access.READ_WRITE, "value": 1},
            {"uid": 1, "available": True, "access": Access.READ_WRITE, "value": 2},
        ]
    )

    await appliance._task_manager.block_till_done()
    callback.assert_awaited_once_with(entity)
