from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from homeconnect_websocket.entities import Access, Entity, EntityDescription, Status
from homeconnect_websocket.errors import AccessError
from homeconnect_websocket.message import Action, Message


def test_init_base() -> None:
    """Test Entity int ."""
    description = EntityDescription(uid=1, name="Test_Entity", protocolType="Integer")
    entity = Entity(description, AsyncMock())
    assert entity.uid == 1
    assert entity.name == "Test_Entity"
    assert entity.value is None
    assert entity.value_raw is None
    assert entity.enum is None


def test_init_full() -> None:
    """Test Entity init full."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=False,
        access=Access.READ,
        enumeration={"0": "Open", "1": "Closed"},
        protocolType="Integer",
    )
    entity = Entity(description, AsyncMock())
    assert entity.uid == 1
    assert entity.name == "Test_Entity"
    assert entity.value is None
    assert entity.value_raw is None
    assert entity.enum == {0: "Open", 1: "Closed"}
    assert entity._rev_enumeration == {"Open": 0, "Closed": 1}


def test_init_object() -> None:
    """Test Entity init full."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        default='{"test": "value", "other": 2}',
        available=False,
        access=Access.READ,
        protocolType="Object",
    )
    entity = Entity(description, AsyncMock())
    assert entity.uid == 1
    assert entity.name == "Test_Entity"
    assert entity.value == {"test": "value", "other": 2}
    assert entity.value_raw == {"test": "value", "other": 2}
    assert entity.enum is None


@pytest.mark.asyncio
async def test_update() -> None:
    """Test Entity.update()."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=False,
        access=Access.READ,
        protocolType="Integer",
    )
    entity = Entity(description, AsyncMock())
    await entity.update({"available": True, "access": Access.READ_WRITE, "value": 1})
    assert entity.value == 1
    assert entity.value_raw == 1


@pytest.mark.asyncio
async def test_update_enum() -> None:
    """Test Entity.update() with Enum."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=False,
        access=Access.READ,
        enumeration={"0": "Open", "1": "Closed"},
        protocolType="Integer",
    )
    entity = Entity(description, AsyncMock())
    await entity.update({"available": True, "access": Access.READ, "value": 1})
    assert entity.value == "Closed"
    assert entity.value_raw == 1


@pytest.mark.asyncio
async def test_set() -> None:
    """Test Entity.set_value()."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=True,
        access=Access.READ_WRITE,
        protocolType="Integer",
    )
    appliance = AsyncMock()
    entity = Entity(description, appliance)
    await entity.set_value(1)
    appliance.session.send_sync.assert_called_with(
        Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": 1, "value": 1},
        )
    )


@pytest.mark.asyncio
async def test_set_raw() -> None:
    """Test Entity.set_value_raw()."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=True,
        access=Access.READ_WRITE,
        protocolType="Integer",
    )
    appliance = AsyncMock()
    entity = Entity(description, appliance)
    await entity.set_value_raw(1)
    appliance.session.send_sync.assert_called_with(
        Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": 1, "value": 1},
        )
    )


@pytest.mark.asyncio
async def test_set_enum() -> None:
    """Test Entity.set_value() with Enum."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=True,
        access=Access.READ_WRITE,
        enumeration={"0": "Open", "1": "Closed"},
        protocolType="Integer",
    )
    appliance = AsyncMock()
    entity = Entity(description, appliance)
    await entity.set_value("Closed")
    appliance.session.send_sync.assert_called_with(
        Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": 1, "value": 1},
        )
    )


@pytest.mark.asyncio
async def test_set_raw_enum() -> None:
    """Test Entity.set_value_raw() with Enum."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=True,
        access=Access.READ_WRITE,
        enumeration={0: "Open", 1: "Closed"},
        protocolType="Integer",
    )
    appliance = AsyncMock()
    entity = Entity(description, appliance)
    await entity.set_value_raw(0)
    appliance.session.send_sync.assert_called_once_with(
        Message(
            resource="/ro/values",
            action=Action.POST,
            data={"uid": 1, "value": 0},
        )
    )


@pytest.mark.asyncio
async def test_callback() -> None:
    """Test Entity callback."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=False,
        access=Access.READ,
        protocolType="Integer",
    )
    entity = Entity(description, AsyncMock())

    callback_1 = MagicMock()
    callback_2 = MagicMock()
    entity.register_callback(callback_1)
    entity.register_callback(callback_2)

    assert entity._callbacks == {callback_1, callback_2}

    await entity.update({"available": True, "access": Access.READ_WRITE, "value": 1})

    callback_1.assert_called_once_with(entity)
    callback_2.assert_called_once_with(entity)

    entity.unregister_callback(callback_1)
    entity.unregister_callback(callback_2)

    assert entity._callbacks == set()


@pytest.mark.asyncio
async def test_access() -> None:
    """Test Entity Access check."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=False,
        access=Access.READ,
        enumeration={"0": "Open", "1": "Closed"},
        protocolType="Integer",
    )
    entity = Status(description, AsyncMock())

    with pytest.raises(AccessError):
        await entity.set_value("Open")

    with pytest.raises(AccessError):
        await entity.set_value_raw(1)

    await entity.update({"access": Access.READ_WRITE})

    with pytest.raises(AccessError):
        await entity.set_value("Open")

    with pytest.raises(AccessError):
        await entity.set_value_raw(1)

    await entity.update({"available": True})

    await entity.set_value("Open")
    await entity.set_value_raw(1)


@pytest.mark.asyncio
async def test_dump() -> None:
    """Test Entity state dump."""
    description = EntityDescription(
        uid=1,
        name="Test_Entity",
        available=False,
        access=Access.READ,
        min=0,
        max=10,
        stepSize=2,
        enumeration={0: "a", 1: "b"},
        protocolType="Integer",
    )
    entity = Status(description, AsyncMock())
    await entity.update({"value": 1})
    assert entity.dump() == {
        "uid": 1,
        "name": "Test_Entity",
        "available": False,
        "value": "b",
        "value_raw": 1,
        "enum": {0: "a", 1: "b"},
        "access": "read",
        "min": 0,
        "max": 10,
        "step": 2,
    }
