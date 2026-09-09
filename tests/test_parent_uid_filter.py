"""Tests for parentUID-based filtering of Option entity updates."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import homeconnect_websocket.appliance
import pytest
from homeconnect_websocket.appliance import HomeAppliance
from homeconnect_websocket.entities import (
    Access,
    EntityDescription,
)
from homeconnect_websocket.testutils import (
    BASE_DESCRIPTION,
    TEST_APP_ID,
    TEST_APP_NAME,
    TEST_PSK64,
)

OPTION_UID = 100
STATUS_UID = 200
COMMAND_UID = 300
SELECTED_PROGRAM_UID = 257
ACTIVE_PROGRAM_UID = 256
PROGRAM_A_UID = 500
PROGRAM_B_UID = 501


def _make_appliance(monkeypatch: pytest.MonkeyPatch, *, with_programs: bool = True):
    """Create a HomeAppliance with an option, status, and command entity."""
    description = BASE_DESCRIPTION.copy()
    description["option"] = [
        EntityDescription(
            uid=OPTION_UID,
            name="Test_Option",
            available=True,
            access=Access.READ_WRITE,
            protocolType="Integer",
        ),
    ]
    description["status"] = [
        EntityDescription(
            uid=STATUS_UID,
            name="Test_Status",
            available=True,
            access=Access.READ,
            protocolType="Integer",
        ),
    ]
    description["command"] = [
        EntityDescription(
            uid=COMMAND_UID,
            name="Test_Command",
            available=True,
            access=Access.WRITE_ONLY,
            protocolType="Boolean",
        ),
    ]
    if with_programs:
        description["selectedProgram"] = EntityDescription(
            uid=SELECTED_PROGRAM_UID,
            name="BSH.Common.Root.SelectedProgram",
            access=Access.READ_WRITE,
        )
        description["activeProgram"] = EntityDescription(
            uid=ACTIVE_PROGRAM_UID,
            name="BSH.Common.Root.ActiveProgram",
            access=Access.READ_WRITE,
        )

    monkeypatch.setattr(homeconnect_websocket.appliance, "HCSession", MagicMock())
    return HomeAppliance(
        description, "127.0.0.1", TEST_APP_NAME, TEST_APP_ID, TEST_PSK64
    )


@pytest.mark.asyncio
async def test_option_update_global_parent_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option updates with parentUID=0 (global context) should be applied."""
    appliance = _make_appliance(monkeypatch)
    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    await appliance._update_entities(
        [{"uid": OPTION_UID, "parentUID": 0, "value": 42}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw == 42
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_option_update_none_parent_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option updates with no parentUID should be applied."""
    appliance = _make_appliance(monkeypatch)
    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    await appliance._update_entities([{"uid": OPTION_UID, "value": 42}])

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw == 42
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_option_update_irrelevant_parent_uid_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option updates from an irrelevant parentUID should be skipped."""
    appliance = _make_appliance(monkeypatch)
    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    await appliance._update_entities(
        [{"uid": OPTION_UID, "parentUID": 9999, "value": 42}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw is None
    callback.assert_not_awaited()


@pytest.mark.asyncio
async def test_option_update_selected_program_parent_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option updates from the selected program's parentUID should be applied."""
    appliance = _make_appliance(monkeypatch)

    # Set the selected program to PROGRAM_A_UID
    await appliance.entities_uid[SELECTED_PROGRAM_UID].update(
        {"value": PROGRAM_A_UID}
    )

    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    await appliance._update_entities(
        [{"uid": OPTION_UID, "parentUID": PROGRAM_A_UID, "value": 10}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw == 10
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_option_update_active_program_parent_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option updates from the active program's parentUID should be applied."""
    appliance = _make_appliance(monkeypatch)

    # Set the active program to PROGRAM_B_UID
    await appliance.entities_uid[ACTIVE_PROGRAM_UID].update(
        {"value": PROGRAM_B_UID}
    )

    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    await appliance._update_entities(
        [{"uid": OPTION_UID, "parentUID": PROGRAM_B_UID, "value": 20}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw == 20
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_option_update_other_program_skipped_while_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option updates from a non-active/non-selected program should be skipped."""
    appliance = _make_appliance(monkeypatch)

    # Set the active program to PROGRAM_A_UID
    await appliance.entities_uid[ACTIVE_PROGRAM_UID].update(
        {"value": PROGRAM_A_UID}
    )

    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    # Update from PROGRAM_B_UID (not active/selected) should be skipped
    await appliance._update_entities(
        [{"uid": OPTION_UID, "parentUID": PROGRAM_B_UID, "value": 99}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw is None
    callback.assert_not_awaited()


@pytest.mark.asyncio
async def test_status_update_not_filtered_by_parent_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Status entity updates should not be filtered regardless of parentUID."""
    appliance = _make_appliance(monkeypatch)
    callback = AsyncMock()
    appliance.entities_uid[STATUS_UID].register_callback(callback)

    await appliance._update_entities(
        [{"uid": STATUS_UID, "parentUID": 9999, "value": 7}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[STATUS_UID].value_raw == 7
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_command_update_not_filtered_by_parent_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Command entity updates should not be filtered regardless of parentUID."""
    appliance = _make_appliance(monkeypatch)
    callback = AsyncMock()
    appliance.entities_uid[COMMAND_UID].register_callback(callback)

    await appliance._update_entities(
        [{"uid": COMMAND_UID, "parentUID": 9999, "value": True}]
    )

    await appliance._task_manager.block_till_done()
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_option_no_programs_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option updates should work when no selected/active programs exist."""
    appliance = _make_appliance(monkeypatch, with_programs=False)
    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    # With no programs, only global contexts (0/None) should pass
    await appliance._update_entities(
        [{"uid": OPTION_UID, "parentUID": 0, "value": 5}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw == 5
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_option_no_programs_irrelevant_parent_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Option from irrelevant parentUID should be skipped when no programs set."""
    appliance = _make_appliance(monkeypatch, with_programs=False)
    callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(callback)

    await appliance._update_entities(
        [{"uid": OPTION_UID, "parentUID": 9999, "value": 5}]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw is None
    callback.assert_not_awaited()


@pytest.mark.asyncio
async def test_mixed_entities_batch_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batch update with mixed entities: option filtered, status not filtered."""
    appliance = _make_appliance(monkeypatch)

    option_callback = AsyncMock()
    status_callback = AsyncMock()
    appliance.entities_uid[OPTION_UID].register_callback(option_callback)
    appliance.entities_uid[STATUS_UID].register_callback(status_callback)

    await appliance._update_entities(
        [
            # Option from irrelevant parent - should be skipped
            {"uid": OPTION_UID, "parentUID": 9999, "value": 42},
            # Status from same irrelevant parent - should be applied
            {"uid": STATUS_UID, "parentUID": 9999, "value": 7},
        ]
    )

    await appliance._task_manager.block_till_done()
    assert appliance.entities_uid[OPTION_UID].value_raw is None
    assert appliance.entities_uid[STATUS_UID].value_raw == 7
    option_callback.assert_not_awaited()
    status_callback.assert_awaited_once()
