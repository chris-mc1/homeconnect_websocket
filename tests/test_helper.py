from __future__ import annotations

import pytest
from homeconnect_websocket.helpers import convert_bool


def test_convert_bool() -> None:
    """Test str to bool."""
    assert convert_bool("True") is True
    assert convert_bool("true") is True
    assert convert_bool("False") is False
    assert convert_bool("false") is False

    assert convert_bool(True) is True  # noqa: FBT003
    assert convert_bool(False) is False  # noqa: FBT003

    assert convert_bool(0) is False
    assert convert_bool(1) is True
    assert convert_bool(1.5) is True

    assert convert_bool("0") is False
    assert convert_bool("1") is True
    assert convert_bool("1.5") is True

    with pytest.raises(TypeError):
        convert_bool({})
    with pytest.raises(TypeError):
        convert_bool("not bool")
