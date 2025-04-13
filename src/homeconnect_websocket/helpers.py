"""Helper functions."""

from __future__ import annotations

import contextlib
import json
from typing import Final


def convert_bool(obj: str | bool | float) -> bool:
    """Convert a string to as bool."""
    if isinstance(obj, str):
        if obj.lower() == "true":
            return True
        if obj.lower() == "false":
            return False
        with contextlib.suppress(ValueError):
            obj = float(obj)
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float | int):
        return bool(obj)
    msg = "Can't convert %s to bool"
    raise TypeError(msg, obj)


def load_object(obj: str) -> dict:
    """Load complex objects from json strings."""
    if isinstance(obj, str):
        return json.loads(obj)
    return obj


TYPE_MAPPING: Final[dict[str, type]] = {
    "Boolean": convert_bool,
    "Integer": int,
    "Float": float,
    "String": str,
    "Object": load_object,
    None: lambda value: value,
}
