"""Helper functions."""

from __future__ import annotations

import contextlib
from math import ceil
from typing import Final

import json_repair


def convert_bool(obj: str | bool | float) -> bool:  # noqa: FBT001
    """Convert string to bool."""
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


def load_object(obj_str: str) -> dict:
    """Load complex objects from json strings."""
    if isinstance(obj_str, str):
        try:
            return json_repair.loads(obj_str)
        except Exception as exc:
            msg = "Can't decode JSON"
            raise TypeError(msg) from exc
    return obj_str


TYPE_MAPPING: Final[dict[str, type]] = {
    "Boolean": convert_bool,
    "Integer": int,
    "Float": float,
    "String": str,
    "Object": load_object,
    None: lambda value: value,
}


def format_hex(n: int) -> str:
    """Convert int to hex string."""
    if n == 0:
        return "0x00"
    return f"0x{n:0{ceil(n.bit_length() / 8) * 2}X}"
