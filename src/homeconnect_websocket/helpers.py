"""Helper functions."""

from __future__ import annotations


def convert_bool(obj: str | bool) -> bool:
    """Convert a string to as bool."""
    if isinstance(obj, str):
        if obj.lower() == "true":
            return True
        if obj.lower() == "false":
            return False
        msg = "Can't convert %s to bool"
        raise TypeError(msg, obj)
    if isinstance(obj, bool):
        return obj
    msg = "Can't convert %s to bool"
    raise TypeError(msg, obj)
