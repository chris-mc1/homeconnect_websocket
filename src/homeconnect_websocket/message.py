from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    """Message Actions."""

    GET = "GET"
    POST = "POST"
    RESPONSE = "RESPONSE"
    NOTIFY = "NOTIFY"


def load_message(msg_str: str | dict) -> Message:
    """Load Message from json."""
    message = Message()
    msg = json.loads(msg_str) if isinstance(msg_str, str) else msg_str
    message.sid = int(msg["sID"])
    message.msg_id = int(msg["msgID"])
    message.resource = msg["resource"]
    message.version = int(msg["version"])
    message.action = Action(msg["action"])
    message.data = msg.get("data", None)
    message.code = msg.get("code", None)
    return message


@dataclass
class Message:
    """Represents an Websocket Message."""

    sid: int | None = None
    """Session ID"""
    msg_id: int | None = None
    """Message ID"""
    resource: str | None = None
    """Resource Endpoint"""
    version: int | None = None
    """Service Version"""
    action: Action = Action.GET
    """Action"""
    data: list[dict] | None = None
    """Message Data"""
    code: int | None = None
    """Response Code"""

    def responde(self, data: list[dict] | None = None) -> Message:
        """Generate a response Message."""
        return Message(
            sid=self.sid,
            msg_id=self.msg_id,
            resource=self.resource,
            version=self.version,
            action=Action.RESPONSE,
            data=data,
        )

    def dump(self) -> str:
        """Dump message to string."""
        msg = {
            "sID": self.sid,
            "msgID": self.msg_id,
            "resource": self.resource,
            "version": self.version,
            "action": self.action.value,
        }
        if self.data is not None:
            # data must be list
            if isinstance(self.data, list):
                msg["data"] = self.data
            else:
                msg["data"] = [self.data]
        buf = json.dumps(msg, separators=(",", ":"))
        # swap ' for ""
        return re.sub("'", '"', buf)
