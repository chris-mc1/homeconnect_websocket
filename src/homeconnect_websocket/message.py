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


def load_message(msg: str | dict) -> Message:
        """Load Message from json."""
        message = Message()
        if isinstance(msg, str):
            msg = json.loads(msg)
        message.sid = int(msg["sID"])
        message.msg_id = int(msg["msgID"])
        message.resource = msg["resource"]
        message.version = int(msg["version"])
        message.action = Action(msg["action"])
        if "data" in msg:
            message.data = msg["data"]
        if "code" in msg:
            message.code = msg["code"]
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
    data: dict | list[dict] | None = None
    """Message Data"""
    code: int = None
    """Response Code"""

    def responde(self, data: dict | list[dict] | None = None) -> Message:
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
