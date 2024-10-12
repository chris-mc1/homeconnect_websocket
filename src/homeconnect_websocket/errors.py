from __future__ import annotations


class HomeConnectError(Exception):
    """General HomeConnect exception."""

class CodeResponsError(HomeConnectError):
    """Code Respons Recived from Appliance."""

    def __init__(self, code: int, *args: object) -> None:
        self.code = code
        super().__init__(*args)

class AccessError(HomeConnectError):
    """Entity not Accessible."""

class NotConnectedError(HomeConnectError):
    """Client is not Connected."""
