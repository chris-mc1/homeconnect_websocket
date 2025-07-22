from __future__ import annotations

from .const import ERROR_CODES


class HomeConnectError(Exception):
    """General HomeConnect exception."""


class CodeResponsError(HomeConnectError):
    """Code Response Recived from Appliance."""

    def __init__(self, code: int, resource: str, *args: object) -> None:
        """
        Code Response Recived from Appliance.

        Args:
        ----
        code (int): Recived Code
        resource (str): Recived resource
        *args (object): extra args

        """
        self.code = code
        self.message = ERROR_CODES.get(code, "Unknown")
        self.resource = resource
        super().__init__(*args)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}, resource={self.resource}"


class AccessError(HomeConnectError):
    """Entity not Accessible."""


class NotConnectedError(HomeConnectError):
    """Client is not Connected."""


class ParserError(HomeConnectError):
    """Description Parser Error."""
