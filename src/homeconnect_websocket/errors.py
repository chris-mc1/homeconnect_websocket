from __future__ import annotations


class HomeConnectError(Exception):
    """General HomeConnect exception."""


class CodeResponsError(HomeConnectError):
    """Code Respons Recived from Appliance."""

    def __init__(self, code: int, *args: object) -> None:
        """
        Code Respons Recived from Appliance.

        Args:
        ----
        code (int): Recived Code
        *args (object): extra args

        """
        self.code = code
        super().__init__(*args)


class AccessError(HomeConnectError):
    """Entity not Accessible."""


class NotConnectedError(HomeConnectError):
    """Client is not Connected."""


class ParserError(HomeConnectError):
    """Description Parser Error."""
