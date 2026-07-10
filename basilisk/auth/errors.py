from __future__ import annotations


class AuthError(Exception):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__(message)
        self.status = 401
