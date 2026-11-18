"""Public API failures. Never return internal exception text to clients."""

from collections.abc import Sequence


class APIError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        headers: Sequence[tuple[str, str]] = (),
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = list(headers)
