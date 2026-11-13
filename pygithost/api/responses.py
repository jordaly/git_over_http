"""Non-JSON API results; errors still use the normal JSON envelope."""

from dataclasses import dataclass


@dataclass(frozen=True)
class BinaryDownload:
    content: bytes
    size: int
    filename: str
