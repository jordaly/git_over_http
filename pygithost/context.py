"""Application dependency container."""

from __future__ import annotations

from dataclasses import dataclass

from .config import AppConfig


@dataclass(frozen=True, slots=True)
class AppContext:
    config: AppConfig

    @classmethod
    def default(cls) -> AppContext:
        return cls(AppConfig.default_for_platform())
