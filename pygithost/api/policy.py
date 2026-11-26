"""Fail-closed access policy until repository collaborator ACLs are available."""

import time
from collections import OrderedDict
from collections.abc import Hashable

from .errors import APIError
from .types import Identity


def can_read_repository(identity: Identity, owner: str, repo: str, flat_owner: str) -> bool:
    # A repository-bound token never reaches another repository, whoever owns it.
    bound = identity.get("repository")
    if bound is not None and tuple(bound) != (owner, repo):
        return False
    return bool(identity["is_admin"] or (owner != flat_owner and owner == identity["username"]))


class RateLimiter:
    """Bounded, per-server fixed windows; accessed only from the server loop."""

    def __init__(self, limit: int = 120, window: int = 60, max_keys: int = 4096) -> None:
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.windows: OrderedDict[Hashable, tuple[float, int]] = OrderedDict()

    def check(self, key: Hashable) -> None:
        now = time.monotonic()
        start, count = self.windows.pop(key, (now, 0))
        if now - start >= self.window:
            start, count = now, 0
        self.windows[key] = (start, count + 1)
        while len(self.windows) > self.max_keys:
            self.windows.popitem(last=False)
        if count >= self.limit:
            retry = max(1, int(self.window - (now - start)) + 1)
            raise APIError(
                429,
                "rate_limited",
                "Request limit exceeded.",
                headers=[("Retry-After", str(retry))],
            )
