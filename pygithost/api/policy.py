"""Fail-closed access policy until repository collaborator ACLs are available."""

import time
from collections import OrderedDict

from .errors import APIError


def can_read_repository(identity, owner, flat_owner):
    return bool(identity["is_admin"] or (
        owner != flat_owner and owner == identity["username"]))


class RateLimiter:
    """Bounded, per-server fixed windows; accessed only from the server loop."""

    def __init__(self, limit=120, window=60, max_keys=4096):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.windows = OrderedDict()

    def check(self, key):
        now = time.monotonic()
        start, count = self.windows.pop(key, (now, 0))
        if now - start >= self.window:
            start, count = now, 0
        self.windows[key] = (start, count + 1)
        while len(self.windows) > self.max_keys:
            self.windows.popitem(last=False)
        if count >= self.limit:
            retry = max(1, int(self.window - (now - start)) + 1)
            raise APIError(429, "rate_limited", "Request limit exceeded.",
                           headers=[("Retry-After", str(retry))])
