"""Relying-party nonces: issued here, single use, short lived.

Production deployments with more than one verifier instance need a shared store
(Redis, DynamoDB with a conditional delete, and so on). Implement ``NonceStore``
with an atomic consume.
"""

from __future__ import annotations

import secrets
import time
from typing import Protocol

from .fetch import Clock


class NonceStore(Protocol):
    def issue(self) -> str: ...

    def is_live(self, nonce: str) -> bool:
        """True if the nonce was issued here, is unexpired and unused."""
        ...

    def consume(self, nonce: str) -> bool:
        """Atomically mark the nonce used. False if it was not live."""
        ...


class InMemoryNonceStore:
    def __init__(self, *, ttl: float = 120.0, clock: Clock = time.time, max_live: int = 100_000):
        self.ttl = ttl
        self.clock = clock
        self.max_live = max_live
        self._live: dict[str, float] = {}

    def _sweep(self) -> None:
        now = self.clock()
        for nonce in [n for n, exp in self._live.items() if exp <= now]:
            del self._live[nonce]

    def issue(self) -> str:
        self._sweep()
        if len(self._live) >= self.max_live:
            raise RuntimeError("too many outstanding nonces")
        nonce = secrets.token_hex(16)
        self._live[nonce] = self.clock() + self.ttl
        return nonce

    def add(self, nonce: str) -> None:
        """Register an externally chosen nonce (tests and vectors)."""
        self._live[nonce] = self.clock() + self.ttl

    def is_live(self, nonce: str) -> bool:
        exp = self._live.get(nonce)
        return exp is not None and exp > self.clock()

    def consume(self, nonce: str) -> bool:
        exp = self._live.pop(nonce, None)
        return exp is not None and exp > self.clock()
