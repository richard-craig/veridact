"""Relying-party policy and per-request inputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class DegradedModePolicy:
    """How old a status list may be before an action is flagged or blocked.

    Defaults follow the table in the spec's Resilience section:
    up to 5 minutes allow everything; 5 minutes to 4 hours allow low risk, allow and
    flag medium risk, block high risk; over 4 hours block everything.
    """

    fresh_seconds: float = 300.0
    stale_limit_seconds: float = 4 * 3600.0

    def evaluate(self, age: float, risk: Risk) -> str:
        """Return 'allow', 'flag' or 'block'."""
        if age <= self.fresh_seconds:
            return "allow"
        if age > self.stale_limit_seconds:
            return "block"
        return {Risk.LOW: "allow", Risk.MEDIUM: "flag", Risk.HIGH: "block"}[risk]


@dataclass(frozen=True)
class RelyingPartyPolicy:
    """Configured once per relying party (or per route)."""

    audience: str
    min_tier: str = "domain"
    allowed_operators: frozenset[str] | None = None  # None means any operator
    allowed_scopes: frozenset[str] | None = None  # None means any scope in the taxonomy
    degraded_mode: DegradedModePolicy = field(default_factory=DegradedModePolicy)
    clock_skew_seconds: int = 30
    require_operator_status: bool = True


@dataclass(frozen=True)
class Payment:
    """A payment the agent is attempting, for delegation-limit checks.

    ``spent_today`` is what the relying party has already let this agent pay today,
    from its own ledger. The verifier is stateless about money.
    """

    amount: Decimal
    currency: str
    spent_today: Decimal = Decimal("0")


@dataclass(frozen=True)
class Request:
    """Per-call inputs: what this route needs."""

    scopes: frozenset[str] = frozenset()
    risk: Risk = Risk.MEDIUM
    payment: Payment | None = None
    min_tier: str | None = None  # overrides the policy's minimum for this route
