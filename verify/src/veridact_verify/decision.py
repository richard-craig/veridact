"""The result of a verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .codes import REASON_MAP, Outcome, PublicCode, Reason


class Failure(Exception):
    """Raised inside the verifier to stop at the first failed check."""

    def __init__(self, reason: Reason, detail: str = "", **context: Any):
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail
        self.context = context


@dataclass
class Decision:
    """A verification decision.

    ``outcome`` and ``public_code`` are safe to return to the caller. ``reason``,
    ``detail``, ``check`` and ``context`` belong in the relying party's logs only.
    """

    outcome: Outcome
    public_code: PublicCode | None = None
    reason: Reason | None = None
    detail: str = ""
    check: int | None = None
    # Populated as checks pass, so logs show how far verification got.
    agent: str | None = None
    operator: str | None = None
    operator_domains: list[str] = field(default_factory=list)
    tier: str | None = None
    accountable_role: str | None = None
    issuers: list[str] = field(default_factory=list)
    scopes_held: list[str] = field(default_factory=list)
    scopes_granted: list[str] = field(default_factory=list)
    agent_key_id: str | None = None
    agent_credential_id: str | None = None
    agent_credential_expires: int | None = None
    flags: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW

    @classmethod
    def from_failure(cls, failure: Failure, check: int, partial: "Decision") -> "Decision":
        outcome, code = REASON_MAP[failure.reason]
        partial.outcome = outcome
        partial.public_code = code
        partial.reason = failure.reason
        partial.detail = failure.detail
        context = dict(failure.context)
        partial.check = context.pop("check", check)
        partial.context.update(context)
        partial.scopes_granted = []
        return partial

    def public(self) -> dict[str, Any]:
        """What the caller may see."""
        body: dict[str, Any] = {"decision": self.outcome.value}
        if self.public_code:
            body["code"] = self.public_code.value
        return body

    def log_record(self) -> dict[str, Any]:
        """The full explanation, for the relying party's own logs."""
        return {
            "decision": self.outcome.value,
            "code": self.public_code.value if self.public_code else None,
            "reason": self.reason.value if self.reason else None,
            "detail": self.detail,
            "check": self.check,
            "agent": self.agent,
            "operator": self.operator,
            "operatorDomains": self.operator_domains,
            "tier": self.tier,
            "accountableRole": self.accountable_role,
            "issuers": self.issuers,
            "scopesHeld": self.scopes_held,
            "scopesGranted": self.scopes_granted,
            "agentKeyId": self.agent_key_id,
            "agentCredentialId": self.agent_credential_id,
            "flags": self.flags,
            "context": self.context,
        }
