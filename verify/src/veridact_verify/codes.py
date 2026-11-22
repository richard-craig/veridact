"""Decisions, public reason codes and internal reason codes.

The spec ("Decisions and reason codes") separates what the caller sees from what
the relying party logs. Every internal code maps to exactly one public code and
one outcome, so a caller learns only what it can act on.
"""

from __future__ import annotations

from enum import Enum


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK_PERSON = "ask_person"
    CHALLENGE = "challenge"


class PublicCode(str, Enum):
    # Defined in specification v0.1
    CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    ISSUER_UNTRUSTED = "ISSUER_UNTRUSTED"
    TIER_TOO_LOW = "TIER_TOO_LOW"
    SCOPE_NOT_HELD = "SCOPE_NOT_HELD"
    LIMIT_PER_PAYMENT = "LIMIT_PER_PAYMENT"
    LIMIT_PER_DAY = "LIMIT_PER_DAY"
    AUTH_FAILED = "AUTH_FAILED"
    # Proposed for v0.2 (docs/proposals/0.2-verifier-gaps.md)
    OPERATOR_NOT_ALLOWED = "OPERATOR_NOT_ALLOWED"
    VERIFICATION_UNAVAILABLE = "VERIFICATION_UNAVAILABLE"


class Reason(str, Enum):
    """Internal reason codes, written to the relying party's logs only."""

    # Check 1: the presentation (SD-JWT+KB) and its KB-JWT
    SDJWT_MALFORMED = "SDJWT_MALFORMED"
    KB_MISSING = "KB_MISSING"
    KB_MALFORMED = "KB_MALFORMED"
    KB_TYP = "KB_TYP"
    KB_AUDIENCE = "KB_AUDIENCE"
    NONCE_MISSING = "NONCE_MISSING"
    NONCE_UNKNOWN = "NONCE_UNKNOWN"
    NONCE_REUSED = "NONCE_REUSED"
    KB_EXPIRED = "KB_EXPIRED"
    KB_NOT_YET_VALID = "KB_NOT_YET_VALID"
    SD_HASH_MISMATCH = "SD_HASH_MISMATCH"
    # Checks 2 and 3: the trust list, then the issuer's signature and the disclosures
    VC_TYP = "VC_TYP"
    VC_MALFORMED = "VC_MALFORMED"
    VCT_UNEXPECTED = "VCT_UNEXPECTED"
    ISSUER_METADATA_UNAVAILABLE = "ISSUER_METADATA_UNAVAILABLE"
    ISSUER_METADATA_INVALID = "ISSUER_METADATA_INVALID"
    VC_KID_INVALID = "VC_KID_INVALID"
    VC_SIGNATURE = "VC_SIGNATURE"
    DISCLOSURE_INVALID = "DISCLOSURE_INVALID"
    # Check 4: trust registry
    TRUST_LIST_UNAVAILABLE = "TRUST_LIST_UNAVAILABLE"
    ISSUER_NOT_LISTED = "ISSUER_NOT_LISTED"
    ISSUER_NOT_ACCREDITED_FOR_TIER = "ISSUER_NOT_ACCREDITED_FOR_TIER"
    ISSUER_KEY_NOT_LISTED = "ISSUER_KEY_NOT_LISTED"
    # Check 5: validity and status
    VC_NOT_YET_VALID = "VC_NOT_YET_VALID"
    VC_EXPIRED = "VC_EXPIRED"
    VC_LIFETIME = "VC_LIFETIME"
    VC_TIME_CLAIMS = "VC_TIME_CLAIMS"
    STATUS_ENTRY_MISSING = "STATUS_ENTRY_MISSING"
    STATUS_LIST_INVALID = "STATUS_LIST_INVALID"
    STATUS_UNAVAILABLE = "STATUS_UNAVAILABLE"
    STATUS_STALE = "STATUS_STALE"
    STATUS_REVOKED = "STATUS_REVOKED"
    STATUS_SUSPENDED = "STATUS_SUSPENDED"
    OPERATOR_REVOKED = "OPERATOR_REVOKED"
    OPERATOR_SUSPENDED = "OPERATOR_SUSPENDED"
    # Check 6: key binding
    CNF_MISSING = "CNF_MISSING"
    KB_SIGNATURE = "KB_SIGNATURE"
    KEY_NOT_LOGGED = "KEY_NOT_LOGGED"
    # Check 7: disclosure
    CLAIMS_NOT_DISCLOSED = "CLAIMS_NOT_DISCLOSED"
    # Check 8: relying-party policy
    TIER_TOO_LOW = "TIER_TOO_LOW"
    OPERATOR_NOT_ALLOWED = "OPERATOR_NOT_ALLOWED"
    SCOPE_NOT_HELD = "SCOPE_NOT_HELD"
    LIMIT_PER_PAYMENT = "LIMIT_PER_PAYMENT"
    LIMIT_PER_DAY = "LIMIT_PER_DAY"
    # Client attestations (pattern C) and known-assistant entries
    CLIENT_MISMATCH = "CLIENT_MISMATCH"
    DPOP_KEY_MISMATCH = "DPOP_KEY_MISMATCH"
    ASSISTANT_NOT_LISTED = "ASSISTANT_NOT_LISTED"
    # Anything unexpected inside the verifier fails closed.
    INTERNAL_ERROR = "INTERNAL_ERROR"


_C, _D, _A = Outcome.CHALLENGE, Outcome.DENY, Outcome.ASK_PERSON
P = PublicCode

# internal reason -> (outcome, public code)
REASON_MAP: dict[Reason, tuple[Outcome, PublicCode]] = {
    Reason.NONCE_MISSING: (_C, P.CHALLENGE_REQUIRED),
    Reason.NONCE_UNKNOWN: (_C, P.CHALLENGE_REQUIRED),
    Reason.NONCE_REUSED: (_C, P.CHALLENGE_REQUIRED),
    Reason.KB_EXPIRED: (_C, P.CHALLENGE_REQUIRED),
    Reason.VC_EXPIRED: (_D, P.CREDENTIAL_EXPIRED),
    Reason.VC_NOT_YET_VALID: (_D, P.CREDENTIAL_EXPIRED),
    Reason.ISSUER_NOT_LISTED: (_D, P.ISSUER_UNTRUSTED),
    Reason.ISSUER_NOT_ACCREDITED_FOR_TIER: (_D, P.ISSUER_UNTRUSTED),
    Reason.ISSUER_KEY_NOT_LISTED: (_D, P.ISSUER_UNTRUSTED),
    Reason.TIER_TOO_LOW: (_D, P.TIER_TOO_LOW),
    Reason.SCOPE_NOT_HELD: (_D, P.SCOPE_NOT_HELD),
    Reason.LIMIT_PER_PAYMENT: (_A, P.LIMIT_PER_PAYMENT),
    Reason.LIMIT_PER_DAY: (_A, P.LIMIT_PER_DAY),
    Reason.OPERATOR_NOT_ALLOWED: (_D, P.OPERATOR_NOT_ALLOWED),
    Reason.ISSUER_METADATA_UNAVAILABLE: (_D, P.VERIFICATION_UNAVAILABLE),
    Reason.TRUST_LIST_UNAVAILABLE: (_D, P.VERIFICATION_UNAVAILABLE),
    Reason.STATUS_UNAVAILABLE: (_D, P.VERIFICATION_UNAVAILABLE),
    Reason.STATUS_STALE: (_D, P.VERIFICATION_UNAVAILABLE),
    Reason.STATUS_LIST_INVALID: (_D, P.VERIFICATION_UNAVAILABLE),
}
# Everything else is a signature, tampering or binding failure.
for _r in Reason:
    REASON_MAP.setdefault(_r, (_D, P.AUTH_FAILED))
del _r
