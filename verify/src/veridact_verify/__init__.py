"""veridact-verify: reference verifier for Veridact agent presentations (specification v0.5).

    verifier = Verifier(RelyingPartyPolicy(audience="https://api.bank.example"),
                        governance_keys={"gov-2026a": {...}})
    nonce, www_authenticate = verifier.challenge(Request(scopes=frozenset({"fs:claims:read-status"})))
    decision = await verifier.verify(sd_jwt_kb, Request(scopes=frozenset({"fs:claims:read-status"})))
    if decision.allowed: ...
    return decision.public()        # to the caller
    log.info(decision.log_record())  # to your own logs
"""

from .codes import Outcome, PublicCode, Reason
from .decision import Decision
from .fetch import FallbackFetcher, HttpFetcher, MirrorFetcher, RoutedFetcher, StaticFetcher
from .nonce import InMemoryNonceStore, NonceStore
from .policy import DegradedModePolicy, Payment, RelyingPartyPolicy, Request, Risk
from .verifier import Verifier

__all__ = [
    "Decision", "DegradedModePolicy", "FallbackFetcher", "HttpFetcher", "InMemoryNonceStore",
    "MirrorFetcher", "NonceStore", "RoutedFetcher", "Outcome", "Payment", "PublicCode", "Reason",
    "RelyingPartyPolicy", "Request", "Risk", "StaticFetcher", "Verifier",
]
__version__ = "0.5.0a1"
