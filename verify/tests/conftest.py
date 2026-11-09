from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from veridact_verify import InMemoryNonceStore, RelyingPartyPolicy, Verifier
from veridact_verify.testing import NOW, MockNetwork
from veridact_verify.testing.mock_network import AUDIENCE, TRUST_LIST_URL


@dataclass
class Clock:
    now: float = NOW

    def __call__(self) -> float:
        return self.now


@dataclass
class Env:
    net: MockNetwork
    clock: Clock = field(default_factory=Clock)

    def verifier(self, **policy) -> Verifier:
        policy.setdefault("audience", AUDIENCE)
        policy.setdefault("min_tier", "organisation")
        return Verifier(
            RelyingPartyPolicy(**policy),
            governance_keys=self.net.governance_keys,
            fetcher=self.net.fetcher,
            nonces=InMemoryNonceStore(clock=self.clock),
            clock=self.clock,
            trust_list_url=TRUST_LIST_URL,
        )


@pytest.fixture
def env() -> Env:
    return Env(MockNetwork())


@pytest.fixture
def domain_env() -> Env:
    return Env(MockNetwork(tier="domain"))
