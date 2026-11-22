"""Everything the issuer publishes for relying parties: Token Status Lists, the trust list
(staging only) and the transparency log.

Status lists follow specification v0.5: Token Status Lists with 2 bits per entry,
131,072 entries each, indexes allocated at random so a list's position says nothing
about issuance order, re-signed at least every 5 minutes (and at once on any change)
with ``exp`` at most 4 hours after ``iat``, naming their own URI in ``sub``. One
credential type per list.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from veridact_verify import status as tsl
from veridact_verify.identifiers import VCT_AGENT, VCT_KNOWN_ASSISTANT, VCT_OPERATOR

from .config import IssuerConfig
from .keys import IssuerIdentity
from .store import Store

STATUS_RESIGN_SECONDS = 240  # under the 5-minute ceiling, with margin for clock skew
STATUS_LIST_LIFETIME = 4 * 3600
LIST_FULL_FRACTION = 0.5  # open a new list once half the indexes are used
KINDS = ("agents", "operators", "assistants")
ENTRIES = tsl.MIN_LIST_ENTRIES


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StatusLists:
    def __init__(self, config: IssuerConfig, identity: IssuerIdentity, store: Store):
        self.config = config
        self.identity = identity
        self.store = store

    def url(self, kind: str, number: int) -> str:
        return f"{self.config.base_url}/status/{kind}/{number}"

    def allocate(self, kind: str) -> tuple[str, int]:
        """Reserve a random unused index; return (list url, index)."""
        if kind not in KINDS:
            raise ValueError(kind)
        lists = self.store.status_lists(kind)
        current = next((sl for sl in reversed(lists)
                        if sl["used_count"] < ENTRIES * LIST_FULL_FRACTION), None)
        if current is None:
            number = (lists[-1]["number"] + 1) if lists else 1
            url = self.url(kind, number)
            self.store.create_status_list(url, kind, number, ENTRIES * tsl.BITS // 8, ENTRIES // 8)
            current = self.store.status_list(url)
        assert current is not None
        used = bytearray(current["used"])
        while True:
            index = secrets.randbelow(ENTRIES)
            if not used[index // 8] & (0x80 >> (index % 8)):
                break
        used[index // 8] |= 0x80 >> (index % 8)
        self.store.save_status_list(current["url"], used=bytes(used),
                                    used_count=current["used_count"] + 1)
        return current["url"], index

    def set_value(self, url: str, index: int, value: int) -> None:
        row = self.store.status_list(url)
        if row is None:
            raise KeyError(url)
        entries = bytearray(row["bits"])
        tsl.put(entries, index, value)
        self.store.save_status_list(url, bits=bytes(entries), dirty=True)

    def value(self, url: str, index: int) -> int:
        row = self.store.status_list(url)
        if row is None:
            raise KeyError(url)
        return tsl.get(row["bits"], index)

    def signed(self, url: str, now: int) -> str | None:
        """The current Status List Token, re-signed when stale or changed."""
        row = self.store.status_list(url)
        if row is None:
            return None
        fresh = (row["jwt"] and not row["dirty"] and row["signed_at"] is not None
                 and now - row["signed_at"] < STATUS_RESIGN_SECONDS)
        if fresh:
            return row["jwt"]
        payload = tsl.status_list_payload(url, self.identity.id, row["bits"], now,
                                          lifetime=STATUS_LIST_LIFETIME)
        jwt = self.identity.signer.sign({"typ": tsl.STATUS_LIST_TYP}, payload)
        self.store.save_status_list(url, jwt=jwt, signed_at=now, dirty=False)
        return jwt

    def refresh_all(self, now: int) -> int:
        """Re-sign every list that needs it. Run on a timer so idle lists stay fresh."""
        count = 0
        for kind in KINDS:
            for row in self.store.status_lists(kind):
                before = row["signed_at"]
                self.signed(row["url"], now)
                if self.store.status_list(row["url"])["signed_at"] != before:  # type: ignore[index]
                    count += 1
        return count


class TrustListPublisher:
    """Staging only: the issuer signs a trust list naming itself.

    Production trust lists come from the governance authority, never from an issuer.
    """

    def __init__(self, config: IssuerConfig, identity: IssuerIdentity):
        if identity.governance_key is None:
            raise ValueError("no governance key: publish_trust_list is off")
        self.config = config
        self.identity = identity
        self._cache: tuple[int, str] | None = None

    def payload(self, now: int) -> dict[str, Any]:
        c = self.config
        return {
            "iss": c.base_url,
            "version": f"{c.environment}-{iso(now)[:10]}",
            "iat": now,
            "exp": now + c.trust_list_lifetime,
            "issuers": [{
                "id": self.identity.id,
                "tiers": list(c.tiers),
                "vcts": [VCT_AGENT, VCT_OPERATOR, VCT_KNOWN_ASSISTANT],
                "keys": [{"kid": self.identity.signer.kid, "jkt": self.identity.jkt,
                          "notBefore": self.identity.key_not_before,
                          "notAfter": self.identity.key_not_after}],
            }],
            "scopes": list(c.scopes),
            "policy": {
                "tierOrder": ["domain", "organisation"],
                "agentCredentialMaxLifetime": c.agent_credential_max_lifetime,
                "presentationMaxLifetime": 120,
                "operatorCredentialMaxLifetime": dict(c.operator_credential_lifetime),
                "knownAssistantMaxLifetime": c.known_assistant_lifetime,
            },
        }

    def signed(self, now: int) -> str:
        # Re-sign daily; a list's iat only moves forward, so verifiers' rollback check holds.
        if self._cache and now - self._cache[0] < 86400:
            return self._cache[1]
        from veridact_verify import jose
        assert self.identity.governance_key is not None
        token = jose.sign({"typ": "trust-list+jwt", "kid": self.identity.governance_kid},
                          self.payload(now), self.identity.governance_key)
        self._cache = (now, token)
        return token


class TransparencyLog:
    """A hash-chained, append-only issuance log.

    A stand-in for the Month 2 tile-based Merkle log (RFC 9162 style): it already
    records every credential before release and lets operators watch their domains,
    but it does not yet produce inclusion proofs or witness-cosigned tree heads.
    """

    LOG_ID = "veridact-staging-log-0"

    def __init__(self, store: Store):
        self.store = store

    @staticmethod
    def _h(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def next_index(self) -> int:
        """The index the next append gets. The issuer signs it into the credential
        (transparencyLogEntry), then appends; issuance is serialised, so it holds."""
        tail = self.store.tlog_tail()
        return (tail["idx"] + 1) if tail else 1

    def entry_id_for(self, index: int) -> str:
        return f"{self.LOG_ID}/{index:09d}"

    def append(self, credential_jwt: str | None, entry: dict[str, Any], now: int,
               expect_index: int | None = None) -> dict[str, Any]:
        """Append an entry. With a credential, its hash is recorded (``type`` names its vct);
        a key event has none."""
        if credential_jwt is not None:
            entry = {**entry, "credentialHash": self._h(credential_jwt.encode())}
        leaf = self._h(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode())
        tail = self.store.tlog_tail()
        prev = tail["chain_hash"] if tail else "0" * 64
        chain = self._h(bytes.fromhex(prev) + bytes.fromhex(leaf))
        index = self.store.tlog_append(leaf, chain, entry, now)
        if expect_index is not None and index != expect_index:
            raise RuntimeError("transparency log index moved during issuance")
        return {"log": self.LOG_ID, "index": index, "leafHash": leaf, "chainHash": chain}

