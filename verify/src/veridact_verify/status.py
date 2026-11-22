"""Token Status Lists (draft-ietf-oauth-status-list), as Veridact uses them.

A credential points at its entry with

    "status": {"status_list": {"idx": 48213, "uri": "https://status.veridact.net/org/agents/7"}}

and the list at that URI is a JWT, ``typ: statuslist+jwt``, signed by the issuer:

    {"sub": <the uri>, "iss": <issuer>, "iat": ..., "exp": ..., "ttl": 300,
     "status_list": {"bits": 2, "lst": base64url(zlib(bytes))}}

Veridact lists use two bits per entry: 0 VALID, 1 INVALID (revoked), 2 SUSPENDED (3 is
refused). Entry ``i`` sits in byte ``i * bits // 8``, starting at the least significant
bit. Lists hold at least 131,072 entries with random indexes, so fetching one tells the
issuer nothing about which credential is being checked.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import Any

from . import jose
from .fetch import ArtefactCache, Fetcher

STATUS_LIST_TYP = "statuslist+jwt"
BITS = 2
VALID, INVALID, SUSPENDED = 0x00, 0x01, 0x02
MIN_LIST_ENTRIES = 131_072
MAX_LIST_BYTES = 16 * 1024 * 1024  # decompressed cap, against zlib bombs
# Issuers re-sign each list at least every 5 minutes, with exp at most 4 hours after iat.
# Verifiers measure a list's age from its iat.
MAX_LIST_LIFETIME = 4 * 3600
DEFAULT_TTL = 300


class StatusError(Exception):
    pass


@dataclass(frozen=True)
class StatusRef:
    """A credential's pointer into a status list."""

    index: int
    uri: str


def parse_ref(raw: Any, *, field: str = "status") -> StatusRef | None:
    """Read ``{"status_list": {"idx", "uri"}}``; None when the claim is absent."""
    if raw is None:
        return None
    entry = raw.get("status_list") if isinstance(raw, dict) else None
    if not isinstance(entry, dict):
        raise StatusError(f"{field} must hold a status_list reference")
    idx, uri = entry.get("idx"), entry.get("uri")
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
        raise StatusError(f"{field}.status_list.idx must be a non-negative integer")
    if not isinstance(uri, str) or not uri.startswith("https://"):
        raise StatusError(f"{field}.status_list.uri must be an https URL")
    return StatusRef(idx, uri)


def ref_claim(index: int, uri: str) -> dict[str, Any]:
    return {"status_list": {"idx": index, "uri": uri}}


# -- the bit array ----------------------------------------------------------------------------


def get(entries: bytes, index: int, bits: int = BITS) -> int:
    per_byte = 8 // bits
    if index < 0 or index >= len(entries) * per_byte:
        raise StatusError("status index out of range")
    shift = (index % per_byte) * bits
    return (entries[index // per_byte] >> shift) & ((1 << bits) - 1)


def put(entries: bytearray, index: int, value: int, bits: int = BITS) -> None:
    per_byte = 8 // bits
    mask = (1 << bits) - 1
    if not 0 <= value <= mask:
        raise ValueError("status value does not fit")
    shift = (index % per_byte) * bits
    byte = entries[index // per_byte]
    entries[index // per_byte] = (byte & ~(mask << shift) & 0xFF) | (value << shift)


def empty(entries: int = MIN_LIST_ENTRIES, bits: int = BITS) -> bytearray:
    return bytearray(entries * bits // 8)


def encode_list(entries: bytes, bits: int = BITS) -> dict[str, Any]:
    return {"bits": bits, "lst": jose.b64url_encode(zlib.compress(bytes(entries), 9))}


def decode_list(raw: Any) -> tuple[int, bytes]:
    if not isinstance(raw, dict):
        raise StatusError("status_list must be an object")
    bits, lst = raw.get("bits"), raw.get("lst")
    if bits != BITS:
        raise StatusError("Veridact status lists use 2 bits per entry")
    try:
        compressed = jose.b64url_decode(lst)
        inflater = zlib.decompressobj()
        data = inflater.decompress(compressed, MAX_LIST_BYTES + 1)
    except (jose.JoseError, zlib.error) as err:
        raise StatusError("lst is not base64url zlib") from err
    if len(data) > MAX_LIST_BYTES or inflater.unconsumed_tail:
        raise StatusError("status list too large")
    if len(data) * 8 // bits < MIN_LIST_ENTRIES:
        raise StatusError("status list shorter than 131,072 entries")
    return bits, data


# -- the signed list ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StatusList:
    uri: str
    issuer: str
    entries: bytes
    jws: jose.CompactJws
    issued_at: int
    expires_at: int
    ttl: int

    def value(self, index: int) -> int:
        return get(self.entries, index)


def _int(payload: dict, name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise StatusError(f"status list needs an integer {name}")
    return value


def parse_status_list(uri: str, token: str) -> StatusList:
    """Parse a Status List Token. The caller checks the signature against the issuer's
    keys and the trust list."""
    try:
        jws = jose.parse(token.strip(), max_length=4 * 1024 * 1024)
    except jose.JoseError as err:
        raise StatusError(f"malformed status list: {err}") from err
    if jws.typ != STATUS_LIST_TYP:
        raise StatusError(f"status list typ must be {STATUS_LIST_TYP}")
    p = jws.payload
    # The list must say it is the list at this URI, so one list cannot stand in for another.
    if p.get("sub") != uri:
        raise StatusError("status list sub does not match its URI")
    issuer = p.get("iss")
    if not isinstance(issuer, str):
        raise StatusError("status list has no iss")
    iat, exp = _int(p, "iat"), _int(p, "exp")
    if not 0 < exp - iat <= MAX_LIST_LIFETIME:
        raise StatusError("status list exp must be within 4 hours of iat")
    ttl = p.get("ttl", DEFAULT_TTL)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        raise StatusError("ttl must be a positive integer")
    _, entries = decode_list(p.get("status_list"))
    return StatusList(uri, issuer, entries, jws, iat, exp, ttl)


def status_list_payload(uri: str, issuer: str, entries: bytes, iat: int, *,
                        lifetime: int = MAX_LIST_LIFETIME, ttl: int = DEFAULT_TTL) -> dict[str, Any]:
    return {"sub": uri, "iss": issuer, "iat": iat, "exp": iat + lifetime, "ttl": ttl,
            "status_list": encode_list(entries)}


@dataclass(frozen=True)
class StatusResult:
    ref: StatusRef
    value: int
    age: float
    stale: bool


class StatusLists:
    """Fetches and caches status lists (default: five minutes, the lists' own ttl).

    ``verify_list`` is a coroutine supplied by the verifier that checks the list's
    signature against its issuer and the trust list; a list that fails it is never
    cached, so a tampered copy cannot replace a good one.
    """

    def __init__(self, fetcher: Fetcher, cache: ArtefactCache, *, ttl: float = 300.0,
                 max_stale: float = 4 * 3600.0):
        self.fetcher = fetcher
        self.cache = cache
        self.ttl = ttl
        self.max_stale = max_stale
        self._newest_iat: dict[str, int] = {}

    async def check(self, ref: StatusRef, verify_list) -> tuple[StatusResult, StatusList]:
        async def load() -> StatusList:
            body = await self.fetcher.fetch(ref.uri)
            status_list = parse_status_list(ref.uri, body.decode("ascii"))
            await verify_list(status_list)
            # Refuse rollback to an older signed list, for example from a stale mirror.
            if status_list.issued_at < self._newest_iat.get(ref.uri, 0):
                raise StatusError("status list is older than one already seen")
            self._newest_iat[ref.uri] = status_list.issued_at
            return status_list

        cached = await self.cache.get("status:" + ref.uri, load,
                                      ttl=self.ttl, max_stale=self.max_stale)
        status_list: StatusList = cached.value
        now = self.cache.clock()
        if now >= status_list.expires_at:
            raise StatusError("status list has passed its own expiry")
        age = max(0.0, now - status_list.issued_at)
        return StatusResult(ref, status_list.value(ref.index), age, cached.stale), status_list
