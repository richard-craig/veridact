"""Bitstring Status List checks (W3C Bitstring Status List v1.0, as VC-JWT).

A status list is a signed credential whose subject carries a GZIP-compressed,
multibase base64url-encoded bitstring. Index 0 is the left-most bit of the first
byte. Lists hold at least 131,072 entries, so fetching one tells the issuer
nothing about which agent is being checked.
"""

from __future__ import annotations

import gzip
import io
from dataclasses import dataclass
from typing import Any

from . import jose
from .fetch import ArtefactCache, Fetcher

STATUS_ENTRY_TYPE = "BitstringStatusListEntry"
STATUS_LIST_TYPE = "BitstringStatusListCredential"
MIN_LIST_BITS = 131_072
MAX_LIST_BYTES = 16 * 1024 * 1024  # decompressed cap, against GZIP bombs


class StatusError(Exception):
    pass


@dataclass(frozen=True)
class StatusEntry:
    purpose: str
    index: int
    list_url: str


@dataclass(frozen=True)
class StatusList:
    url: str
    issuer: str
    purpose: str
    bits: bytes
    jws: jose.CompactJws

    def is_set(self, index: int) -> bool:
        if index < 0 or index >= len(self.bits) * 8:
            raise StatusError("status index out of range")
        return bool(self.bits[index // 8] & (0x80 >> (index % 8)))


@dataclass(frozen=True)
class StatusResult:
    entry: StatusEntry
    set: bool
    age: float
    stale: bool


def parse_entries(credential: dict[str, Any]) -> list[StatusEntry]:
    raw = credential.get("credentialStatus")
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    entries = []
    for item in items:
        if not isinstance(item, dict) or item.get("type") != STATUS_ENTRY_TYPE:
            raise StatusError("unsupported credentialStatus entry")
        try:
            index = int(item["statusListIndex"])
        except (KeyError, TypeError, ValueError) as err:
            raise StatusError("statusListIndex must be an integer string") from err
        url = item.get("statusListCredential")
        purpose = item.get("statusPurpose")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise StatusError("statusListCredential must be an https URL")
        if purpose not in ("revocation", "suspension"):
            raise StatusError("statusPurpose must be revocation or suspension")
        entries.append(StatusEntry(purpose, index, url))
    return entries


def decode_bitstring(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not encoded.startswith("u"):
        raise StatusError("encodedList must be multibase base64url ('u' prefix)")
    try:
        compressed = jose.b64url_decode(encoded[1:])
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz:
            bits = gz.read(MAX_LIST_BYTES + 1)
    except (jose.JoseError, OSError, EOFError) as err:
        raise StatusError("encodedList is not valid GZIP") from err
    if len(bits) > MAX_LIST_BYTES:
        raise StatusError("status list too large")
    if len(bits) * 8 < MIN_LIST_BITS:
        raise StatusError("status list shorter than 131,072 entries")
    return bits


def encode_bitstring(bits: bytes) -> str:
    return "u" + jose.b64url_encode(gzip.compress(bits, mtime=0))


def parse_status_list(url: str, token: str) -> StatusList:
    """Parse a status list credential. Its signature is checked by the caller,
    against the issuer's DID and the trust list."""
    try:
        jws = jose.parse(token.strip())
    except jose.JoseError as err:
        raise StatusError(f"malformed status list: {err}") from err
    if jws.typ != "vc+jwt":
        raise StatusError("status list typ must be vc+jwt")
    vc = jws.payload
    if STATUS_LIST_TYPE not in (vc.get("type") or []):
        raise StatusError("not a BitstringStatusListCredential")
    subject = vc.get("credentialSubject") or {}
    if subject.get("type") != "BitstringStatusList":
        raise StatusError("credentialSubject must be a BitstringStatusList")
    issuer = vc.get("issuer")
    issuer = issuer.get("id") if isinstance(issuer, dict) else issuer
    if not isinstance(issuer, str):
        raise StatusError("status list has no issuer")
    # The list must say it is the list at this URL, so one list cannot stand in for another.
    if vc.get("id") != url and subject.get("id") not in (url, url + "#list"):
        raise StatusError("status list id does not match its URL")
    return StatusList(
        url=url,
        issuer=issuer,
        purpose=str(subject.get("statusPurpose")),
        bits=decode_bitstring(subject.get("encodedList")),
        jws=jws,
    )


class StatusLists:
    """Fetches and caches status lists (default: five minutes).

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

    async def check(self, entry: StatusEntry, verify_list, *, expected_issuer: str) -> StatusResult:
        async def load() -> StatusList:
            body = await self.fetcher.fetch(entry.list_url)
            status_list = parse_status_list(entry.list_url, body.decode("ascii"))
            await verify_list(status_list)
            return status_list

        cached = await self.cache.get(
            "status:" + entry.list_url, load, ttl=self.ttl, max_stale=self.max_stale
        )
        status_list: StatusList = cached.value
        # Checked on every use, not only when loaded: credentials from different
        # issuers could name the same URL, and the cached copy was verified for one.
        if status_list.issuer != expected_issuer:
            raise StatusError("status list issued by a different issuer")
        exp = status_list.jws.payload.get("exp")
        if isinstance(exp, int) and self.cache.clock() >= exp:
            raise StatusError("status list has passed its own expiry")
        if status_list.purpose != entry.purpose:
            raise StatusError("status list purpose does not match the entry")
        return StatusResult(entry, status_list.is_set(entry.index), cached.age, cached.stale)
