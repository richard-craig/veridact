"""did:webvh resolution through cached, mirror-aware fetching.

Log verification (hash chain, SCID, eddsa-jcs-2022 proofs, pre-rotation and
witness rules) is delegated to the did-webvh reference library. This module adds
fetching through the verifier's own fetchers and caches, and key lookup by
verification relationship.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from did_webvh.const import HISTORY_FILENAME, WITNESS_FILENAME
from did_webvh.core.file_utils import AsyncTextReadError, read_str
from did_webvh.core.resolver import DidResolver, HistoryResolver
from did_webvh.history import did_base_url
from did_webvh.verify import WebvhVerifier

from . import jose
from .fetch import ArtefactCache, Fetcher, FetchError

AUTHENTICATION = "authentication"
ASSERTION_METHOD = "assertionMethod"


class DidError(Exception):
    """The DID could not be resolved or the key could not be found."""


class DidUnavailable(DidError):
    """The DID log could not be fetched (as opposed to fetched and found invalid)."""


def split_did_url(did_url: str) -> tuple[str, str]:
    """Split 'did:...#frag' into ('did:...', 'frag')."""
    if not isinstance(did_url, str) or "#" not in did_url:
        raise DidError("DID URL must have a fragment")
    did, frag = did_url.split("#", 1)
    if not did.startswith("did:") or not frag or "?" in did or "/" in did:
        raise DidError("malformed DID URL")
    return did, frag


@dataclass
class ResolvedDid:
    did: str
    document: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def deactivated(self) -> bool:
        return bool(self.metadata.get("deactivated"))

    def _vm_id(self, ref: str) -> str:
        return self.did + ref if ref.startswith("#") else ref

    def key_for(self, kid: str, relationship: str) -> ec.EllipticCurvePublicKey:
        """Return the P-256 key ``kid`` names, only if it is listed for ``relationship``."""
        did, _ = split_did_url(kid)
        if did != self.did:
            raise DidError("kid belongs to a different DID")
        methods: dict[str, dict] = {}
        for vm in self.document.get("verificationMethod", []) or []:
            if isinstance(vm, dict) and isinstance(vm.get("id"), str):
                methods[self._vm_id(vm["id"])] = vm
        allowed = False
        for entry in self.document.get(relationship, []) or []:
            if isinstance(entry, str) and self._vm_id(entry) == kid:
                allowed = True
            elif isinstance(entry, dict) and self._vm_id(str(entry.get("id", ""))) == kid:
                methods[kid] = entry
                allowed = True
        if not allowed:
            raise DidError(f"{kid} is not listed under {relationship}")
        vm = methods.get(kid)
        if vm is None:
            raise DidError(f"{kid} has no verification method")
        controller = vm.get("controller")
        if controller is not None and controller != self.did:
            raise DidError("verification method controlled by another DID")
        try:
            return jose.key_from_verification_method(vm)
        except jose.JoseError as err:
            raise DidError(str(err)) from err


class _FetchingHistory(HistoryResolver):
    def __init__(self, fetcher: Fetcher):
        self.fetcher = fetcher
        self.fetch_failed = False

    async def _text(self, url: str) -> str:
        try:
            body = await self.fetcher.fetch(url)
        except FetchError as err:
            self.fetch_failed = True
            raise AsyncTextReadError(str(err)) from err
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError as err:
            raise AsyncTextReadError(str(err)) from err

    @asynccontextmanager
    async def resolve_entry_log(self, document_id):
        text = await self._text(did_base_url(document_id) + HISTORY_FILENAME)
        async with read_str(text) as reader:
            yield reader

    @asynccontextmanager
    async def resolve_witness_log(self, document_id):
        text = await self._text(did_base_url(document_id) + WITNESS_FILENAME)
        async with read_str(text) as reader:
            yield reader


class WebvhResolver:
    """Resolves and verifies did:webvh DIDs, caching verified documents."""

    def __init__(
        self,
        fetcher: Fetcher,
        cache: ArtefactCache,
        *,
        ttl: float = 300.0,
        max_stale: float = 4 * 3600.0,
    ):
        self.fetcher = fetcher
        self.cache = cache
        self.ttl = ttl
        self.max_stale = max_stale
        self._resolver = DidResolver(WebvhVerifier(verify_proofs=True))

    async def _load(self, did: str) -> ResolvedDid:
        history = _FetchingHistory(self.fetcher)
        result = await self._resolver.resolve(did, history)
        if result.resolution_metadata or result.document is None:
            if history.fetch_failed:
                raise DidUnavailable(f"cannot fetch the DID log for {did}")
            meta = result.resolution_metadata
            detail = meta.serialize() if hasattr(meta, "serialize") else str(meta)
            raise DidError(f"cannot resolve {did}: {detail}")
        return ResolvedDid(did, result.document, result.document_metadata or {})

    async def resolve(self, did: str) -> ResolvedDid:
        if not isinstance(did, str) or not did.startswith("did:webvh:"):
            raise DidError("only did:webvh is supported")
        try:
            cached = await self.cache.get(
                "did:" + did, lambda: self._load(did), ttl=self.ttl, max_stale=self.max_stale
            )
        except DidError:
            raise
        except Exception as err:  # library or network failure
            raise DidError(f"cannot resolve {did}: {err}") from err
        resolved = cached.value
        if resolved.deactivated:
            raise DidError(f"{did} is deactivated")
        return resolved
