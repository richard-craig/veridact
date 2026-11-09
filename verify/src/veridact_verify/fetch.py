"""Fetching and caching of public artefacts.

Relying parties only ever read public, signed, cacheable files (spec: Architecture
overview). Integrity comes from signatures, never from the transport, so a member
mirror or a CDN can serve any of them.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar
from urllib.parse import urlsplit

Clock = Callable[[], float]
T = TypeVar("T")

MAX_ARTEFACT_BYTES = 8 * 1024 * 1024


class FetchError(Exception):
    """An artefact could not be fetched."""


class Fetcher(Protocol):
    async def fetch(self, url: str) -> bytes: ...


class StaticFetcher:
    """Serves artefacts from memory. Used by tests, vectors and air-gapped setups."""

    def __init__(self, files: Mapping[str, bytes | str] | None = None):
        self.files: dict[str, bytes] = {}
        self.requests: list[str] = []
        self.offline = False
        for url, body in (files or {}).items():
            self.put(url, body)

    def put(self, url: str, body: bytes | str) -> None:
        self.files[url] = body.encode() if isinstance(body, str) else body

    async def fetch(self, url: str) -> bytes:
        self.requests.append(url)
        if self.offline:
            raise FetchError(f"offline: {url}")
        try:
            return self.files[url]
        except KeyError:
            raise FetchError(f"not found: {url}") from None


class HttpFetcher:
    """HTTPS fetcher with a timeout and a response size cap."""

    def __init__(self, *, timeout: float = 5.0, max_bytes: int = MAX_ARTEFACT_BYTES):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._session = None

    async def _get_session(self):
        import aiohttp

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={"User-Agent": "veridact-verify/0.1"},
            )
        return self._session

    async def fetch(self, url: str) -> bytes:
        import aiohttp

        if urlsplit(url).scheme != "https":
            raise FetchError(f"only https is allowed: {url}")
        session = await self._get_session()
        try:
            async with session.get(url, allow_redirects=False) as resp:
                if resp.status != 200:
                    raise FetchError(f"HTTP {resp.status} for {url}")
                body = await resp.content.read(self.max_bytes + 1)
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            raise FetchError(f"{type(err).__name__} for {url}") from err
        if len(body) > self.max_bytes:
            raise FetchError(f"artefact too large: {url}")
        return body

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()


class MirrorFetcher:
    """Reads https://host/path from {base}/host/path on a member mirror."""

    def __init__(self, base_url: str, inner: Fetcher):
        self.base_url = base_url.rstrip("/")
        self.inner = inner

    async def fetch(self, url: str) -> bytes:
        parts = urlsplit(url)
        return await self.inner.fetch(f"{self.base_url}/{parts.netloc}{parts.path}")


class FallbackFetcher:
    """Tries each fetcher in order: typically a member mirror first, then the origin."""

    def __init__(self, fetchers: Sequence[Fetcher]):
        if not fetchers:
            raise ValueError("at least one fetcher is required")
        self.fetchers = list(fetchers)

    async def fetch(self, url: str) -> bytes:
        errors = []
        for fetcher in self.fetchers:
            try:
                return await fetcher.fetch(url)
            except FetchError as err:
                errors.append(str(err))
        raise FetchError("; ".join(errors))


@dataclass
class Cached(Generic[T]):
    value: T
    fetched_at: float
    age: float
    stale: bool


class ArtefactCache:
    """A TTL cache that remembers the last good value for bounded stale use.

    ``ttl`` is how long a value is used without refreshing. ``max_stale`` is how long
    after fetching the last good value may still be returned when a refresh fails.
    The caller sees the age and decides what a stale value is good for.
    """

    def __init__(self, clock: Clock = time.time):
        self.clock = clock
        self._entries: dict[str, tuple[object, float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def clear(self) -> None:
        self._entries.clear()

    async def get(
        self,
        key: str,
        loader: Callable[[], Awaitable[T]],
        *,
        ttl: float,
        max_stale: float,
    ) -> Cached[T]:
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            now = self.clock()
            entry = self._entries.get(key)
            if entry is not None and now - entry[1] < ttl:
                return Cached(entry[0], entry[1], now - entry[1], False)  # type: ignore[arg-type]
            try:
                value = await loader()
            except Exception:
                if entry is not None and now - entry[1] <= max_stale:
                    return Cached(entry[0], entry[1], now - entry[1], True)  # type: ignore[arg-type]
                raise
            self._entries[key] = (value, now)
            return Cached(value, now, 0.0, False)
