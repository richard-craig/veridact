"""A whole Veridact network in one process: issuer, an operator's website, vbot and a
relying party, joined by routes from their canonical https hosts to local test servers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from veridact_issuer import Issuer, IssuerConfig, create_app
from veridact_issuer.validation import StaticTxtResolver
from veridact_sandbox import create_app as create_sandbox
from veridact_sidecar import VerifierConfig
from veridact_sidecar import create_app as create_sidecar
from veridact_verify import RoutedFetcher

ISSUER_HOST = "staging.veridact.test"
OPERATOR_DOMAIN = "operator.veridact.test"
SANDBOX_HOST = "sandbox.veridact.test"


@dataclass
class Network:
    tmp: Path
    issuer: Issuer
    routes: dict[str, str] = field(default_factory=dict)
    servers: list[TestServer] = field(default_factory=list)
    txt: StaticTxtResolver = field(default_factory=StaticTxtResolver)

    @property
    def directory(self) -> str:
        return f"https://{ISSUER_HOST}/directory"

    @property
    def vbot_home(self) -> Path:
        return self.tmp / "vbot"

    def fetcher(self) -> RoutedFetcher:
        return RoutedFetcher(self.routes)

    def rp_config(self, audience: str, **extra) -> VerifierConfig:
        return VerifierConfig(
            audience=audience,
            governance_keys=self.issuer.identity.governance_jwks,
            trust_list_url=self.issuer.config.trust_list_url,
            routes=dict(self.routes),
            # No caching, so a revocation shows on the next call.
            did_ttl=0, status_ttl=0, trust_ttl=0, **extra)

    async def start_sandbox(self) -> str:
        await self.serve(SANDBOX_HOST, create_sandbox(self.rp_config(f"https://{SANDBOX_HOST}")))
        return f"https://{SANDBOX_HOST}"

    async def start_sidecar(self, audience: str, token: str | None = None) -> str:
        server = TestServer(create_sidecar(self.rp_config(audience), api_token=token))
        await server.start_server()
        self.servers.append(server)
        return str(server.make_url("")).rstrip("/")

    async def serve(self, host: str, app: web.Application) -> None:
        server = TestServer(app)
        await server.start_server()
        self.servers.append(server)
        self.routes[host] = str(server.make_url("")).rstrip("/")


def static_site(root: Path) -> web.Application:
    """The operator's own website: serves vbot's publish/ directory."""
    async def handler(request: web.Request) -> web.StreamResponse:
        path = (root / request.match_info["path"]).resolve()
        if not str(path).startswith(str(root.resolve())) or not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(path)

    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    return app


@pytest.fixture
async def network(tmp_path: Path):
    routes: dict[str, str] = {}
    txt = StaticTxtResolver()
    config = IssuerConfig(base_url=f"https://{ISSUER_HOST}", data_dir=str(tmp_path / "issuer"))
    issuer = Issuer(config, fetcher=RoutedFetcher(routes), txt=txt)
    net = Network(tmp_path, issuer, routes, txt=txt)
    await net.serve(ISSUER_HOST, create_app(issuer, background=False))
    await net.serve(OPERATOR_DOMAIN, static_site(net.vbot_home / "publish"))
    # RoutedFetcher copied the routes at construction; point it at the live table.
    issuer.fetcher.routes = routes  # type: ignore[attr-defined]
    yield net
    for server in reversed(net.servers):
        await server.close()
    issuer.store.close()
