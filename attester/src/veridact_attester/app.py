"""The Veridact known-assistant attester (reference implementation, v0.5 §6 and §7).

Mainstream assistants (Claude, ChatGPT, Gemini, Copilot) connect to banks as one OAuth client per platform. They do
not hold Veridact keys or run ACME-A. So Veridact verifies the platform's operator itself and issues a credential
*about* the platform, which relying parties check locally. Suspending an entry stops that assistant at every relying
party on its next status check.

Published for relying parties                      Admin (VERIDACT_ADMIN_SECRET; restrict by network too)
  GET /.well-known/jwt-vc-issuer   issuer keys       GET  /admin                              a small control page
  GET /known-assistants            the entries       POST /admin/known-assistants/{id}/status {status, reason}
  GET /known-assistants/{id}       SD-JWT VC
  GET /status/known-assistants/1   statuslist+jwt

This is a reference attester for demonstrations and pilots: software keys on disk, a JSON state file and documentary
validation by a reviewer. A production attester keeps its keys in an HSM, is listed in the governance-signed trust
list and logs every issuance and status change to the transparency log.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from veridact_verify import jose

from . import sdjwt

VCT = "https://veridact.net/vct/known-assistant/v1"
LIST_PATH = "/status/known-assistants/1"
LIST_SIZE = 131_072                     # herd privacy (§7): indexes are random within at least 2^17 entries
ENTRY_LIFETIME = 30 * 86400             # up to 90 days (§2)
log = logging.getLogger("veridact.attester")

# The demo's one entry. A statement by this attester ABOUT a platform; the platform takes no part (§6).
DEFAULT_ENTRIES: dict[str, dict[str, Any]] = {
    "claude": {
        "sub": "claude",            # the bank registers Claude's client itself, so the identifier is a stable name
        "name": "Claude",
        "client_metadata_urls": ["https://claude.ai/oauth/claude-code-client-metadata"],
        "operator": {"name": "Anthropic PBC", "jurisdiction": "US", "verified_on": "2026-11-22",
                     "verification": "documentary review (reference attester, demonstration only)"},
        "redirect_hosts": ["claude.ai", "claude.com"],
        "token_endpoint_auth": {"method": "client_secret", "note": "a bank-registered confidential client"},
        "max_level": "approved_payer",
    },
}


@dataclass
class Config:
    issuer: str
    data_dir: Path
    admin_secret: str
    ttl: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(issuer=os.environ.get("VERIDACT_ISSUER", "http://localhost:8100").rstrip("/"),
                   data_dir=Path(os.environ.get("VERIDACT_DATA", "./attester-data")),
                   admin_secret=os.environ.get("VERIDACT_ADMIN_SECRET", ""),
                   ttl=int(os.environ.get("VERIDACT_STATUS_TTL", "300")))


class Attester:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.data_dir.mkdir(parents=True, exist_ok=True)
        self.key, self.kid = self._key()
        self.state_file = cfg.data_dir / "known-assistants.json"
        self.state = self._load()

    # ------------------------------------------------------------ keys and state
    def _key(self) -> tuple[ec.EllipticCurvePrivateKey, str]:
        path = self.cfg.data_dir / "issuer-key.pem"
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
        jwk = jose.key_to_jwk(key.public_key())
        thumb = jose.b64url_encode(hashlib.sha256(json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")},
                                                             separators=(",", ":"), sort_keys=True).encode()).digest())
        return key, "ka-" + thumb[:16]

    def _load(self) -> dict[str, Any]:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        used: set[int] = set()
        entries = {}
        for eid, claims in DEFAULT_ENTRIES.items():
            idx = secrets.randbelow(LIST_SIZE)
            while idx in used:
                idx = secrets.randbelow(LIST_SIZE)
            used.add(idx)
            entries[eid] = {"claims": claims, "idx": idx, "status": "valid", "jti": f"urn:uuid:{_uuid()}",
                            "history": [{"at": int(time.time()), "status": "valid", "reason": "issued"}]}
        state = {"entries": entries}
        self._save(state)
        return state

    def _save(self, state: dict[str, Any] | None = None) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state or self.state, indent=2))
        tmp.replace(self.state_file)

    # ------------------------------------------------------------ artefacts
    def metadata(self) -> dict[str, Any]:
        return {"issuer": self.cfg.issuer,
                "jwks": {"keys": [{**jose.key_to_jwk(self.key.public_key()), "kid": self.kid, "alg": "ES256",
                                   "use": "sig"}]}}

    def entry(self, eid: str) -> str:
        e = self.state["entries"][eid]
        now = int(time.time())
        claims = {"iss": self.cfg.issuer, "vct": VCT, "jti": e["jti"], "iat": now, "nbf": now,
                  "exp": now + ENTRY_LIFETIME, **e["claims"],
                  "status": {"status_list": {"idx": e["idx"], "uri": self.cfg.issuer + LIST_PATH}}}
        return sdjwt.issue(claims, self.key, self.kid)

    def status_list(self) -> str:
        values = {e["idx"]: sdjwt.STATUS_VALUES[e["status"]] for e in self.state["entries"].values()
                  if e["status"] != "valid"}
        return sdjwt.status_list_token(self.cfg.issuer + LIST_PATH, self.cfg.issuer, values, LIST_SIZE, self.key,
                                       self.kid, int(time.time()), self.cfg.ttl)

    def set_status(self, eid: str, status: str, reason: str) -> dict[str, Any]:
        if status not in sdjwt.STATUS_VALUES:
            raise ValueError("status is valid, withdrawn or suspended")
        e = self.state["entries"][eid]
        if e["status"] == "withdrawn" and status != "withdrawn":
            raise ValueError("a withdrawn entry cannot be restored; issue a new one")
        e["status"] = status
        e["history"].append({"at": int(time.time()), "status": status, "reason": reason[:200]})
        self._save()
        log.warning("known-assistant %s is now %s: %s", eid, status, reason)
        return self.summary(eid)

    def summary(self, eid: str) -> dict[str, Any]:
        e = self.state["entries"][eid]
        return {"id": eid, "name": e["claims"].get("name"), "operator": e["claims"]["operator"]["name"],
                "status": e["status"], "entry": f"{self.cfg.issuer}/known-assistants/{eid}",
                "max_level": e["claims"].get("max_level"), "history": e["history"][-5:]}


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------- HTTP
def create_app(cfg: Config | None = None) -> web.Application:
    cfg = cfg or Config.from_env()
    att = Attester(cfg)
    app = web.Application()
    app["attester"] = att

    def admin_ok(request: web.Request, given: str | None = None) -> bool:
        if not cfg.admin_secret:
            return False
        offered = given if given is not None else request.headers.get("Authorization", "").removeprefix("Bearer ")
        return secrets.compare_digest(offered.encode(), cfg.admin_secret.encode())

    async def metadata(_: web.Request) -> web.Response:
        return web.json_response(att.metadata())

    async def entries(_: web.Request) -> web.Response:
        return web.json_response({"entries": [att.summary(e) | {"history": None} for e in att.state["entries"]]})

    async def entry(request: web.Request) -> web.Response:
        eid = request.match_info["eid"]
        if eid not in att.state["entries"]:
            raise web.HTTPNotFound()
        return web.Response(text=att.entry(eid), content_type="application/dc+sd-jwt")

    async def status(_: web.Request) -> web.Response:
        return web.Response(text=att.status_list(), content_type="application/statuslist+jwt",
                            headers={"Cache-Control": f"max-age={cfg.ttl}"})

    async def set_status(request: web.Request) -> web.Response:
        eid = request.match_info["eid"]
        if request.content_type == "application/json":
            body = await request.json()
            secret = None
        else:
            body = dict(await request.post())
            secret = str(body.get("secret", ""))
        if not admin_ok(request, secret):
            return web.json_response({"error": "unauthorized"}, status=401)
        if eid not in att.state["entries"]:
            raise web.HTTPNotFound()
        try:
            out = att.set_status(eid, str(body.get("status", "")), str(body.get("reason") or "set by the attester"))
        except ValueError as e:
            return web.json_response({"error": "invalid_request", "error_description": str(e)}, status=400)
        if secret is not None:                      # the form: back to the page
            raise web.HTTPSeeOther("/admin?done=" + eid)
        return web.json_response(out)

    async def admin(request: web.Request) -> web.Response:
        rows = []
        for eid in att.state["entries"]:
            s = att.summary(eid)
            hist = "".join(f"<li>{time.strftime('%d %b %H:%M:%S', time.localtime(h['at']))}: {html.escape(h['status'])}"
                           f" ({html.escape(h['reason'])})</li>" for h in reversed(s["history"]))
            buttons = "".join(
                f'<button name="status" value="{v}" class="{v}">{label}</button>'
                for v, label in (("suspended", "Suspend"), ("valid", "Restore"), ("withdrawn", "Withdraw for good")))
            rows.append(f"""<section><h2>{html.escape(s['name'] or eid)} <small>operated by
              {html.escape(s['operator'])}</small> <span class="st {s['status']}">{s['status']}</span></h2>
              <p>Ceiling: {html.escape(str(s['max_level']))} · <a href="/known-assistants/{eid}">entry (SD-JWT VC)</a>
              · <a href="{LIST_PATH}">status list</a></p>
              <form method="post" action="/admin/known-assistants/{eid}/status">
              <input type="password" name="secret" placeholder="admin secret" required>
              <input name="reason" placeholder="reason" value="demonstration: platform incident">
              {buttons}</form><ul>{hist}</ul></section>""")
        page = f"""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Veridact attester</title><style>body{{font:15px system-ui;max-width:760px;margin:2em auto;padding:0 1em}}
section{{border:1px solid #ddd;border-radius:10px;padding:1em;margin:1em 0}}small{{color:#666;font-weight:400}}
.st{{font-size:13px;padding:2px 8px;border-radius:10px;margin-left:6px}}.valid{{background:#d9f2e3}}
.suspended{{background:#fde8c8}}.withdrawn{{background:#f8d4d4}}button{{margin:4px 4px 0 0;padding:6px 12px;
border:0;border-radius:6px;cursor:pointer}}input{{padding:6px;margin:4px 4px 0 0}}</style>
<h1>Veridact known-assistant attester</h1>
<p>Reference attester (demonstration). Relying parties check these entries and the status list themselves; a change
here reaches them on their next status check (status list ttl {cfg.ttl}s).</p>{''.join(rows)}"""
        return web.Response(text=page, content_type="text/html")

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "issuer": cfg.issuer, "entries": len(att.state["entries"])})

    app.add_routes([web.get("/.well-known/jwt-vc-issuer", metadata), web.get("/known-assistants", entries),
                    web.get("/known-assistants/{eid}", entry), web.get(LIST_PATH, status),
                    web.post("/admin/known-assistants/{eid}/status", set_status), web.get("/admin", admin),
                    web.get("/healthz", health)])
    return app
