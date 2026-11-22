"""vbot: the Veridact agent client, as a library (specification v0.5).

    bot = Vbot.load("~/.vbot")
    presentation = bot.presentation("a7f3k2", aud="https://api.bank.example", nonce=nonce)

One home directory holds an operator and its agents: state.json plus keys/ (mode
0600). publish/ holds the files the operator serves on its own domain:
``.well-known/veridact-operator.json`` and, for agents it hosts itself, each agent's
Client ID Metadata Document at ``agents/{id}``.
"""

from __future__ import annotations

import json
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from veridact_verify import sdjwt
from veridact_verify.identifiers import (
    VCT_DELEGATION,
    client_metadata_document,
    operator_metadata_document,
    operator_metadata_url,
    operator_url,
)

from .acme import AcmeClient
from .keys import SoftwareKeyStore

KB_TYP = "veridact-kb+jwt"
RENEW_FRACTION = 2 / 3


class VbotError(Exception):
    pass


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _claims(credential: str) -> dict[str, Any]:
    return sdjwt.parse(credential).claims()


@dataclass
class Vbot:
    home: Path
    state: dict[str, Any]

    # -- persistence ----------------------------------------------------------------

    @classmethod
    def load(cls, home: str | Path) -> "Vbot":
        home = Path(home).expanduser()
        path = home / "state.json"
        if not path.exists():
            raise VbotError(f"no vbot state in {home}: run `vbot init` first")
        state = json.loads(path.read_text())
        if state.get("version") != 5:
            raise VbotError(f"{home} holds a v0.4 (did:webvh) state; v0.5 is a clean cut: use a new home")
        return cls(home, state)

    @classmethod
    def create(cls, home: str | Path, issuer: str, routes: dict[str, str] | None = None) -> "Vbot":
        home = Path(home).expanduser()
        if (home / "state.json").exists():
            raise VbotError(f"{home} already holds a vbot state")
        home.mkdir(parents=True, exist_ok=True)
        bot = cls(home, {"version": 5, "issuer": issuer, "routes": routes or {}, "agents": {}})
        bot.save()
        return bot

    def save(self) -> None:
        tmp = self.home / "state.json.tmp"
        tmp.write_text(json.dumps(self.state, indent=2))
        tmp.replace(self.home / "state.json")

    @property
    def keys(self) -> SoftwareKeyStore:
        return SoftwareKeyStore(self.home)

    @property
    def publish_dir(self) -> Path:
        return self.home / "publish"

    def client(self) -> AcmeClient:
        return AcmeClient(self.state["issuer"], self.keys.get_or_create("account"),
                          routes=self.state.get("routes"), account_url=self.state.get("account"))

    def agent(self, agent_id: str) -> dict[str, Any]:
        try:
            return self.state["agents"][agent_id]
        except KeyError:
            raise VbotError(f"no agent {agent_id!r}; agents: {sorted(self.state['agents'])}") from None

    def default_agent(self) -> str:
        agents = sorted(self.state["agents"])
        if len(agents) != 1:
            raise VbotError(f"say which agent (--agent): {agents}")
        return agents[0]

    # -- account --------------------------------------------------------------------

    async def register(self, contact: list[str] | None = None) -> str:
        async with self.client() as acme:
            url = await acme.register(contact)
            self.state["account"] = url
            self.state["slug"] = acme.account.get("veridactSlug")
            directory = await acme.directory()
            meta = directory["meta"]
            self.state["agentHosting"] = meta.get("veridactAgentHosting")
            self.state["environment"] = meta.get("veridactEnvironment", "staging")
        self.save()
        return url

    # -- operator ----------------------------------------------------------------------

    def create_operator(self, domain: str) -> dict[str, Any]:
        """Create the operator's delegation key and the file the operator must serve."""
        domain = domain.lower().rstrip(".")
        if self.state.get("operator"):
            raise VbotError("this home already has an operator")
        key = self.keys.get_or_create("operator")
        operator = operator_url(domain)
        files = {self._publish_path(operator_metadata_url(operator)):
                 json.dumps(operator_metadata_document(operator, [key.jwk]), indent=2)}
        self._write_publish(files)
        self.state["operator"] = {"domain": domain, "id": operator, "jkt": key.jkt}
        self.save()
        return {"operator": operator, "files": sorted(str(p) for p in files)}

    def _publish_path(self, url: str) -> Path:
        return self.publish_dir / urlsplit(url).path.lstrip("/")

    def _write_publish(self, files: dict[Path, str]) -> None:
        for path, text in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def operator(self) -> dict[str, Any]:
        op = self.state.get("operator")
        if not op:
            raise VbotError("no operator yet: run `vbot init --domain ...`")
        return op

    async def obtain_operator_credential(self, *, challenge: str = "operator-keys-01",
                                         before_respond=None) -> dict[str, Any]:
        """Order the Operator Credential. ``before_respond(txt_name, txt_value)`` is awaited
        for dns-01, so the caller can publish the record first."""
        op = self.operator()
        key = self.keys.get("operator")
        async with self.client() as acme:
            order_url, order = await acme.new_order({"type": "dns", "value": op["domain"]})
            authz = await acme.get(order["authorizations"][0])
            ch = next((c for c in authz["challenges"] if c["type"] == challenge), None)
            if ch is None:
                raise VbotError(f"issuer did not offer {challenge}")
            payload = {"key": op["jkt"]} if challenge == "operator-keys-01" else {}
            if challenge == "dns-01" and before_respond is not None:
                await before_respond(f"_acme-challenge.{op['domain']}", self.dns01_record(ch["token"]))
            result = await acme.respond(ch["url"], payload)
            if result["status"] != "valid":
                raise VbotError(f"{challenge} failed: {result.get('error', {}).get('detail', result)}")
            order = await acme.wait_ready(order_url)
            order = await acme.finalize(order, lambda nonce: self._key_binding(
                key, op["id"], order["finalize"], nonce))
            credential, receipt = await acme.download(order["credential"])
        op.update(credential=credential, credentialUrl=order["credential"],
                  credentialId=_claims(credential)["jti"], receipt=receipt)
        self.save()
        return op

    def dns01_record(self, token: str) -> str:
        """The TXT value for dns-01, if you prefer DNS to operator-keys-01."""
        import hashlib

        from veridact_verify import jose
        thumb = self.keys.get_or_create("account").jkt
        return jose.b64url_encode(hashlib.sha256(f"{token}.{thumb}".encode()).digest())

    # -- agents --------------------------------------------------------------------------

    async def create_agent(self, *, hosted: bool = True, agent_id: str | None = None,
                           name: str | None = None) -> dict[str, Any]:
        """Create the agent key and its Client ID Metadata Document: uploaded to the issuer
        (hosted) or written to publish/ for the operator's own domain."""
        op = self.operator()
        agent_id = agent_id or ("a" + secrets.token_hex(3))
        if agent_id in self.state["agents"]:
            raise VbotError(f"agent {agent_id} exists")
        if hosted:
            base, slug = self.state.get("agentHosting"), self.state.get("slug")
            if not base or not slug:
                raise VbotError("register with an issuer that hosts agent metadata first")
            client_id = f"{base}/{slug}/{agent_id}"
        else:
            client_id = f"https://{op['domain']}/agents/{agent_id}"
        key = self.keys.get_or_create(f"agent-{agent_id}")
        doc = client_metadata_document(client_id, [key.jwk], name=name)
        if hosted:
            async with self.client() as acme:
                if await acme.upload_metadata(agent_id, doc) != client_id:
                    raise VbotError("the issuer hosted the agent at an unexpected URL")
        else:
            self._write_publish({self._publish_path(client_id): json.dumps(doc, indent=2)})
        self.state["agents"][agent_id] = {"id": client_id, "jkt": key.jkt, "hosted": hosted}
        self.save()
        return {"id": agent_id, "client_id": client_id, "jkt": key.jkt, "hosted": hosted}

    def delegate(self, agent_id: str, scopes: list[str], *, role: str, days: int = 30,
                 max_lifetime: int = 8 * 3600, limits: dict[str, str] | None = None,
                 audiences: list[str] | None = None) -> str:
        """The operator signs a Delegation Credential (an SD-JWT VC) for the agent.

        Staging simplification: the operator's key signs as the approver. Approver
        Credentials and the two-person rule come next (spec: Delegation and human intent).
        """
        op = self.operator()
        agent = self.agent(agent_id)
        if not 1 <= days <= 90:
            raise VbotError("a delegation lasts 1 to 90 days")
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": op["id"], "vct": VCT_DELEGATION, "jti": f"urn:uuid:{uuid.uuid4()}",
            "sub": agent["id"], "iat": now, "nbf": now, "exp": now + days * 86400,
            "scopes": sorted(set(scopes)), "accountable_role": role, "max_lifetime": max_lifetime,
            "environment": self.state.get("environment", "staging"),
        }
        if limits:
            claims["limits"] = limits
        if audiences:
            claims["audiences"] = audiences
        key = self.keys.get("operator")
        token = sdjwt.issue({}, claims, {}, lambda h, p: key.sign({**h, "kid": op["jkt"]}, p))
        agent["delegation"] = token
        self.save()
        return token

    async def issue(self, agent_id: str, *, lifetime: int | None = None,
                    attestation: bool = False) -> dict[str, Any]:
        """Obtain (or renew) the agent's Agent Credential, and with ``attestation`` its
        Client Attestation form for pattern C."""
        agent = self.agent(agent_id)
        if not agent.get("delegation"):
            raise VbotError(f"agent {agent_id} has no delegation: run `vbot delegate` first")
        key = self.keys.get(f"agent-{agent_id}")
        formats = ["dc+sd-jwt", "client-attestation"] if attestation else None
        async with self.client() as acme:
            order_url, order = await acme.new_order({"type": "agent", "value": agent["id"]},
                                                    lifetime=lifetime, formats=formats)
            authz = await acme.get(order["authorizations"][0])
            ch = next(c for c in authz["challenges"] if c["type"] == "delegation-01")
            result = await acme.respond(ch["url"], {"delegation": agent["delegation"]})
            if result["status"] != "valid":
                raise VbotError(f"delegation-01 failed: {result.get('error', {}).get('detail', result)}")
            order = await acme.wait_ready(order_url)
            order = await acme.finalize(order, lambda nonce: self._key_binding(
                key, agent["id"], order["finalize"], nonce))
            credential, receipt = await acme.download(order["credential"])
            client_attestation = None
            if attestation:
                client_attestation, _ = await acme.download(order["attestation"])
        claims = _claims(credential)
        agent.update(credential=credential, credentialUrl=order["credential"], credentialId=claims["jti"],
                     iat=claims["iat"], exp=claims["exp"], receipt=receipt)
        if client_attestation:
            agent["attestation"] = client_attestation
        self.save()
        return agent

    @staticmethod
    def _key_binding(key, subject: str, finalize_url: str, nonce: str) -> str:
        return key.sign({"typ": KB_TYP, "kid": key.jkt},
                        {"iss": subject, "aud": finalize_url, "nonce": nonce, "iat": int(time.time())})

    def renewal_due(self, agent_id: str, now: float | None = None) -> float:
        """Seconds until renewal is due (<= 0: due now). Two thirds through the lifetime."""
        agent = self.agent(agent_id)
        if not agent.get("credential"):
            return 0
        now = time.time() if now is None else now
        due = agent["iat"] + (agent["exp"] - agent["iat"]) * RENEW_FRACTION
        return due - now

    async def revoke(self, target: str, reason: str = "unspecified") -> None:
        """Revoke an agent's credential (agent id) or the Operator Credential ("operator")."""
        if target == "operator":
            cred = self.operator().get("credential")
        else:
            cred = self.agent(target).get("credential")
        if not cred:
            raise VbotError(f"{target} has no credential to revoke")
        async with self.client() as acme:
            await acme.revoke(cred, reason)

    async def retire_key(self, target: str, *, compromised: bool = False) -> dict[str, Any]:
        """Log a retire (or compromise) event for the agent's or operator's key. The issuer
        revokes every credential that names it."""
        subject = self.operator() if target == "operator" else self.agent(target)
        async with self.client() as acme:
            return await acme.key_event(subject["id"], subject["jkt"],
                                        "compromise" if compromised else "retire")

    # -- presenting ------------------------------------------------------------------------

    def presentation(self, agent_id: str, *, aud: str, nonce: str,
                     disclose: list[str] | None = None) -> str:
        """An SD-JWT+KB for this relying party and nonce. ``disclose`` names the selectively
        disclosable claims to show; None shows all of them."""
        agent = self.agent(agent_id)
        if not agent.get("credential"):
            raise VbotError("the agent needs an Agent Credential: run `vbot issue`")
        if agent["exp"] <= time.time():
            raise VbotError(f"agent {agent_id}'s credential expired: run `vbot issue` or `vbot run`")
        key = self.keys.get(f"agent-{agent_id}")
        return sdjwt.present(agent["credential"], disclose=disclose, aud=aud, nonce=nonce,
                             iat=int(time.time()), sign=key.sign)

    def authorization(self, agent_id: str, *, aud: str, nonce: str, disclose: list[str] | None = None) -> str:
        return f'Veridact sd-jwt="{self.presentation(agent_id, aud=aud, nonce=nonce, disclose=disclose)}"'

    def status(self) -> dict[str, Any]:
        out: dict[str, Any] = {"issuer": self.state["issuer"], "account": self.state.get("account")}
        op = self.state.get("operator")
        if op:
            exp = _claims(op["credential"])["exp"] if op.get("credential") else None
            out["operator"] = {"domain": op["domain"], "id": op["id"], "key": op["jkt"],
                               "credentialExpires": _iso(exp) if exp else None}
        out["agents"] = {
            aid: {"id": a["id"], "hosted": a["hosted"], "key": a["jkt"],
                  "scopes": _claims(a["delegation"])["scopes"] if a.get("delegation") else None,
                  "credentialExpires": _iso(a["exp"]) if a.get("exp") else None,
                  "attestation": bool(a.get("attestation"))}
            for aid, a in self.state["agents"].items()
        }
        return out
