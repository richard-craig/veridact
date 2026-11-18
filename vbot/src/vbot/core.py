"""vbot: the Veridact agent client, as a library.

    bot = Vbot.load("~/.vbot")
    vp = bot.presentation("a7f3k2", aud="https://api.bank.example", nonce=nonce)

One home directory holds an operator and its agents: state.json plus keys/ (mode
0600). publish/ holds the files the operator serves on its own domain.
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

from veridact_verify import jose, provision

from .acme import AcmeClient
from .keys import SoftwareKeyStore

KB_TYP = "veridact-kb+jwt"
VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2", "https://veridact.net/ns/v1"]
DIF_CONTEXT = ["https://www.w3.org/2018/credentials/v1",
               "https://identity.foundation/.well-known/did-configuration/v1"]
PRESENTATION_LIFETIME = 60
RENEW_FRACTION = 2 / 3


class VbotError(Exception):
    pass


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _claims(jwt: str) -> dict[str, Any]:
    return jose.parse(jwt).payload


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
        return cls(home, json.loads(path.read_text()))

    @classmethod
    def create(cls, home: str | Path, issuer: str, routes: dict[str, str] | None = None) -> "Vbot":
        home = Path(home).expanduser()
        if (home / "state.json").exists():
            raise VbotError(f"{home} already holds a vbot state")
        home.mkdir(parents=True, exist_ok=True)
        bot = cls(home, {"issuer": issuer, "routes": routes or {}, "agents": {}})
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
            self.state["hostedDidPrefix"] = directory["meta"].get("veridactHostedDidPrefix")
            self.state["environment"] = directory["meta"].get("veridactEnvironment", "staging")
        self.save()
        return url

    # -- operator ----------------------------------------------------------------------

    def create_operator(self, domain: str) -> dict[str, Any]:
        """Create the operator DID and the files the operator must serve on its domain."""
        domain = domain.lower().rstrip(".")
        if self.state.get("operator"):
            raise VbotError("this home already has an operator")
        key = self.keys.get_or_create("operator")
        update, nxt = provision.new_update_key(), provision.new_update_key()
        made = provision.provision(domain, {"key-1": key.public_key()}, {"assertionMethod": ["key-1"]},
                                   update, next_update_key=nxt)
        self.keys.save_update_keys("operator", update, nxt)
        kid = f"{made.did}#key-1"
        now = int(time.time())
        linkage = key.sign({"typ": "JWT", "kid": kid}, {
            "iss": made.did, "sub": made.did, "nbf": now, "exp": now + 365 * 86400,
            "vc": {
                "@context": DIF_CONTEXT,
                "issuer": made.did,
                "issuanceDate": _iso(now),
                "expirationDate": _iso(now + 365 * 86400),
                "type": ["VerifiableCredential", "DomainLinkageCredential"],
                "credentialSubject": {"id": made.did, "origin": f"https://{domain}"},
            },
        })
        files = {
            self._publish_path(made.log_url): made.log,
            self._publish_path(f"https://{domain}/.well-known/did-configuration.json"): json.dumps({
                "@context": "https://identity.foundation/.well-known/did-configuration/v1",
                "linked_dids": [linkage]}, indent=2),
        }
        self._write_publish(files)
        self.state["operator"] = {"domain": domain, "did": made.did, "kid": kid}
        self.save()
        return {"did": made.did, "files": sorted(str(p) for p in files)}

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

    async def obtain_operator_credential(self, *, challenge: str = "did-config-01",
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
            payload = {"did": op["did"]} if challenge == "did-config-01" else {}
            if challenge == "dns-01" and before_respond is not None:
                await before_respond(f"_acme-challenge.{op['domain']}", self.dns01_record(ch["token"]))
            result = await acme.respond(ch["url"], payload)
            if result["status"] != "valid":
                raise VbotError(f"{challenge} failed: {result.get('error', {}).get('detail', result)}")
            order = await acme.wait_ready(order_url)
            order = await acme.finalize(order, lambda nonce: self._key_binding(
                key, op["did"], op["kid"], order["finalize"], nonce))
            jwt, receipt = await acme.download(order["credential"])
        op.update(credential=jwt, credentialUrl=order["credential"],
                  credentialId=_claims(jwt)["id"], receipt=receipt)
        self.save()
        return op

    def dns01_record(self, token: str) -> str:
        """The TXT value for dns-01, if you prefer DNS to did-config-01."""
        import hashlib
        jwk = self.keys.get_or_create("account").jwk
        thumb = jose.b64url_encode(hashlib.sha256(json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"), sort_keys=True).encode()).digest())
        return jose.b64url_encode(hashlib.sha256(f"{token}.{thumb}".encode()).digest())

    # -- agents --------------------------------------------------------------------------

    async def create_agent(self, *, hosted: bool = True, agent_id: str | None = None) -> dict[str, Any]:
        op = self.operator()
        agent_id = agent_id or ("a" + secrets.token_hex(3))
        if agent_id in self.state["agents"]:
            raise VbotError(f"agent {agent_id} exists")
        if hosted:
            prefix, slug = self.state.get("hostedDidPrefix"), self.state.get("slug")
            if not prefix or not slug:
                raise VbotError("register with an issuer that hosts DIDs first")
            path = f"{prefix}:{slug}:{agent_id}"
        else:
            path = f"{op['domain']}:agents:{agent_id}"
        key = self.keys.get_or_create(f"agent-{agent_id}")
        update, nxt = provision.new_update_key(), provision.new_update_key()
        made = provision.provision(path, {"key-1": key.public_key()}, {"authentication": ["key-1"]},
                                   update, next_update_key=nxt)
        self.keys.save_update_keys(f"agent-{agent_id}", update, nxt)
        if hosted:
            async with self.client() as acme:
                await acme.upload_did(agent_id, made.log)
        else:
            self._write_publish({self._publish_path(made.log_url): made.log})
        self.state["agents"][agent_id] = {"did": made.did, "kid": f"{made.did}#key-1",
                                          "hosted": hosted}
        self.save()
        return {"id": agent_id, **self.state["agents"][agent_id], "logUrl": made.log_url}

    def delegate(self, agent_id: str, scopes: list[str], *, role: str, days: int = 30,
                 max_lifetime: int = 8 * 3600, limits: dict[str, str] | None = None,
                 audiences: list[str] | None = None) -> str:
        """The operator signs a Delegation Credential for the agent.

        Staging simplification: the operator DID signs as the approver. Approver
        Credentials and the two-person rule come next (spec: Delegation and human intent).
        """
        op = self.operator()
        agent = self.agent(agent_id)
        if not 1 <= days <= 90:
            raise VbotError("a delegation lasts 1 to 90 days")
        now = int(time.time())
        subject: dict[str, Any] = {
            "id": agent["did"], "scopes": sorted(set(scopes)), "accountableRole": role,
            "maxLifetime": max_lifetime, "environment": self.state.get("environment", "staging"),
        }
        if limits:
            subject["limits"] = limits
        if audiences:
            subject["audiences"] = audiences
        jwt = self.keys.get("operator").sign({"typ": "vc+jwt", "kid": op["kid"]}, {
            "@context": VC_CONTEXT,
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "VeridactDelegationCredential"],
            "issuer": op["did"],
            "validFrom": _iso(now), "validUntil": _iso(now + days * 86400),
            "iat": now, "exp": now + days * 86400,
            "credentialSubject": subject,
        })
        agent["delegation"] = jwt
        self.save()
        return jwt

    async def issue(self, agent_id: str, *, lifetime: int | None = None) -> dict[str, Any]:
        """Obtain (or renew) the agent's Agent Credential."""
        agent = self.agent(agent_id)
        if not agent.get("delegation"):
            raise VbotError(f"agent {agent_id} has no delegation: run `vbot delegate` first")
        key = self.keys.get(f"agent-{agent_id}")
        async with self.client() as acme:
            order_url, order = await acme.new_order({"type": "agent-did", "value": agent["did"]},
                                                    lifetime=lifetime)
            authz = await acme.get(order["authorizations"][0])
            ch = next(c for c in authz["challenges"] if c["type"] == "delegation-01")
            result = await acme.respond(ch["url"], {"delegation": agent["delegation"]})
            if result["status"] != "valid":
                raise VbotError(f"delegation-01 failed: {result.get('error', {}).get('detail', result)}")
            order = await acme.wait_ready(order_url)
            order = await acme.finalize(order, lambda nonce: self._key_binding(
                key, agent["did"], agent["kid"], order["finalize"], nonce))
            jwt, receipt = await acme.download(order["credential"])
        claims = _claims(jwt)
        agent.update(credential=jwt, credentialUrl=order["credential"], credentialId=claims["id"],
                     iat=claims["iat"], exp=claims["exp"], receipt=receipt)
        self.save()
        return agent

    @staticmethod
    def _key_binding(key, did: str, kid: str, finalize_url: str, nonce: str) -> str:
        return key.sign({"typ": KB_TYP, "kid": kid},
                        {"iss": did, "aud": finalize_url, "nonce": nonce, "iat": int(time.time())})

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

    # -- presenting ------------------------------------------------------------------------

    def presentation(self, agent_id: str, *, aud: str, nonce: str) -> str:
        agent = self.agent(agent_id)
        op = self.operator()
        if not agent.get("credential") or not op.get("credential"):
            raise VbotError("the agent needs an Agent Credential and the operator an Operator Credential")
        if agent["exp"] <= time.time():
            raise VbotError(f"agent {agent_id}'s credential expired: run `vbot issue` or `vbot run`")
        now = int(time.time())
        return self.keys.get(f"agent-{agent_id}").sign({"typ": "vp+jwt", "kid": agent["kid"]}, {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": agent["did"],
            "verifiableCredential": [
                {"@context": ["https://www.w3.org/ns/credentials/v2"],
                 "type": "EnvelopedVerifiableCredential",
                 "id": "data:application/vc+jwt," + cred}
                for cred in (agent["credential"], op["credential"])
            ],
            "aud": aud, "nonce": nonce, "iat": now, "exp": now + PRESENTATION_LIFETIME,
        })

    def authorization(self, agent_id: str, *, aud: str, nonce: str) -> str:
        return f'Veridact vp="{self.presentation(agent_id, aud=aud, nonce=nonce)}"'

    def status(self) -> dict[str, Any]:
        out: dict[str, Any] = {"issuer": self.state["issuer"], "account": self.state.get("account")}
        op = self.state.get("operator")
        if op:
            exp = _claims(op["credential"])["exp"] if op.get("credential") else None
            out["operator"] = {"domain": op["domain"], "did": op["did"],
                               "credentialExpires": _iso(exp) if exp else None}
        out["agents"] = {
            aid: {"did": a["did"], "hosted": a["hosted"],
                  "scopes": _claims(a["delegation"])["credentialSubject"]["scopes"]
                  if a.get("delegation") else None,
                  "credentialExpires": _iso(a["exp"]) if a.get("exp") else None}
            for aid, a in self.state["agents"].items()
        }
        return out
