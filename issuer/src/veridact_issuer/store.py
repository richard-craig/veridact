"""Issuer state in SQLite.

Staging runs one issuer process, so SQLite is enough. Every method is a small
transaction, so the store can move to Postgres or DynamoDB without changing callers.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY, thumbprint TEXT UNIQUE NOT NULL, jwk TEXT NOT NULL,
  status TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, contact TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
  identifier TEXT NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS orders_by_account ON orders(account_id, created);
CREATE TABLE IF NOT EXISTS authzs (
  id TEXT PRIMARY KEY, order_id TEXT NOT NULL, account_id TEXT NOT NULL, status TEXT NOT NULL,
  identifier TEXT NOT NULL, expires INTEGER NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY, authz_id TEXT NOT NULL, account_id TEXT NOT NULL, type TEXT NOT NULL,
  token TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL,
  jwt TEXT NOT NULL, status_list TEXT NOT NULL, status_index INTEGER NOT NULL,
  iat INTEGER NOT NULL, exp INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
  log_index INTEGER, data TEXT NOT NULL, cnf_jkt TEXT);
CREATE INDEX IF NOT EXISTS credentials_by_subject ON credentials(subject, kind);
CREATE INDEX IF NOT EXISTS credentials_by_key ON credentials(cnf_jkt);
CREATE TABLE IF NOT EXISTS status_lists (
  url TEXT PRIMARY KEY, kind TEXT NOT NULL, number INTEGER NOT NULL, bits BLOB NOT NULL,
  used BLOB NOT NULL, used_count INTEGER NOT NULL, jwt TEXT, signed_at INTEGER, dirty INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS hosted_agents (
  path TEXT PRIMARY KEY, account_id TEXT NOT NULL, client_id TEXT UNIQUE NOT NULL, doc TEXT NOT NULL,
  updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS key_events (
  id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, subject TEXT NOT NULL, jkt TEXT NOT NULL,
  action TEXT NOT NULL, ts INTEGER NOT NULL, log_index INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS key_events_by_key ON key_events(subject, jkt);
CREATE TABLE IF NOT EXISTS assistants (
  id TEXT PRIMARY KEY, sub TEXT NOT NULL, credential TEXT NOT NULL, status_list TEXT NOT NULL,
  status_index INTEGER NOT NULL, iat INTEGER NOT NULL, exp INTEGER NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tlog (
  idx INTEGER PRIMARY KEY, leaf_hash TEXT NOT NULL, chain_hash TEXT NOT NULL,
  entry TEXT NOT NULL, ts INTEGER NOT NULL);
"""


def new_id(nbytes: int = 12) -> str:
    return secrets.token_urlsafe(nbytes)


def _row(cur: sqlite3.Cursor, row: tuple) -> dict[str, Any]:
    out = {d[0]: v for d, v in zip(cur.description, row)}
    if "data" in out and isinstance(out["data"], str):
        out["data"] = json.loads(out["data"])
    return out


class Store:
    def __init__(self, path: str | Path):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.row_factory = _row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def _one(self, sql: str, *args: Any) -> dict[str, Any] | None:
        return self.db.execute(sql, args).fetchone()

    def _all(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        return self.db.execute(sql, args).fetchall()

    # -- accounts ----------------------------------------------------------------

    def account_by_thumbprint(self, thumbprint: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM accounts WHERE thumbprint=?", thumbprint)

    def account(self, account_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM accounts WHERE id=?", account_id)

    def account_by_slug(self, slug: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM accounts WHERE slug=?", slug)

    def create_account(self, jwk: dict, thumbprint: str, contact: list[str], now: int) -> dict[str, Any]:
        account_id = new_id()
        # Opaque slug for Veridact-hosted agent DIDs: a public name must not leak the operator.
        slug = "o" + secrets.token_hex(5)
        self.db.execute(
            "INSERT INTO accounts VALUES (?,?,?,?,?,?,?)",
            (account_id, thumbprint, json.dumps(jwk), "valid", slug, json.dumps(contact), now))
        return self.account(account_id)  # type: ignore[return-value]

    def deactivate_account(self, account_id: str) -> None:
        self.db.execute("UPDATE accounts SET status='deactivated' WHERE id=?", (account_id,))

    # -- orders, authorisations, challenges ----------------------------------------

    def create_order(self, account_id: str, kind: str, identifier: dict, expires: int, now: int,
                     challenge_types: list[str]) -> dict[str, Any]:
        order_id, authz_id = new_id(), new_id()
        self.db.execute("BEGIN")
        try:
            self.db.execute("INSERT INTO orders VALUES (?,?,?,?,?,?,?,?)", (
                order_id, account_id, kind, "pending", json.dumps(identifier), expires, now,
                json.dumps({"authorizations": [authz_id]})))
            self.db.execute("INSERT INTO authzs VALUES (?,?,?,?,?,?,?)", (
                authz_id, order_id, account_id, "pending", json.dumps(identifier), expires,
                json.dumps({})))
            for ctype in challenge_types:
                self.db.execute("INSERT INTO challenges VALUES (?,?,?,?,?,?,?)", (
                    new_id(), authz_id, account_id, ctype, secrets.token_urlsafe(32), "pending",
                    json.dumps({})))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return self.order(order_id)  # type: ignore[return-value]

    def orders_since(self, account_id: str, since: int) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM orders WHERE account_id=? AND created>=?",
                        account_id, since)
        return int(row["n"]) if row else 0

    def order(self, order_id: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM orders WHERE id=?", order_id)
        if row:
            row["identifier"] = json.loads(row["identifier"])
        return row

    def update_order(self, order_id: str, status: str, **data: Any) -> None:
        order = self.order(order_id)
        merged = {**(order["data"] if order else {}), **data}
        self.db.execute("UPDATE orders SET status=?, data=? WHERE id=?",
                        (status, json.dumps(merged), order_id))

    def authz(self, authz_id: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM authzs WHERE id=?", authz_id)
        if row:
            row["identifier"] = json.loads(row["identifier"])
        return row

    def update_authz(self, authz_id: str, status: str, **data: Any) -> None:
        authz = self.authz(authz_id)
        merged = {**(authz["data"] if authz else {}), **data}
        self.db.execute("UPDATE authzs SET status=?, data=? WHERE id=?",
                        (status, json.dumps(merged), authz_id))

    def challenges_for(self, authz_id: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM challenges WHERE authz_id=? ORDER BY type", authz_id)

    def challenge(self, challenge_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM challenges WHERE id=?", challenge_id)

    def update_challenge(self, challenge_id: str, status: str, **data: Any) -> None:
        ch = self.challenge(challenge_id)
        merged = {**(ch["data"] if ch else {}), **data}
        self.db.execute("UPDATE challenges SET status=?, data=? WHERE id=?",
                        (status, json.dumps(merged), challenge_id))

    # -- credentials ----------------------------------------------------------------

    def add_credential(self, cred_id: str, account_id: str, kind: str, subject: str, jwt: str,
                       status_list: str, status_index: int, iat: int, exp: int,
                       log_index: int, data: dict, cnf_jkt: str | None = None) -> None:
        self.db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            cred_id, account_id, kind, subject, jwt, status_list, status_index, iat, exp, 0,
            log_index, json.dumps(data), cnf_jkt))

    def credentials_for_key(self, subject: str, jkt: str) -> list[dict[str, Any]]:
        """Unrevoked credentials whose cnf is this subject's key."""
        return self._all("SELECT * FROM credentials WHERE subject=? AND cnf_jkt=? AND revoked=0",
                         subject, jkt)

    def update_credential_data(self, cred_id: str, **data: Any) -> None:
        cred = self.credential(cred_id)
        merged = {**(cred["data"] if cred else {}), **data}
        self.db.execute("UPDATE credentials SET data=? WHERE id=?", (json.dumps(merged), cred_id))

    def credential(self, cred_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM credentials WHERE id=?", cred_id)

    def credential_by_jwt(self, jwt: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM credentials WHERE jwt=?", jwt)

    def latest_operator_credential(self, operator: str) -> dict[str, Any] | None:
        return self._one(
            "SELECT * FROM credentials WHERE subject=? AND kind='operator' ORDER BY iat DESC LIMIT 1",
            operator)

    def operator_credentials(self, account_id: str, now: int) -> list[dict[str, Any]]:
        """The account's unrevoked, unexpired Operator Credentials, newest first."""
        return self._all(
            "SELECT * FROM credentials WHERE account_id=? AND kind='operator' AND revoked=0 "
            "AND exp>? ORDER BY iat DESC", account_id, now)

    def mark_revoked(self, cred_id: str, reason: str) -> None:
        cred = self.credential(cred_id)
        data = {**(cred["data"] if cred else {}), "revocationReason": reason}
        self.db.execute("UPDATE credentials SET revoked=1, data=? WHERE id=?",
                        (json.dumps(data), cred_id))

    # -- status lists -----------------------------------------------------------------

    def status_lists(self, kind: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM status_lists WHERE kind=? ORDER BY number", kind)

    def status_list(self, url: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM status_lists WHERE url=?", url)

    def create_status_list(self, url: str, kind: str, number: int, entry_bytes: int,
                           used_bytes: int) -> None:
        self.db.execute("INSERT INTO status_lists VALUES (?,?,?,?,?,?,?,?,?)", (
            url, kind, number, bytes(entry_bytes), bytes(used_bytes), 0, None, None, 1))

    def save_status_list(self, url: str, *, bits: bytes | None = None, used: bytes | None = None,
                         used_count: int | None = None, jwt: str | None = None,
                         signed_at: int | None = None, dirty: bool | None = None) -> None:
        sets, args = [], []
        for col, val in (("bits", bits), ("used", used), ("used_count", used_count), ("jwt", jwt),
                         ("signed_at", signed_at), ("dirty", None if dirty is None else int(dirty))):
            if val is not None:
                sets.append(f"{col}=?")
                args.append(val)
        if sets:
            self.db.execute(f"UPDATE status_lists SET {', '.join(sets)} WHERE url=?", (*args, url))

    # -- Veridact-hosted agents (CIMDs) --------------------------------------------------

    def hosted_agent(self, path: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM hosted_agents WHERE path=?", path)

    def put_hosted_agent(self, path: str, account_id: str, client_id: str, doc: str, now: int) -> None:
        self.db.execute(
            "INSERT INTO hosted_agents VALUES (?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET "
            "doc=excluded.doc, updated=excluded.updated",
            (path, account_id, client_id, doc, now))

    # -- key events ---------------------------------------------------------------------

    def add_key_event(self, account_id: str, subject: str, jkt: str, action: str, now: int,
                      log_index: int) -> None:
        self.db.execute("INSERT INTO key_events (account_id, subject, jkt, action, ts, log_index) "
                        "VALUES (?,?,?,?,?,?)", (account_id, subject, jkt, action, now, log_index))

    def key_events(self, subject: str, jkt: str) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM key_events WHERE subject=? AND jkt=? ORDER BY id", subject, jkt)

    # -- known-assistant entries -----------------------------------------------------------

    def put_assistant(self, entry_id: str, sub: str, credential: str, status_list: str,
                      status_index: int, iat: int, exp: int, data: dict) -> None:
        self.db.execute(
            "INSERT INTO assistants VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "sub=excluded.sub, credential=excluded.credential, status_list=excluded.status_list, "
            "status_index=excluded.status_index, iat=excluded.iat, exp=excluded.exp, data=excluded.data",
            (entry_id, sub, credential, status_list, status_index, iat, exp, json.dumps(data)))

    def assistant(self, entry_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM assistants WHERE id=?", entry_id)

    def assistants(self) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM assistants ORDER BY id")

    # -- transparency log ---------------------------------------------------------------

    def tlog_tail(self) -> dict[str, Any] | None:
        return self._one("SELECT * FROM tlog ORDER BY idx DESC LIMIT 1")

    def tlog_append(self, leaf_hash: str, chain_hash: str, entry: dict, now: int) -> int:
        cur = self.db.execute("INSERT INTO tlog (leaf_hash, chain_hash, entry, ts) VALUES (?,?,?,?)",
                              (leaf_hash, chain_hash, json.dumps(entry, sort_keys=True), now))
        return int(cur.lastrowid)  # type: ignore[arg-type]

    def tlog_range(self, start: int, count: int) -> list[dict[str, Any]]:
        rows = self._all("SELECT * FROM tlog WHERE idx>=? ORDER BY idx LIMIT ?", start, count)
        for row in rows:
            row["entry"] = json.loads(row["entry"])
        return rows
