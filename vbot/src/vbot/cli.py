"""vbot: get Veridact credentials for your AI agents, the way certbot gets certificates.

  vbot init --issuer https://staging.veridact.net/directory --domain example.com
  # publish the files under ~/.vbot/publish/ at https://example.com/
  vbot operator                          # Operator Credential (did-config-01 or dns-01)
  vbot agent new                         # agent key + DID (hosted by the issuer)
  vbot delegate --scope fs:claims:read-status --role "Head of Digital Claims"
  vbot issue                             # Agent Credential, valid for hours
  vbot call https://sandbox.veridact.net/claims/CLM-1001/status
  vbot run                               # keep renewing, two thirds through each lifetime
  vbot token https://auth.bank.example   # pattern A: a DPoP-bound access token from the bank's IdP
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from typing import Any

from .acme import AcmeError
from .core import Vbot, VbotError
from .http import call, exchange

_DURATION = re.compile(r"^(\d+)([smhd]?)$")


def duration(text: str) -> int:
    m = _DURATION.match(text.strip())
    if not m:
        raise argparse.ArgumentTypeError("use seconds or 30m, 8h, 7d")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2))


def _routes(values: list[str] | None) -> dict[str, str]:
    return dict(v.split("=", 1) for v in values or [])


async def _wait_for_dns(name: str, value: str) -> None:
    print(f"Publish this TXT record, then press Enter:\n  {name}  TXT  \"{value}\"", file=sys.stderr)
    await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)


async def run(args: argparse.Namespace) -> int:
    home = args.home
    cmd = args.command

    if cmd == "init":
        bot = Vbot.create(home, args.issuer, _routes(args.route))
        await bot.register([f"mailto:{args.email}"] if args.email else None)
        made = bot.create_operator(args.domain)
        print(f"Operator DID: {made['did']}\n")
        print(f"Serve these files at https://{args.domain}/ (paths as shown):")
        for path in made["files"]:
            print(f"  {path}")
        print("\nThen run: vbot operator")
        return 0

    bot = Vbot.load(home)

    if cmd == "operator":
        op = await bot.obtain_operator_credential(challenge=args.challenge,
                                                  before_respond=_wait_for_dns)
        _print({"operator": op["did"], "credential": op["credentialId"], "logEntry": op.get("receipt")})
    elif cmd == "agent":
        made = await bot.create_agent(hosted=not args.on_domain, agent_id=args.id)
        _print(made)
        if args.on_domain:
            print(f"Serve {made['logUrl']} from {bot.publish_dir}", file=sys.stderr)
    elif cmd == "delegate":
        limits = None
        if args.per_payment or args.per_day:
            if not (args.per_payment and args.per_day):
                raise VbotError("give both --per-payment and --per-day")
            limits = {"currency": args.currency, "perPayment": args.per_payment, "perDay": args.per_day}
        agent_id = args.agent or bot.default_agent()
        bot.delegate(agent_id, args.scope, role=args.role, days=args.days,
                     max_lifetime=args.max_lifetime, limits=limits, audiences=args.audience)
        _print({"agent": agent_id, "scopes": sorted(set(args.scope)), "days": args.days})
    elif cmd == "issue":
        agent_id = args.agent or bot.default_agent()
        agent = await bot.issue(agent_id, lifetime=args.lifetime)
        _print({"agent": agent_id, "credential": agent["credentialId"],
                "expires": bot.status()["agents"][agent_id]["credentialExpires"]})
    elif cmd == "run":
        agent_ids = args.agent or sorted(bot.state["agents"])
        print(f"vbot: keeping {', '.join(agent_ids)} renewed (Ctrl-C to stop)", file=sys.stderr)
        while True:
            wait = 3600.0
            for agent_id in agent_ids:
                due = bot.renewal_due(agent_id)
                if due <= 0:
                    try:
                        await bot.issue(agent_id)
                        print(f"renewed {agent_id}", file=sys.stderr)
                        due = bot.renewal_due(agent_id)
                    except (AcmeError, VbotError, OSError) as err:
                        print(f"renewal of {agent_id} failed: {err}; retrying in 5 minutes",
                              file=sys.stderr)
                        due = 300
                wait = min(wait, max(due, 30))
            if args.once:
                return 0
            await asyncio.sleep(wait)
    elif cmd == "present":
        print(bot.presentation(args.agent or bot.default_agent(), aud=args.aud, nonce=args.nonce))
    elif cmd == "call":
        body = json.loads(args.json) if args.json else None
        result = await call(bot, args.url, agent_id=args.agent or bot.default_agent(),
                            method=args.method, json_body=body)
        print(f"HTTP {result.status}", file=sys.stderr)
        try:
            _print(result.json())
        except ValueError:
            print(result.body.decode(errors="replace"))
        return 0 if result.status < 400 else 1
    elif cmd == "token":
        result = await exchange(bot, args.bridge, agent_id=args.agent or bot.default_agent(),
                                scopes=args.scope)
        print(f"HTTP {result.status}", file=sys.stderr)
        _print(result.body)
        return 0 if result.status == 200 else 1
    elif cmd == "revoke":
        await bot.revoke(args.target, args.reason)
        print(f"revoked {args.target}", file=sys.stderr)
    elif cmd == "status":
        _print(bot.status())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vbot", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--home", default=os.environ.get("VBOT_HOME", "~/.vbot"))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create an account and the operator DID")
    p.add_argument("--issuer", required=True, help="ACME-A directory URL")
    p.add_argument("--domain", required=True, help="the operator's domain")
    p.add_argument("--email")
    p.add_argument("--route", action="append", metavar="HOST=URL",
                   help="development: reach https://HOST at URL")

    p = sub.add_parser("operator", help="obtain the Operator Credential")
    p.add_argument("--challenge", choices=["did-config-01", "dns-01"], default="did-config-01")

    p = sub.add_parser("agent", help="create an agent key and DID")
    p.add_argument("action", choices=["new"])
    p.add_argument("--id", help="agent id (default: random, so it leaks nothing)")
    p.add_argument("--on-domain", action="store_true",
                   help="host the agent DID on your domain instead of the issuer's")

    p = sub.add_parser("delegate", help="sign a Delegation Credential for an agent")
    p.add_argument("--agent")
    p.add_argument("--scope", action="append", required=True)
    p.add_argument("--role", required=True, help="accountable role title, never a person's name")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--max-lifetime", type=duration, default=8 * 3600)
    p.add_argument("--currency", default="ZAR")
    p.add_argument("--per-payment")
    p.add_argument("--per-day")
    p.add_argument("--audience", action="append")

    p = sub.add_parser("issue", help="obtain or renew the Agent Credential")
    p.add_argument("--agent")
    p.add_argument("--lifetime", type=duration)

    p = sub.add_parser("run", help="keep agent credentials renewed")
    p.add_argument("--agent", action="append")
    p.add_argument("--once", action="store_true")

    p = sub.add_parser("present", help="print a presentation for a nonce")
    p.add_argument("--agent")
    p.add_argument("--aud", required=True)
    p.add_argument("--nonce", required=True)

    p = sub.add_parser("call", help="call a Veridact-protected API")
    p.add_argument("url")
    p.add_argument("--agent")
    p.add_argument("-X", "--method", default="GET")
    p.add_argument("--json", help="JSON request body")

    p = sub.add_parser("token", help="exchange a presentation for an access token (pattern A)")
    p.add_argument("bridge", help="token-exchange endpoint origin, e.g. https://auth.bank.example")
    p.add_argument("--agent")
    p.add_argument("--scope", action="append")

    p = sub.add_parser("revoke", help="revoke an agent's credential, or 'operator'")
    p.add_argument("target")
    p.add_argument("--reason", default="unspecified")

    sub.add_parser("status", help="show the operator and agents")

    args = parser.parse_args(argv)
    try:
        return asyncio.run(run(args))
    except (VbotError, AcmeError) as err:
        print(f"vbot: {err}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
