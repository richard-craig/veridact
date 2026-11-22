"""veridact-attester serve | status <id> <valid|suspended|withdrawn> [reason] | show"""

from __future__ import annotations

import json
import os
import sys

from aiohttp import web

from .app import Attester, Config, create_app


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args.pop(0) if args else "serve"
    if cmd == "serve":
        web.run_app(create_app(), host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8100")))
        return 0
    att = Attester(Config.from_env())
    if cmd == "show":
        print(json.dumps({e: att.summary(e) for e in att.state["entries"]}, indent=2))
        return 0
    if cmd == "status" and len(args) >= 2:
        # Note: a running server keeps its own copy of the state; use the admin API against it instead.
        print(json.dumps(att.set_status(args[0], args[1], " ".join(args[2:]) or "set from the command line"), indent=2))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
