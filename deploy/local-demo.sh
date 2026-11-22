#!/usr/bin/env bash
# The whole Veridact staging stack on one machine, without Docker:
#   issuer (ACME-A)  ->  an operator's website  ->  vbot  ->  the sandbox insurer API.
#
#   python -m venv .venv && . .venv/bin/activate
#   pip install -e ./verify -e ./issuer -e ./vbot -e ./sidecar -e ./sandbox
#   deploy/local-demo.sh
#
# Canonical names are *.veridact.test; --route sends each one to a local port, so every
# credential, identifier and status list carries the https URL it would have in production.
set -euo pipefail

WORK="${WORK:-$(mktemp -d -t veridact-demo-XXXX)}"
ISSUER_PORT=${ISSUER_PORT:-18080}
SITE_PORT=${SITE_PORT:-18081}
SANDBOX_PORT=${SANDBOX_PORT:-18082}
ISSUER=staging.veridact.test
DOMAIN=operator.veridact.test
SANDBOX=sandbox.veridact.test
ROUTES=(--route "$ISSUER=http://127.0.0.1:$ISSUER_PORT"
        --route "$DOMAIN=http://127.0.0.1:$SITE_PORT"
        --route "$SANDBOX=http://127.0.0.1:$SANDBOX_PORT")
export VBOT_HOME="$WORK/vbot"
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { for _ in $(seq 50); do curl -fs "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done
             echo "timed out waiting for $1" >&2; return 1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "Issuer: https://$ISSUER (on :$ISSUER_PORT)"
veridact-issuer serve --base-url "https://$ISSUER" --data-dir "$WORK/issuer" \
  "${ROUTES[@]}" --port "$ISSUER_PORT" >"$WORK/issuer.log" 2>&1 & PIDS+=($!)
wait_for "http://127.0.0.1:$ISSUER_PORT/healthz"

step "Operator website: https://$DOMAIN (serves vbot's publish/ directory on :$SITE_PORT)"
mkdir -p "$VBOT_HOME/publish"
python -m http.server "$SITE_PORT" --bind 127.0.0.1 --directory "$VBOT_HOME/publish" \
  >"$WORK/site.log" 2>&1 & PIDS+=($!)

step "Sandbox relying party: https://$SANDBOX (on :$SANDBOX_PORT)"
veridact-sandbox --audience "https://$SANDBOX" --trust-list "https://$ISSUER/trust-list.jwt" \
  --governance-keys-url "https://$ISSUER/governance-keys.json" "${ROUTES[@]}" \
  --status-ttl 0 --port "$SANDBOX_PORT" >"$WORK/sandbox.log" 2>&1 & PIDS+=($!)
wait_for "http://127.0.0.1:$SANDBOX_PORT/healthz"

step "vbot init: ACME-A account, operator key, veridact-operator.json to publish"
vbot init --issuer "https://$ISSUER/directory" --domain "$DOMAIN" "${ROUTES[@]}"

step "vbot operator: operator-keys-01, then the Operator Credential (an SD-JWT VC)"
vbot operator

step "vbot agent new: agent key and client metadata (CIMD), hosted by the issuer"
vbot agent new

step "vbot delegate: the operator signs a Delegation Credential for the agent"
vbot delegate --scope fs:claims:read-status --scope fs:quotes:create \
  --role "Head of Digital Claims" --per-payment 500.00 --per-day 2000.00

step "vbot issue: an Agent Credential (SD-JWT VC), valid for hours"
vbot issue

step "vbot call: the sandbox challenges, vbot presents an SD-JWT+KB, the sandbox decides"
vbot call "https://$SANDBOX/claims/CLM-1001/status"

step "A scope the agent was not given (expect SCOPE_NOT_HELD)"
vbot call "https://$SANDBOX/payments" -X POST --json '{"amount": "100.00", "currency": "ZAR"}' || true

step "Revoke the agent, then try again (expect AUTH_FAILED, explain.reason STATUS_REVOKED)"
vbot revoke "$(vbot status | python -c 'import json,sys; print(next(iter(json.load(sys.stdin)["agents"])))')"
# The demo sandbox runs with --status-ttl 0. Production verifiers cache Token Status Lists for up
# to 5 minutes, which is the revocation window the spec promises.
vbot call "https://$SANDBOX/claims/CLM-1001/status" || true

step "Transparency log: every key event and credential, in order"
curl -fs "http://127.0.0.1:$ISSUER_PORT/log/entries?count=10" | python -m json.tool || true

echo
echo "Done. State and logs are in $WORK"
