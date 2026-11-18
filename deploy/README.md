# Running the staging stack

Four pieces: the **issuer** (ACME-A), an **operator's website** (where vbot's DID files are published), **vbot**,
and the **sandbox** relying party.

Every artefact carries the https URL it would have in production (`https://staging.veridact.test/...`). Locally
there is no TLS, so each component takes `--route host=url` to reach those names at a local address. Signatures,
not the transport, make the artefacts trustworthy, so this changes nothing about what is verified.

## Without Docker

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ./verify -e './issuer[dns]' -e ./vbot -e ./sidecar -e ./sandbox
deploy/local-demo.sh
```

The script starts all four, runs the whole vbot flow, then shows a denied scope, a revocation and the
transparency log.

## With Docker Compose

```sh
docker compose -f deploy/compose.yaml up -d --build
alias vbot='docker compose -f deploy/compose.yaml run --rm vbot'
vbot init --issuer https://staging.veridact.test/directory --domain operator.veridact.test \
  --route staging.veridact.test=http://issuer:8080 --route sandbox.veridact.test=http://sandbox:8070
vbot operator
vbot agent new
vbot delegate --scope fs:claims:read-status --role "Head of Digital Claims"
vbot issue
vbot call https://sandbox.veridact.test/claims/CLM-1001/status
```

## Public staging (next)

To run staging at `staging.veridact.net` and `sandbox.veridact.net`: one container host in af-south-1 behind an
ALB with ACM certificates for both names, the issuer's data directory on EFS (or move the store to RDS), and no
`--route` flags. Operators then publish their own two files on their own domains.
