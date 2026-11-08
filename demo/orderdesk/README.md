# OrderDesk

A small order-management platform: a Python API, a React dashboard, and a Go
gateway in front of both. Used as the end-to-end demo repository for
[Provemark](../../README.md).

    browser -> gateway (Go) -> api (Python/Flask) -> postgres
                            -> cdn (React build)

## Layout

| Path        | What it is                                  |
| ----------- | ------------------------------------------- |
| `backend/`  | Flask API: orders, users, reports, auth      |
| `frontend/` | React dashboard (webpack build)              |
| `gateway/`  | Go reverse proxy / auth / metrics            |
| `docs/`     | architecture, API reference, runbook         |
| `scripts/`  | seeding and deployment helpers               |

## Running locally

    make seed
    make api        # :8000
    make gateway    # :8080

## Status

Internal prototype. No LICENSE yet, CI is thin, and the dependency pins have
not been audited. That is deliberate: this repository exists so the guardrail
has something real to find.

## Everything here is fake

Every credential, key, identifier and card number in this repository is a
fabricated sample written to trigger a specific rule. Nothing is valid, nothing
belongs to anyone, and nothing was ever in use. Do not copy the values.

The measured results for this repository — five rounds of automatic re-scans,
0/100 F up to 73/100 C — are in the root [README](../../README.md#demo).
