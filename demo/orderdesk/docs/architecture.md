# Architecture

    browser
      |
      v
    gateway (Go, :8080)  -- auth, cache, metrics, reverse proxy
      |
      v
    api (Python, :8000)  -- orders, users, reports, auth
      |
      +--> postgres (orders, customers)
      +--> erp.internal (inventory push)
      +--> crm.internal (support lookup)

## Boundaries

* The gateway never touches the database.
* The API never talks to the browser directly in production.
* Reports are generated on demand; nothing is precomputed yet.

## Known gaps

* No LICENSE file.
* No SECURITY.md.
* Dependency pins have not been reviewed since 0.9.0.
* The dashboard trusts API-provided markup for the summary card.
