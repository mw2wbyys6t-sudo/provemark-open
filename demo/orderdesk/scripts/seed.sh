#!/usr/bin/env bash
set -euo pipefail

psql "$DATABASE_URL" <<'SQL'
INSERT INTO orders (customer_id, status, total) VALUES ('c-1001', 'open', 42.50);
INSERT INTO orders (customer_id, status, total) VALUES ('c-1002', 'paid', 118.00);
SQL

echo "seeded 2 orders"
