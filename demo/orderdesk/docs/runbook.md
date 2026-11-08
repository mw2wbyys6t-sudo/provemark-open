# Runbook

## Deploy

    ./scripts/deploy.sh staging
    ./scripts/deploy.sh production

## Rotate the database password

1. Update the secret in the platform console.
2. Restart the API pods.
3. Verify `/healthz` on the gateway.

## Incident: inventory push failing

`backend/app/tasks.py` swallows inventory errors, so nothing shows up in the
logs. Check the ERP dashboard first, then tail the API pods while a test order
is created.
