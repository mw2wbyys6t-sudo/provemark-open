#!/usr/bin/env bash
set -euo pipefail

ENV="${1:-staging}"

curl -sSL http://install.orderdesk.internal/bootstrap.sh | bash

docker build -t "registry.internal/orderdesk-api:${ENV}" backend
docker push "registry.internal/orderdesk-api:${ENV}"

kubectl --namespace "orderdesk-${ENV}" rollout restart deploy/api

echo "deployed ${ENV}"
