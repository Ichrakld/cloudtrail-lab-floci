#!/usr/bin/env bash
set -euo pipefail
for tool in docker aws python3 jq; do
  command -v "$tool" >/dev/null || { echo "Outil manquant : $tool" >&2; exit 1; }
done
docker compose version
aws --endpoint-url "${AWS_ENDPOINT_URL:-http://127.0.0.1:4566}" sts get-caller-identity
