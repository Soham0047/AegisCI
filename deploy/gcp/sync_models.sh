#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/config.env"

if [ ! -d "artifacts/models" ]; then
  echo "artifacts/models not found"
  exit 1
fi

gsutil -m rsync -r artifacts/models "${GCS_BUCKET_MODELS}/models/local"
