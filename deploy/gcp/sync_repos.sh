#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/config.env"

if [ ! -d "data/repos" ]; then
  echo "data/repos not found"
  exit 1
fi

gsutil -m rsync -r data/repos "${GCS_BUCKET_DATASETS}/repos"
