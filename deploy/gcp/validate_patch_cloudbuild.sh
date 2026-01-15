#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/config.env"

PATCH_PATH=${1:-artifacts/patches/selected.diff}
COMMIT=${2:-HEAD}

if [ ! -f "${PATCH_PATH}" ]; then
  echo "Patch not found: ${PATCH_PATH}"
  exit 1
fi

gcloud config set project "${GCP_PROJECT_ID}"

gcloud builds submit \
  --config "${SCRIPT_DIR}/cloudbuild.validate.yaml" \
  --substitutions _VALIDATOR_IMAGE="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REGISTRY_REPO}/${VALIDATOR_IMAGE}:latest",_PATCH_PATH="${PATCH_PATH}",_COMMIT="${COMMIT}" \
  .
