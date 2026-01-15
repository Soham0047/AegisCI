#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/config.env"

gcloud config set project "${GCP_PROJECT_ID}"

gcloud builds submit \
  --config "${SCRIPT_DIR}/cloudbuild.backend.yaml" \
  --substitutions _REGION="${GCP_REGION}",_REPO="${ARTIFACT_REGISTRY_REPO}",_SERVICE="${CLOUD_RUN_SERVICE}",_IMAGE="securedev-api" \
  .
