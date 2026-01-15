#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/config.env"

GCP_REGION=${GCP_REGION_OVERRIDE:-${GCP_REGION}}

gcloud config set project "${GCP_PROJECT_ID}"

gcloud builds submit \
  --config "${SCRIPT_DIR}/cloudbuild.train.yaml" \
  --substitutions _REGION="${GCP_REGION}",_REPO="${ARTIFACT_REGISTRY_REPO}",_IMAGE="${TRAIN_IMAGE}" \
  .
