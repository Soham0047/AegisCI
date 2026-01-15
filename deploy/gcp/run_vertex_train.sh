#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/config.env"

GCP_REGION=${GCP_REGION_OVERRIDE:-${GCP_REGION}}

gcloud config set project "${GCP_PROJECT_ID}"

JOB_NAME=${JOB_NAME:-securedev-train-$(date +%Y%m%d-%H%M%S)}
IMAGE_URI="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REGISTRY_REPO}/${TRAIN_IMAGE}:latest"

# Budget-aware defaults (target <= 2 hours on n1-standard-16 CPU)
MACHINE_TYPE=${MACHINE_TYPE:-n1-standard-16}
ACCELERATOR_TYPE=${ACCELERATOR_TYPE:-}
ACCELERATOR_COUNT=${ACCELERATOR_COUNT:-0}
MACHINE_TYPE=${MACHINE_TYPE_OVERRIDE:-${MACHINE_TYPE}}
ACCELERATOR_TYPE=${ACCELERATOR_TYPE_OVERRIDE:-${ACCELERATOR_TYPE}}
ACCELERATOR_COUNT=${ACCELERATOR_COUNT_OVERRIDE:-${ACCELERATOR_COUNT}}

MAX_FILES=${MAX_FILES:-400}
MAX_SAMPLES=${MAX_SAMPLES:-15000}
EPOCHS=${EPOCHS:-20}
BATCH_SIZE=${BATCH_SIZE:-32}
LR=${LR:-2e-4}
TRANSFORMER_SIZE=${TRANSFORMER_SIZE:-medium}
GNN_HIDDEN_DIM=${GNN_HIDDEN_DIM:-256}
GNN_LAYERS=${GNN_LAYERS:-3}
GNN_DROPOUT=${GNN_DROPOUT:-0.2}
SEED=${SEED:-42}
DEVICE=${DEVICE:-cpu}
DEVICE=${DEVICE_OVERRIDE:-${DEVICE}}
RUN_DATA_PIPELINE=${RUN_DATA_PIPELINE:-0}
SEMGREP_CONFIG=${SEMGREP_CONFIG:-max}
SEMGREP_EXPERIMENTAL=${SEMGREP_EXPERIMENTAL:-1}
MIN_CONFIDENCE=${MIN_CONFIDENCE:-MEDIUM}
RULE_ALLOWLIST=${RULE_ALLOWLIST:-}
CATEGORY_ALLOWLIST=${CATEGORY_ALLOWLIST:-}
AUTO_RELAX=${AUTO_RELAX:-0}
FAIL_ON_EMPTY=${FAIL_ON_EMPTY:-0}
RUN_EVAL=${RUN_EVAL:-0}
EVAL_ONLY=${EVAL_ONLY:-0}
EVAL_MODEL_PREFIX=${EVAL_MODEL_PREFIX:-}
BALANCE_MODE=${BALANCE_MODE:-ratio}
MAX_SAFE_RATIO=${MAX_SAFE_RATIO:-10}
MIN_POS_PER_CATEGORY=${MIN_POS_PER_CATEGORY:-0}
MAX_POS_PER_CATEGORY=${MAX_POS_PER_CATEGORY:-0}
AUGMENT_CONTEXTS=${AUGMENT_CONTEXTS:-3}
RISK_WEIGHT=${RISK_WEIGHT:-1.0}
CAT_WEIGHT=${CAT_WEIGHT:-1.0}
WARMUP_RISK_EPOCHS=${WARMUP_RISK_EPOCHS:-0}
FOCAL_LOSS=${FOCAL_LOSS:-0}
FOCAL_ALPHA=${FOCAL_ALPHA:-0.25}
FOCAL_GAMMA=${FOCAL_GAMMA:-2.0}

ARGS=(
  --datasets-bucket "${GCS_BUCKET_DATASETS}"
  --models-bucket "${GCS_BUCKET_MODELS}"
  --dataset-prefix datasets
  --output-prefix models/vertex
  --max-files "${MAX_FILES}"
  --max-samples "${MAX_SAMPLES}"
  --epochs "${EPOCHS}"
  --batch-size "${BATCH_SIZE}"
  --lr "${LR}"
  --seed "${SEED}"
  --device "${DEVICE}"
  --transformer-size "${TRANSFORMER_SIZE}"
  --gnn-hidden-dim "${GNN_HIDDEN_DIM}"
  --gnn-layers "${GNN_LAYERS}"
  --gnn-dropout "${GNN_DROPOUT}"
  --risk-weight "${RISK_WEIGHT}"
  --cat-weight "${CAT_WEIGHT}"
  --warmup-risk-epochs "${WARMUP_RISK_EPOCHS}"
  --focal-alpha "${FOCAL_ALPHA}"
  --focal-gamma "${FOCAL_GAMMA}"
)

if [ "${RUN_DATA_PIPELINE}" = "1" ]; then
  ARGS+=(
    --run-data-pipeline
    --repos-bucket "${GCS_BUCKET_DATASETS}"
    --repos-prefix repos
    --balance-mode "${BALANCE_MODE}"
    --max-safe-ratio "${MAX_SAFE_RATIO}"
    --min-pos-per-category "${MIN_POS_PER_CATEGORY}"
    --max-pos-per-category "${MAX_POS_PER_CATEGORY}"
    --augment-contexts "${AUGMENT_CONTEXTS}"
    --semgrep-config "${SEMGREP_CONFIG}"
    --min-confidence "${MIN_CONFIDENCE}"
    --rule-allowlist "${RULE_ALLOWLIST}"
    --category-allowlist "${CATEGORY_ALLOWLIST}"
  )
  if [ "${SEMGREP_EXPERIMENTAL}" = "1" ]; then
    ARGS+=(--semgrep-experimental)
  fi
  if [ "${AUTO_RELAX}" = "1" ]; then
    ARGS+=(--auto-relax)
  fi
  if [ "${FAIL_ON_EMPTY}" = "1" ]; then
    ARGS+=(--fail-on-empty)
  fi
fi
if [ "${FOCAL_LOSS}" = "1" ]; then
  ARGS+=(--focal-loss)
fi
if [ "${RUN_EVAL}" = "1" ]; then
  ARGS+=(--run-eval)
fi
if [ "${EVAL_ONLY}" = "1" ]; then
  ARGS+=(--eval-only)
fi
if [ -n "${EVAL_MODEL_PREFIX}" ]; then
  ARGS+=(--eval-model-prefix "${EVAL_MODEL_PREFIX}")
fi

JOB_CONFIG=$(mktemp)
trap 'rm -f "${JOB_CONFIG}"' EXIT

{
  echo "workerPoolSpecs:"
  echo "- replicaCount: 1"
  echo "  machineSpec:"
  echo "    machineType: ${MACHINE_TYPE}"
  if [ -n "${ACCELERATOR_TYPE}" ] && [ "${ACCELERATOR_COUNT}" -gt 0 ]; then
    echo "    acceleratorType: ${ACCELERATOR_TYPE}"
    echo "    acceleratorCount: ${ACCELERATOR_COUNT}"
  fi
  echo "  containerSpec:"
  echo "    imageUri: ${IMAGE_URI}"
  echo "    args:"
  for arg in "${ARGS[@]}"; do
    printf '      - "%s"\n' "${arg}"
  done
} > "${JOB_CONFIG}"

gcloud ai custom-jobs create \
  --region "${GCP_REGION}" \
  --display-name "${JOB_NAME}" \
  --config "${JOB_CONFIG}"
