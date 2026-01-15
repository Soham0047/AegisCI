# GCP Deployment Guide (Cloud Run + Vertex AI + Cloud Build)

This guide deploys SecureDev Guardian for production:
- **Cloud Run** for the API/backend
- **Vertex AI** for scalable training jobs
- **Cloud Build** for Docker validator jobs
- **GCS** for datasets + model artifacts

## 0) Prereqs
- `gcloud` + `gsutil` installed and authenticated
- Artifact Registry + Cloud Run + Vertex AI APIs enabled

## 1) Configure
Update `deploy/gcp/config.env` with your project values.

```
GCP_PROJECT_ID=securedev-guardian
GCP_REGION=us-central1
ARTIFACT_REGISTRY_REPO=securedev-registry
GCS_BUCKET_DATASETS=gs://securedev-datasets-securedev-guardian
GCS_BUCKET_MODELS=gs://securedev-models-securedev-guardian
```

## 2) Enable APIs
```
./deploy/gcp/enable_apis.sh
```

## 3) Create Artifact Registry (if needed)
```
gcloud artifacts repositories create securedev-registry \
  --repository-format=docker \
  --location us-central1
```

## 4) Build + Deploy Backend (Cloud Run)
```
./deploy/gcp/deploy_backend.sh
```

## 5) Build Validator + Train Images
```
./deploy/gcp/build_validator_image.sh
./deploy/gcp/build_train_image.sh
```

## 6) Upload Repos / Datasets (optional)
```
# Upload repos for cloud data pipeline
./deploy/gcp/sync_repos.sh

# Upload datasets built locally
./deploy/gcp/sync_datasets.sh
```

## 7) Run Vertex AI Training (recommended)
```
# Uses the latest training image in Artifact Registry
# Set RUN_DATA_PIPELINE=1 to rebuild datasets in cloud
RUN_DATA_PIPELINE=1 ./deploy/gcp/run_vertex_train.sh
```

Default training parameters (override with env vars):
- `TRANSFORMER_SIZE=medium`
- `EPOCHS=20`
- `BATCH_SIZE=32`
- `MAX_FILES=400`
- `MAX_SAMPLES=15000`

Budget-aware compute defaults:
- `MACHINE_TYPE=n1-standard-16`
- GPU optional via `ACCELERATOR_TYPE` + `ACCELERATOR_COUNT`

Example: CPU-only (fast + cost-balanced)
```
MACHINE_TYPE=n1-standard-16 EPOCHS=20 MAX_FILES=400 ./deploy/gcp/run_vertex_train.sh
```

Example: GPU (faster transformer training)
```
MACHINE_TYPE=n1-standard-8 ACCELERATOR_TYPE=NVIDIA_TESLA_T4 ACCELERATOR_COUNT=1 \\
  EPOCHS=20 ./deploy/gcp/run_vertex_train.sh
```

## 8) Validate Patch in Cloud Build (Docker)
```
./deploy/gcp/validate_patch_cloudbuild.sh artifacts/patches/selected.diff HEAD
```

## Notes
- Cloud Run is **not** suitable for Docker‑in‑Docker. Patch validation must run via Cloud Build.
- Vertex AI runs the full training loop within the `docker/train.Dockerfile` image.
- All model artifacts are synced to `GCS_BUCKET_MODELS`.
