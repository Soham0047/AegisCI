# Deep Learning Training Pipeline

This document describes the deep learning training pipeline for SecureDev Guardian, including dataset preparation, model training, and configuration options.

## Overview

The DL training pipeline consists of three main components:

1. **Embeddings Model** (`rag/dl/train_embeddings.py`) - Dual-encoder for code similarity
2. **Reranker Model** (`rag/dl/train_reranker.py`) - MLP for retrieval reranking
3. **Patch Ranker Model** (`patcher/dl/train_patch_ranker.py`) - Ranks patch candidates

## Quick Start

```bash
# Build balanced dataset from data/repos/
python -m rag.dl.dataset --build-balanced

# Train all models
python -m rag.dl.train_embeddings
python -m rag.dl.train_reranker
python -m patcher.dl.train_patch_ranker
```

## Dataset Preparation

### Balanced Dataset

The pipeline now supports automatic dataset balancing to achieve a 50/50 vulnerable vs safe code split:

```python
from rag.dl.dataset import build_balanced_dataset
from pathlib import Path

# Build balanced dataset with default settings
dataset = build_balanced_dataset(
    repos_root=Path("data/repos"),
    output_dir=Path("artifacts/dl/balanced"),
    balance_ratio=0.5,  # 50/50 split
    seed=1337,          # Deterministic
)

print(f"Train: {len(dataset.train)} samples")
print(f"Val: {len(dataset.val)} samples")
print(f"Test: {len(dataset.test)} samples")
print(f"Stats: {dataset.stats}")
```

### Data Augmentation

Deterministic data augmentation is available to increase dataset diversity:

```python
from rag.dl.augment import augment_text, AugmentConfig

config = AugmentConfig(
    enable_shuffle=True,
    enable_whitespace=True,
    enable_rename=True,
    enable_comment=True,
    shuffle_prob=0.3,
    whitespace_prob=0.2,
    rename_prob=0.4,
    comment_prob=0.2,
)

result = augment_text(code, seed=42, config=config)
print(f"Original: {result.original}")
print(f"Augmented: {result.augmented}")
print(f"Transforms: {result.transformations}")
```

#### Augmentation Types

| Transform | Description |
|-----------|-------------|
| `shuffle_tokens_local` | Window-based token shuffling (preserves string literals) |
| `perturb_whitespace` | Normalize/strip whitespace variations |
| `rename_identifiers` | Deterministic variable renaming (var_1, var_2, ...) |
| `manipulate_comments` | Insert/remove comments |

### Building Dataset with Augmentation

```python
dataset = build_balanced_dataset(
    repos_root=Path("data/repos"),
    augment_k=3,  # Generate 3 augmented variants per sample
    seed=1337,
)
```

## Training Configuration

### Hyperparameters

All training scripts support both CLI arguments and environment variables:

| Parameter | CLI | Env Variable | Default |
|-----------|-----|--------------|---------|
| Epochs | `--epochs` | `DL_EPOCHS` | 10 (embeddings/reranker), 20 (patch) |
| Learning Rate | `--lr` | `DL_LR` | 5e-4 (embeddings/reranker), 5e-3 (patch) |
| Seed | `--seed` | `DL_SEED` | 1337 |
| Weight Decay | `--weight-decay` | `DL_WEIGHT_DECAY` | 0.01 |
| Warmup Steps | `--warmup-steps` | `DL_WARMUP_STEPS` | 100 |
| Batch Size | `--batch-size` | `DL_BATCH_SIZE` | 16 |

### Environment Variable Examples

```bash
# Use environment variables for CI/CD
export DL_EPOCHS=20
export DL_LR=1e-4
export DL_SEED=42
export DL_ARTIFACTS_DIR=artifacts/dl

python -m rag.dl.train_embeddings
```

### CLI Examples

```bash
# Full training with custom hyperparameters
python -m rag.dl.train_embeddings \
    --epochs 15 \
    --lr 1e-4 \
    --batch-size 32 \
    --weight-decay 0.01 \
    --seed 42

# Quick smoke test
python -m rag.dl.train_embeddings --epochs 1 --max-pairs 50
```

## Optional Pretrained Models

The pipeline supports optional pretrained code models (CodeBERT, CodeT5) with offline-safe fallback:

### Enabling Pretrained Models

```bash
# Enable pretrained model loading
export DL_PRETRAINED_MODEL=1

# Force offline mode (default)
export DL_PRETRAINED_OFFLINE=1

python -m rag.dl.train_embeddings
```

### Fallback Behavior

If pretrained models cannot be loaded (network unavailable, library not installed), the pipeline automatically falls back to a simple learned embedding layer. This ensures:

1. **Offline Safety**: No network calls during training by default
2. **Graceful Degradation**: Training continues without pretrained weights
3. **Determinism**: Same results given same seed, regardless of fallback

### Supported Pretrained Models

| Model | Description |
|-------|-------------|
| `microsoft/codebert-base` | CodeBERT for code understanding (default) |
| `Salesforce/codet5-base` | CodeT5 encoder |

## Testing

### Running Tests

```bash
# Run quick tests (default)
pytest tests/test_dataset_balance.py -v
pytest tests/test_augmentation_determinism.py -v

# Run full DL training tests (slower)
RUN_DL_TRAIN_TESTS=1 pytest tests/test_dataset_balance.py -v
RUN_DL_TRAIN_TESTS=1 pytest tests/test_augmentation_determinism.py -v

# Run all DL tests
RUN_DL_TRAIN_TESTS=1 pytest tests/ -k "dl or dataset or augment" -v
```

### Test Categories

| Test File | Description | Gated |
|-----------|-------------|-------|
| `test_dataset_balance.py` | Dataset balancing, splits, determinism | Yes |
| `test_augmentation_determinism.py` | Augmentation determinism, config | Yes |
| `test_dl_embeddings_train_smoke.py` | Embeddings training smoke test | Yes |
| `test_dl_reranker_integration.py` | Reranker integration | Yes |

## Directory Structure

```
artifacts/dl/
├── balanced/              # Balanced dataset
│   ├── train.jsonl
│   ├── val.jsonl
│   ├── test.jsonl
│   └── stats.json
├── pairs.jsonl            # Training pairs
├── triples.jsonl          # Retrieval triples
├── embeddings_model.pt    # Trained embeddings model
├── embeddings_meta.json
├── vocab.json
├── reranker_model.pt      # Trained reranker
├── reranker_meta.json
└── patch_ranker.pt        # Trained patch ranker
```

## Reproducibility

All operations are deterministic given the same seed:

```python
# These will produce identical results
dataset1 = build_balanced_dataset(seed=1337)
dataset2 = build_balanced_dataset(seed=1337)
assert dataset1.train == dataset2.train

# Augmentation is also deterministic
result1 = augment_text(code, seed=42)
result2 = augment_text(code, seed=42)
assert result1.augmented == result2.augmented
```

### Seed Propagation

- Dataset building: `seed` parameter
- Augmentation: `seed` or `base_seed` parameter
- Training: `--seed` CLI arg or `DL_SEED` env var
- PyTorch: `torch.manual_seed(seed)` called at training start
- Python random: `random.seed(seed)` called at training start

## Troubleshooting

### "ModuleNotFoundError: transformers"

Pretrained models require the `transformers` library:

```bash
pip install transformers
```

Or disable pretrained models:

```bash
export DL_PRETRAINED_MODEL=0  # (default)
```

### "OSError: Couldn't reach model on hub"

The pipeline is offline by default. To enable network access:

```bash
export DL_PRETRAINED_OFFLINE=0
export DL_PRETRAINED_MODEL=1
```

### "CUDA out of memory"

Reduce batch size:

```bash
python -m rag.dl.train_embeddings --batch-size 8
```

### Tests skipped

DL training tests are gated. Enable them:

```bash
RUN_DL_TRAIN_TESTS=1 pytest tests/test_dataset_balance.py
```

## Performance Tips

1. **Dataset Size**: Use `--max-pairs` / `--max-triples` for quick iterations
2. **Epochs**: More epochs (10-20) generally improve convergence
3. **Learning Rate**: Lower LR (1e-4 to 5e-4) for stable training
4. **Weight Decay**: 0.01 helps prevent overfitting
5. **Batch Size**: Larger batches (32-64) if memory allows
6. **Augmentation**: 2-3 variants per sample for better generalization
