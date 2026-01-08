# Data & Datasets

This folder is the local data workspace for dataset generation. It does **not** require
network access. You provide repos locally, and the builder writes JSONL datasets.

## Inputs
- `data/repos/`: place one or more repo folders here (each subfolder is treated as a repo).

Example:
```
data/repos/
  repo_one/
  repo_two/
```

## Outputs
- `datasets/python/{train,val,test}.jsonl`
- `datasets/ts/{train,val,test}.jsonl`
- `datasets/python/all.jsonl` and `datasets/ts/all.jsonl`

## Build
```bash
python scripts/build_dataset.py \
  --repos-dir data/repos \
  --out-dir datasets \
  --languages python,ts \
  --context-lines 10 \
  --seed 1337 \
  --split 0.8,0.1,0.1 \
  --commit-mode workdir \
  --validate
```

## Validate Only
```bash
python scripts/build_dataset.py \
  --repos-dir data/repos \
  --out-dir datasets \
  --languages python,ts \
  --validate
```

## Expected Output Tree
```
datasets/
  python/
    all.jsonl
    train.jsonl
    val.jsonl
    test.jsonl
  ts/
    all.jsonl
    train.jsonl
    val.jsonl
    test.jsonl
```

## Weak labeling
Run tools and map findings into dataset samples:
```bash
python scripts/weak_label.py label \
  --repos-dir data/repos \
  --tool-outputs data/tool_outputs \
  --datasets-dir datasets \
  --semgrep-config p/ci \
  --workers 4
```

Map existing tool outputs into labels (no tool runs):
```bash
python scripts/weak_label.py map \
  --tool-outputs data/tool_outputs \
  --datasets-dir datasets \
  --out datasets/weak_labels.jsonl
```

Note: Semgrep registry configs may download rules if not cached. Tests use fixtures and do not
require network access.

## Gold labeling
Generate a selected set (deterministic) and label interactively:
```bash
python scripts/label_gold.py select --inputs datasets/python/all.jsonl,datasets/ts/all.jsonl
python scripts/label_gold.py label --annotator alice --max-items 5
python scripts/label_gold.py stats
```
See `data/labeling_guide.md` for taxonomy and guidance.
