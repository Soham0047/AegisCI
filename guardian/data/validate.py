from __future__ import annotations

import json
import logging
from pathlib import Path

from guardian.data.schema import Sample

LOGGER = logging.getLogger(__name__)


def validate_jsonl(path: Path) -> tuple[int, int]:
    if not path.exists():
        raise FileNotFoundError(path)
    total = 0
    errors = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        total += 1
        try:
            Sample.model_validate(json.loads(line))
        except Exception as exc:  # pragma: no cover - error path for debug
            errors += 1
            LOGGER.warning("Invalid sample in %s: %s", path, exc)
    return total, errors
