from __future__ import annotations

import random
from collections import defaultdict
from hashlib import sha256
from typing import Any

DEFAULT_SEVERITY_WEIGHTS = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1,
}


def build_item_id(sample_id: str, finding: dict[str, Any]) -> str:
    raw = "|".join(
        [
            sample_id,
            str(finding.get("source") or ""),
            str(finding.get("rule_id") or ""),
            str(finding.get("line") or ""),
            str(finding.get("message") or ""),
        ]
    )
    return sha256(raw.encode()).hexdigest()


def build_label_items(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for sample in samples:
        for finding in sample.get("weak_labels", []) or []:
            item = {
                "item_id": build_item_id(sample["sample_id"], finding),
                "sample_id": sample["sample_id"],
                "language": sample["language"],
                "repo": sample["repo"],
                "commit": sample["commit"],
                "filepath": sample["filepath"],
                "span": sample["function_span"],
                "code_snippet": sample["code_snippet"],
                "context_before": sample["context_before"],
                "context_after": sample["context_after"],
                "finding": {
                    "source": finding.get("source"),
                    "rule_id": finding.get("rule_id"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "message": finding.get("message"),
                    "line": finding.get("line"),
                },
                "duplicate_group": None,
            }
            items.append(item)
    return items


def _hardness_score(item: dict[str, Any], noisy_rules: set[str] | None) -> int:
    score = 0
    finding = item.get("finding") or {}
    confidence = str(finding.get("confidence") or "").upper()
    if confidence in {"LOW", "LOW_CONFIDENCE"}:
        score += 1

    span = item.get("span") or {}
    start = span.get("start_line", 0)
    end = span.get("end_line", 0)
    span_len = max(0, end - start + 1)
    if span_len > 40:
        score += 1

    line = finding.get("line")
    if isinstance(line, int):
        if abs(line - start) <= 2 or abs(end - line) <= 2:
            score += 1

    rule_id = finding.get("rule_id") or ""
    if noisy_rules and rule_id in noisy_rules:
        score += 1

    return score


def _rank_items(
    items: list[dict[str, Any]],
    rng: random.Random,
    severity_weights: dict[str, int],
) -> list[dict[str, Any]]:
    def score(item: dict[str, Any]) -> int:
        severity = str(item.get("finding", {}).get("severity") or "").upper()
        return severity_weights.get(severity, 1) + int(item.get("hardness", 0))

    return sorted(items, key=lambda item: (-score(item), rng.random(), item["item_id"]))


def _select_round_robin(
    pool_by_source: dict[str, list[dict[str, Any]]],
    target_n: int,
    per_rule_cap: int,
    counts_rule: dict[str, int],
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    indices = {source: 0 for source in pool_by_source}
    sources = sorted(pool_by_source.keys())

    def has_remaining() -> bool:
        return any(indices[source] < len(pool_by_source[source]) for source in sources)

    while len(selected) < target_n and has_remaining():
        for source in sources:
            pool = pool_by_source[source]
            while indices[source] < len(pool) and len(selected) < target_n:
                item = pool[indices[source]]
                indices[source] += 1
                rule_id = item.get("finding", {}).get("rule_id") or ""
                if per_rule_cap and counts_rule.get(rule_id, 0) >= per_rule_cap:
                    continue
                counts_rule[rule_id] = counts_rule.get(rule_id, 0) + 1
                selected.append(item)
                break
    return selected


def select_items(
    items: list[dict[str, Any]],
    target_n: int,
    seed: int,
    overlap_ratio: float,
    per_rule_cap: int,
    severity_weights: dict[str, int] | None = None,
    hard_fraction: float = 0.35,
    noisy_rules: set[str] | None = None,
) -> list[dict[str, Any]]:
    if not items:
        return []
    severity_weights = severity_weights or DEFAULT_SEVERITY_WEIGHTS
    target_n = min(target_n, len(items))

    rng = random.Random(seed)
    ordered = sorted(items, key=lambda item: item["item_id"])
    for item in ordered:
        item["hardness"] = _hardness_score(item, noisy_rules)

    hard_target = int(round(target_n * hard_fraction))
    hard_sorted = sorted(ordered, key=lambda item: (-item["hardness"], item["item_id"]))
    hard_ids = {item["item_id"] for item in hard_sorted[:hard_target] if item["hardness"] > 0}
    hard_items = [item for item in ordered if item["item_id"] in hard_ids]
    easy_items = [item for item in ordered if item["item_id"] not in hard_ids]

    counts_rule: dict[str, int] = {}
    selected: list[dict[str, Any]] = []

    def pool_by_source(source_items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        pools: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in source_items:
            pools[item["finding"]["source"] or "unknown"].append(item)
        for source, pool in pools.items():
            pools[source] = _rank_items(pool, rng, severity_weights)
        return pools

    hard_selected = _select_round_robin(
        pool_by_source(hard_items),
        target_n=min(hard_target, target_n),
        per_rule_cap=per_rule_cap,
        counts_rule=counts_rule,
    )
    selected.extend(hard_selected)

    remaining = target_n - len(selected)
    if remaining > 0:
        easy_selected = _select_round_robin(
            pool_by_source(easy_items),
            target_n=remaining,
            per_rule_cap=per_rule_cap,
            counts_rule=counts_rule,
        )
        selected.extend(easy_selected)

    if len(selected) < target_n:
        remaining = target_n - len(selected)
        fallback_pool = [item for item in ordered if item not in selected]
        fallback_selected = _select_round_robin(
            pool_by_source(fallback_pool),
            target_n=remaining,
            per_rule_cap=per_rule_cap,
            counts_rule=counts_rule,
        )
        selected.extend(fallback_selected)

    overlap_n = int(round(target_n * overlap_ratio))
    if overlap_n <= 0 or not selected:
        return selected

    overlap_n = min(overlap_n, len(selected))
    overlap_items = rng.sample(selected, k=overlap_n)
    duplicates: list[dict[str, Any]] = []
    for item in overlap_items:
        group_id = sha256(f"{item['item_id']}|{seed}|overlap".encode()).hexdigest()[:12]
        item["duplicate_group"] = group_id
        duplicate = dict(item)
        duplicate["duplicate_group"] = group_id
        duplicates.append(duplicate)

    return selected + duplicates
