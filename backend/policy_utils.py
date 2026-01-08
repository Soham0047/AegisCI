from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

POLICY_PATH = Path("gateway/policy.yaml")


def load_base_policy() -> dict[str, Any]:
    if not POLICY_PATH.exists():
        return {"version": 1, "tools": []}
    data = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return {"version": 1, "tools": []}
    return data


def merge_policy_overrides(org_overrides: dict | None, repo_overrides: dict | None) -> dict:
    merged: dict[str, Any] = {}
    if isinstance(org_overrides, dict):
        merged = _deep_copy(org_overrides)
    if isinstance(repo_overrides, dict):
        merged = _merge_dicts(merged, repo_overrides)
    return merged


def apply_policy_overrides(
    base_policy: dict[str, Any], overrides: dict[str, Any]
) -> dict[str, Any]:
    policy = _deep_copy(base_policy)
    tools = policy.get("tools")
    if not isinstance(tools, list) or not overrides:
        return policy
    tools_by_name = {tool.get("name"): tool for tool in tools if isinstance(tool, dict)}
    for override in overrides.get("tools", []) if isinstance(overrides, dict) else []:
        if not isinstance(override, dict):
            continue
        name = override.get("name")
        if name not in tools_by_name:
            continue
        tool = tools_by_name[name]
        for key in (
            "allowed",
            "scopes",
            "requires_approval",
            "arg_constraints",
            "redaction",
            "output",
        ):
            if key in override:
                tool[key] = override[key]
    policy["tools"] = list(tools_by_name.values())
    return policy


def validate_policy_overrides(overrides: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(overrides, dict):
        return ["policy_overrides must be object"]
    tools = overrides.get("tools")
    if tools is None:
        return []
    if not isinstance(tools, list):
        return ["policy_overrides.tools must be list"]
    for item in tools:
        if not isinstance(item, dict):
            errors.append("policy_overrides.tools entries must be object")
            continue
        if "name" not in item:
            errors.append("policy_overrides.tools entry missing name")
        for key in item:
            if key not in {
                "name",
                "allowed",
                "scopes",
                "requires_approval",
                "arg_constraints",
                "redaction",
                "output",
            }:
                errors.append(f"policy_overrides.tools.{key} not allowed")
    return errors


def _deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _merge_dicts(base: dict, updates: dict) -> dict:
    merged = _deep_copy(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged
