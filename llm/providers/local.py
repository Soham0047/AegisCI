from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class LocalProvider:
    """Deterministic offline provider for tests and local runs."""

    def generate_patch(self, context: dict[str, Any]) -> str:
        candidates = context.get("local_candidates")
        if isinstance(candidates, list) and candidates:
            candidate_id = str(context.get("candidate_id") or "0")
            try:
                index = int(candidate_id.split("-")[-1])
            except ValueError:
                index = 0
            if 0 <= index < len(candidates):
                return candidates[index]
            return candidates[0]

        if "fixture_diff" in context and isinstance(context["fixture_diff"], str):
            return context["fixture_diff"]

        snippet = (context.get("snippet") or "").strip()
        if "shell=True" in snippet:
            return (
                "--- a/app.py\n"
                "+++ b/app.py\n"
                "@@ -1,2 +1,2 @@\n"
                "-subprocess.run(['ls'], shell=True)\n"
                "+subprocess.run(['ls'])\n"
            )

        return "--- a/unknown.txt\n" "+++ b/unknown.txt\n" "@@ -1 +1 @@\n" "-old\n" "+new\n"

    def explain(self, context: dict[str, Any]) -> str:
        return "Deterministic local provider summary."
