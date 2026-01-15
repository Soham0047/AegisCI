from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class OpenAIProvider:
    def generate_patch(self, context: dict[str, Any]) -> str:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        base_url = os.environ.get("PATCH_LLM_BASE_URL", "https://api.openai.com/v1")
        model = os.environ.get("GUARDIAN_OPENAI_MODEL") or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        temperature = float(os.environ.get("PATCH_LLM_TEMPERATURE", "0"))
        max_tokens = int(os.environ.get("PATCH_LLM_MAX_TOKENS", "800"))

        prompt = _build_prompt(context)
        body = {
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {
                    "role": "system",
                    "content": "Return ONLY a unified diff. No prose.",
                },
                {"role": "user", "content": prompt},
            ],
        }
        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]

    def explain(self, context: dict[str, Any]) -> str:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        base_url = os.environ.get("PATCH_LLM_BASE_URL", "https://api.openai.com/v1")
        model = os.environ.get("GUARDIAN_OPENAI_MODEL") or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        prompt = _build_explain_prompt(context)
        body = {
            "model": model,
            "temperature": 0,
            "max_tokens": 200,
            "messages": [
                {"role": "system", "content": "Provide a short summary."},
                {"role": "user", "content": prompt},
            ],
        }
        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]


def _build_prompt(context: dict[str, Any]) -> str:
    citations = "\n".join(context.get("citations") or [])
    finding = context.get("finding") or {}
    filepath = finding.get("filepath", "unknown")
    start_line = finding.get("start_line", 1)
    return (
        "You are Patch Copilot. Return ONLY a unified diff. No prose.\n"
        "STRICT FORMAT:\n"
        f"1) Start with: diff --git a/{filepath} b/{filepath}\n"
        f"2) Then include: --- a/{filepath} and +++ b/{filepath}\n"
        "3) Include @@ -<line>,<count> +<line>,<count> @@ with numeric values (no '...').\n"
        "4) Use exact lines from the snippet for context; do NOT invent code.\n"
        "5) Do NOT wrap in ``` or add explanations.\n"
        "Constraints: no commands, no secrets, minimal localized edits.\n"
        f"Finding JSON: {json.dumps(context.get('finding'))}\n"
        f"Hint: hunk should start near line {start_line}.\n"
        f"Snippet:\n{context.get('snippet')}\n"
        f"Citations:\n{citations}\n"
    )


def _build_explain_prompt(context: dict[str, Any]) -> str:
    citations = "\n".join(context.get("citations") or [])
    return (
        "Summarize the proposed fix in 2-3 sentences with citation IDs.\n"
        f"Finding: {json.dumps(context.get('finding'))}\n"
        f"Citations:\n{citations}\n"
    )
