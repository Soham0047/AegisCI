from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

from llm.providers.gemini import GeminiProvider
from llm.providers.local import LocalProvider
from llm.providers.openai import OpenAIProvider


class LLMProvider(Protocol):
    def generate_patch(self, context: dict[str, Any]) -> str: ...

    def explain(self, context: dict[str, Any]) -> str: ...


@dataclass
class PatchGenerationResult:
    ok: bool
    diff: str | None
    error: str | None
    provider: str
    raw: str


def get_provider() -> LLMProvider:
    provider = os.environ.get("PATCH_LLM_PROVIDER", "local").lower()
    if provider == "openai":
        return OpenAIProvider()
    if provider == "gemini":
        return GeminiProvider()
    return LocalProvider()


def generate_patch(context: dict[str, Any]) -> PatchGenerationResult:
    provider_name = os.environ.get("PATCH_LLM_PROVIDER", "local").lower()
    provider = get_provider()
    raw = provider.generate_patch(context)
    ok, reason = enforce_diff_only(raw)
    if not ok:
        return PatchGenerationResult(
            ok=False,
            diff=None,
            error=reason or "diff-only enforcement failed",
            provider=provider_name,
            raw=raw,
        )
    return PatchGenerationResult(ok=True, diff=raw, error=None, provider=provider_name, raw=raw)


def explain(context: dict[str, Any]) -> str:
    provider = get_provider()
    return provider.explain(context)


def enforce_diff_only(text: str) -> tuple[bool, str | None]:
    if "```" in text:
        return False, "contains code fence"
    if re.search(r"\bExplanation\b", text):
        return False, "contains prose"
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return False, "empty response"
    first = lines[0]
    if not (first.startswith("diff --git") or first.startswith("--- a/")):
        return False, "missing diff header"
    if any(line.startswith("$") for line in lines):
        return False, "contains shell prompt"
    return True, None


def redact_text(text: str) -> str:
    patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"sk-[A-Za-z0-9]{20,}",
        r"AIza[0-9A-Za-z\\-_]{35}",
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
    ]
    redacted = text
    for pat in patterns:
        redacted = re.sub(pat, "[REDACTED]", redacted)
    redacted = re.sub(r"[A-Za-z0-9_/=+\\-]{32,}", "[REDACTED]", redacted)
    return redacted
