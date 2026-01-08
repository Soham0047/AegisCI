
from llm.providers.local import LocalProvider
from patcher.llm_client import get_provider


def test_provider_default_local(monkeypatch) -> None:
    monkeypatch.delenv("PATCH_LLM_PROVIDER", raising=False)
    provider = get_provider()
    assert isinstance(provider, LocalProvider)


def test_provider_explicit_local(monkeypatch) -> None:
    monkeypatch.setenv("PATCH_LLM_PROVIDER", "local")
    provider = get_provider()
    assert isinstance(provider, LocalProvider)
