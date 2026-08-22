"""Provider adapters.

Coverage put this module at 57%. The uncovered lines were the `complete()` methods - the code that
maps each vendor's response shape onto our `Completion`. That mapping is where provider-specific
bugs live, and it cannot be exercised by the mock path.

Real SDK clients are stubbed rather than called. That is not a compromise: it is the only way to
test the failure modes that matter - a provider that reports no usage metadata, or returns its text
in a different place - on demand instead of by waiting for them in production.
"""

import os

import pytest

# Vendor SDKs are OPTIONAL extras - the core package installs without any of them, and CI proves
# that in a bare venv. Tests that construct a real provider must skip rather than fail when the
# corresponding extra is absent, or the suite quietly requires what the package says it does not.
openai_sdk = pytest.importorskip("openai", reason="pip install -e '.[openai]'")

from aegis.providers import (
    Completion,
    OpenAICompatProvider,
    ProviderError,
    _estimate_tokens,
    resolve,
)

# --------------------------------------------------------------------- token estimation


def test_estimate_is_deliberately_pessimistic():
    """A budget fed an under-estimate fails to stop the thing it exists to stop.

    3 chars/token over-counts relative to the usual ~4, on purpose.
    """
    text = "x" * 1200
    assert _estimate_tokens(text) == 400
    assert _estimate_tokens(text) > len(text) // 4


def test_estimate_never_returns_zero():
    """Zero tokens would make a budget un-triggerable."""
    assert _estimate_tokens("") >= 1
    assert _estimate_tokens("a") >= 1


# --------------------------------------------------------------------- resolution


def test_unknown_provider_lists_the_valid_options():
    with pytest.raises(ProviderError) as exc:
        resolve("banana")
    msg = str(exc.value)
    assert "banana" in msg
    for known in ("anthropic", "gemini", "openai", "ollama"):
        assert known in msg


def test_gemini_without_a_key_points_at_where_to_get_one(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(ProviderError) as exc:
        resolve("gemini")
    assert "aistudio.google.com" in str(exc.value)


def test_gemini_accepts_either_key_variable(monkeypatch):
    """GOOGLE_API_KEY is what the Google SDK itself documents; GEMINI_API_KEY is what AI Studio shows."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-for-construction-only")
    p = resolve("gemini")
    assert p.name == "gemini"


@pytest.mark.parametrize(
    "alias,expected_host",
    [("groq", "groq.com"), ("openrouter", "openrouter.ai"), ("ollama", "localhost:11434")],
)
def test_openai_aliases_point_at_the_right_host(monkeypatch, alias, expected_host):
    """One OpenAI-shaped client covers four vendors - the alias must set the base URL for you."""
    monkeypatch.delenv("AEGIS_BASE_URL", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    resolve(alias)
    assert expected_host in os.environ["AEGIS_BASE_URL"]


def test_ollama_needs_no_real_key(monkeypatch):
    """Local models are the answer for teams that cannot send logs anywhere. A key must not block that."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_BASE_URL", raising=False)
    p = resolve("ollama")
    assert p.name == "openai"


def test_openai_without_key_or_base_url_fails_clearly(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_BASE_URL", raising=False)
    with pytest.raises(ProviderError) as exc:
        OpenAICompatProvider()
    assert "OPENAI_API_KEY" in str(exc.value)


def test_model_is_overridable_by_env(monkeypatch):
    """A pinned model id is a dated assumption - gemini-2.0-flash was retired mid-project."""
    monkeypatch.setenv("GOOGLE_API_KEY", "fake")
    monkeypatch.setenv("AEGIS_MODEL", "gemini-3.6-flash-lite")
    assert resolve("gemini").model == "gemini-3.6-flash-lite"


# --------------------------------------------------------------------- response mapping


class _FakeOpenAIResponse:
    def __init__(self, text, usage=None):
        self.choices = [type("C", (), {"message": type("M", (), {"content": text})()})()]
        self.usage = usage


def test_openai_adapter_maps_text_and_usage(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    monkeypatch.delenv("AEGIS_BASE_URL", raising=False)
    p = OpenAICompatProvider()
    usage = type("U", (), {"prompt_tokens": 111, "completion_tokens": 22})()
    p._client = type("Cl", (), {
        "chat": type("Ch", (), {
            "completions": type("Co", (), {
                "create": staticmethod(lambda **kw: _FakeOpenAIResponse('{"a":1}', usage))
            })()
        })()
    })()
    out = p.complete(system="s", user="u")
    assert isinstance(out, Completion)
    assert out.text == '{"a":1}'
    assert out.input_tokens == 111 and out.output_tokens == 22


def test_openai_adapter_estimates_when_the_provider_reports_no_usage(monkeypatch):
    """Some OpenAI-compatible servers (Ollama among them) omit usage. Zeros would disarm the budget."""
    monkeypatch.setenv("OPENAI_API_KEY", "fake")
    monkeypatch.delenv("AEGIS_BASE_URL", raising=False)
    p = OpenAICompatProvider()
    p._client = type("Cl", (), {
        "chat": type("Ch", (), {
            "completions": type("Co", (), {
                "create": staticmethod(lambda **kw: _FakeOpenAIResponse("hello world", None))
            })()
        })()
    })()
    out = p.complete(system="system prompt", user="user prompt")
    assert out.input_tokens > 0, "no usage reported and no estimate - budget would never fire"
    assert out.output_tokens > 0
