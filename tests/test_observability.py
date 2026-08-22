"""Tracing.

Coverage put this module at 73%; the untested lines were exporter selection and `configure()` -
i.e. the code that decides whether telemetry goes anywhere at all. An observability layer that
silently exports nothing is worse than none, because it looks like it is working.
"""

import importlib

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import aegis.observability as obs


@pytest.fixture(autouse=True)
def _fresh_module():
    """Each test gets a clean module: `configure()` is idempotent by design, which makes it sticky."""
    importlib.reload(obs)
    yield
    importlib.reload(obs)


@pytest.fixture
def recorded_spans(monkeypatch):
    """A LOCAL recording tracer, so attribute assertions actually run.

    `obs.span()` opens its span on the global tracer, which is a no-op provider when tracing is off
    (`AEGIS_TRACE=0`, the default for tests). On a no-op span `set_attribute` silently does nothing,
    so a test guarding its assertions behind `if attrs:` passes having verified NOTHING. Rather than
    fight OpenTelemetry's set-once global provider, this points `obs.tracer` at a private in-memory
    provider for the duration of the test - deterministic regardless of env, and no global mutation.
    Returns (exporter, tracer); read the finished span off the exporter.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    local_tracer = provider.get_tracer("test")
    monkeypatch.setattr(obs, "tracer", lambda: local_tracer)
    return exporter, local_tracer


def test_configure_is_idempotent(monkeypatch):
    monkeypatch.delenv("AEGIS_TRACE", raising=False)
    obs.configure()
    first = trace.get_tracer_provider()
    obs.configure()
    assert trace.get_tracer_provider() is first, "configure() replaced the provider on second call"


def test_trace_disabled_short_circuits(monkeypatch):
    monkeypatch.setenv("AEGIS_TRACE", "0")
    obs.configure()
    assert obs._CONFIGURED is False, "AEGIS_TRACE=0 must not install a provider"


def test_console_exporter_selected_by_env(monkeypatch):
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter

    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.setenv("AEGIS_TRACE_CONSOLE", "1")
    assert isinstance(obs._build_exporter(), ConsoleSpanExporter)


def test_no_exporter_when_nothing_is_configured(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("AEGIS_TRACE_CONSOLE", raising=False)
    assert obs._build_exporter() is None, "spans should not be exported unless asked for"


def test_otlp_endpoint_selects_an_exporter_and_never_raises(monkeypatch):
    """If the OTLP extra is missing it must fall back, not crash.

    Telemetry failing to ship is an inconvenience. Telemetry taking the incident-response tool down
    during an incident is not acceptable.
    """
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    exporter = obs._build_exporter()
    assert exporter is not None


def test_span_sets_prefixed_attributes_and_skips_none(recorded_spans):
    exporter, _ = recorded_spans
    with obs.span("unit.test", alpha="a", beta=None):
        pass
    finished = exporter.get_finished_spans()
    assert len(finished) == 1, "the span was not recorded - the test would prove nothing"
    attrs = dict(finished[0].attributes or {})
    assert attrs.get("aegis.alpha") == "a"
    assert "aegis.beta" not in attrs, "None-valued attributes should be omitted, not stringified"


def test_span_records_the_exception_and_re_raises():
    """Swallowing an exception inside a span would hide failures from both the trace AND the caller."""
    with pytest.raises(ValueError, match="boom"), obs.span("unit.explode"):
        raise ValueError("boom")


def test_gen_ai_attribute_names_match_the_spec():
    """These constants are the whole reason Langfuse and Phoenix can read our traces.

    A typo here produces an attribute nothing queries, and nothing would fail.
    """
    assert obs.GEN_AI_OPERATION == "gen_ai.operation.name"
    assert obs.GEN_AI_PROVIDER == "gen_ai.provider.name"
    assert obs.GEN_AI_REQUEST_MODEL == "gen_ai.request.model"
    assert obs.GEN_AI_INPUT_TOKENS == "gen_ai.usage.input_tokens"
    assert obs.GEN_AI_OUTPUT_TOKENS == "gen_ai.usage.output_tokens"


def test_record_model_call_sets_every_field(recorded_spans):
    exporter, tracer = recorded_spans
    with tracer.start_as_current_span("m") as sp:
        obs.record_model_call(
            sp, operation="chat", provider="gemini", model="gemini-3.6-flash",
            input_tokens=10, output_tokens=5, usd=0.001,
        )
    finished = exporter.get_finished_spans()
    assert len(finished) == 1, "the span was not recorded - the test would prove nothing"
    attrs = dict(finished[0].attributes or {})
    assert attrs[obs.GEN_AI_OPERATION] == "chat"
    assert attrs[obs.GEN_AI_PROVIDER] == "gemini"
    assert attrs[obs.GEN_AI_REQUEST_MODEL] == "gemini-3.6-flash"
    assert attrs[obs.GEN_AI_INPUT_TOKENS] == 10
    assert attrs[obs.GEN_AI_OUTPUT_TOKENS] == 5
    assert attrs["aegis.cost.usd"] == 0.001
