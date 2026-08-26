"""OpenTelemetry tracing for the graph.

One span per node, so a run is a tree an operator can read: which node was slow, which tool failed,
what the verdict was, and what the tokens cost. This is the difference between "the agent did
something" and "here is exactly what it did, in order, with timings".

By default a provider IS installed but NO exporter is attached, so spans are recorded and nothing
is printed — the human-readable verdict output stays clean. Opt in to seeing traces without any
collector by setting `WARDEN_TRACE_CONSOLE=1` (prints spans to the console); set
`OTEL_EXPORTER_OTLP_ENDPOINT` to ship to a real backend (Langfuse, Phoenix, any OTLP collector)
instead. If that OTLP exporter extra is not installed, it falls back to the console rather than
crashing a run.

`WARDEN_TRACE=0` turns tracing off entirely for quiet test runs.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter

_CONFIGURED = False


def _build_exporter() -> SpanExporter | None:
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            return OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")
        except ImportError:
            # The OTLP exporter is an optional extra. Fall back rather than crash a run because
            # telemetry could not be shipped - observability must never take the system down.
            return ConsoleSpanExporter()
    if os.environ.get("WARDEN_TRACE_CONSOLE") == "1":
        return ConsoleSpanExporter()
    return None


def configure() -> None:
    """Idempotent. Safe to call from every entry point."""
    global _CONFIGURED
    if _CONFIGURED or os.environ.get("WARDEN_TRACE") == "0":
        return
    provider = TracerProvider(
        resource=Resource.create({"service.name": "warden", "service.version": "0.5.1"})
    )
    exporter = _build_exporter()
    if exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _CONFIGURED = True


def tracer() -> trace.Tracer:
    configure()
    return trace.get_tracer("warden")


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[trace.Span]:
    """Open a span with attributes, and record an exception properly if one escapes."""
    with tracer().start_as_current_span(name) as sp:
        for key, value in attrs.items():
            if value is not None:
                sp.set_attribute(f"warden.{key}", value)
        try:
            yield sp
        except Exception as exc:
            sp.record_exception(exc)
            sp.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
            raise


def record_cost(sp: trace.Span, *, input_tokens: int, output_tokens: int, usd: float) -> None:
    """Token and money on the span itself, so cost is queryable per run and per node.

    Uses the **OpenTelemetry GenAI semantic conventions** (`gen_ai.*`) rather than invented names.
    That is the difference between traces a tool can read and traces only we can read: Langfuse,
    Arize Phoenix and any OTLP backend understand `gen_ai.usage.input_tokens` out of the box.

    ⚠ The GenAI conventions were moved to their own repository in semconv v1.42.0 (June 2026) and
    remain in *Development* status — the core usage and model attributes are stable enough to build
    on, but expect churn. Cost is not in the spec, so it stays under `warden.`
    """
    sp.set_attribute(GEN_AI_INPUT_TOKENS, input_tokens)
    sp.set_attribute(GEN_AI_OUTPUT_TOKENS, output_tokens)
    sp.set_attribute("warden.cost.usd", usd)  # not a spec attribute; ours by necessity


# OpenTelemetry GenAI semantic conventions. Named constants rather than inline strings so a spec
# change is one edit, and so a typo cannot silently produce an attribute nothing queries.
GEN_AI_OPERATION = "gen_ai.operation.name"
GEN_AI_PROVIDER = "gen_ai.provider.name"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"


def record_model_call(
    sp: trace.Span,
    *,
    operation: str,
    provider: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    usd: float,
) -> None:
    """Everything one model call should put on a span, in spec order."""
    sp.set_attribute(GEN_AI_OPERATION, operation)
    sp.set_attribute(GEN_AI_PROVIDER, provider)
    sp.set_attribute(GEN_AI_REQUEST_MODEL, model)
    record_cost(sp, input_tokens=input_tokens, output_tokens=output_tokens, usd=usd)
