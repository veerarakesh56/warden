"""OpenTelemetry tracing for the graph.

One span per node, so a run is a tree an operator can read: which node was slow, which tool failed,
what the verdict was, and what the tokens cost. This is the difference between "the agent did
something" and "here is exactly what it did, in order, with timings".

Defaults to a console exporter so the trace is visible with no collector running — a demo that
needs a Jaeger stack before you can see anything is a demo nobody runs. Set
`OTEL_EXPORTER_OTLP_ENDPOINT` to ship to a real backend instead.

`AEGIS_TRACE=0` turns tracing off entirely for quiet test runs.
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
    if os.environ.get("AEGIS_TRACE_CONSOLE") == "1":
        return ConsoleSpanExporter()
    return None


def configure() -> None:
    """Idempotent. Safe to call from every entry point."""
    global _CONFIGURED
    if _CONFIGURED or os.environ.get("AEGIS_TRACE") == "0":
        return
    provider = TracerProvider(
        resource=Resource.create({"service.name": "aegis", "service.version": "0.1.0"})
    )
    exporter = _build_exporter()
    if exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _CONFIGURED = True


def tracer() -> trace.Tracer:
    configure()
    return trace.get_tracer("aegis")


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[trace.Span]:
    """Open a span with attributes, and record an exception properly if one escapes."""
    with tracer().start_as_current_span(name) as sp:
        for key, value in attrs.items():
            if value is not None:
                sp.set_attribute(f"aegis.{key}", value)
        try:
            yield sp
        except Exception as exc:
            sp.record_exception(exc)
            sp.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
            raise


def record_cost(sp: trace.Span, *, input_tokens: int, output_tokens: int, usd: float) -> None:
    """Token and money on the span itself, so cost is queryable per run and per node."""
    sp.set_attribute("aegis.tokens.input", input_tokens)
    sp.set_attribute("aegis.tokens.output", output_tokens)
    sp.set_attribute("aegis.cost.usd", usd)
