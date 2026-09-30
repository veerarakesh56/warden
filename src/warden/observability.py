"""OpenTelemetry tracing for the graph.

Spans for the run, each tool call and analyse/propose/verify, so a run is a tree an operator can
read: which node was slow, which tool failed,
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

import logging
import os
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter

from . import __version__

# At module level, not inside the formatter: a record logged from workflow code is formatted under
# Temporal's sandbox importer, where a lazy import is re-done and warned about (third review work,
# 2026-09-30).
from .gate import strip_controls
from .redaction import redact

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
            return ConsoleSpanExporter(out=sys.stderr)
    if os.environ.get("WARDEN_TRACE_CONSOLE") == "1":
        # stderr, never stdout (audit A-C-20): stdout is the MCP server's JSON-RPC channel, and one
        # span printed there corrupts the stream for the client.
        return ConsoleSpanExporter(out=sys.stderr)
    return None


def configure() -> None:
    """Idempotent. Safe to call from every entry point."""
    global _CONFIGURED
    if _CONFIGURED or os.environ.get("WARDEN_TRACE") == "0":
        return
    provider = TracerProvider(
        resource=Resource.create({"service.name": "warden", "service.version": __version__})
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
    # ⛔ Spans leave the process for a tracing backend. The exception's TEXT can quote evidence, a key
    # or an escape sequence (a model refusal carries 400 characters of the CLI's output), and the SDK
    # records it raw by default - twice. It is recorded here scrubbed and bounded instead
    # (independent review 2026-09-28, audit A-C-8).
    with tracer().start_as_current_span(name, record_exception=False, set_status_on_exception=False) as sp:
        for key, value in attrs.items():
            if value is not None:
                sp.set_attribute(f"warden.{key}", value)
        try:
            yield sp
        except Exception as exc:
            safe = _safe_error(exc)
            sp.add_event("exception", {"exception.type": type(exc).__name__, "exception.message": safe})
            sp.set_status(trace.Status(trace.StatusCode.ERROR, type(exc).__name__))
            raise


def _redact_then_cut(text: str, limit: int) -> str:
    """Redacted FIRST, then cut: cut first, a secret straddling the cut left a prefix the redactor no
    longer recognised (`AKIAIOSFO`, third review 2026-09-30). The raw text is bounded far above the
    limit to keep redaction cheap, and the token that bound cuts is dropped whole."""
    if len(text) > 8 * limit:
        text = re.sub(r"\S*\Z", "", text[: 8 * limit])
    return redact(text).text[:limit]


def _safe_error(exc: BaseException) -> str:
    try:
        return _redact_then_cut(" ".join(strip_controls(str(exc)).split()), 300)
    except Exception:  # noqa: BLE001 - a redaction failure must not hide the original error
        return "(error text withheld)"


class GatedFormatter(logging.Formatter):
    """A log record as the outbound gate would let it out: no control character, redacted, bounded.
    The worker's libraries log exception text and tracebacks - temporalio logs every failed activity
    with exc_info - and exception text is not WARDEN's words (review 2A defect 6)."""

    LIMIT = 8000

    def format(self, record: logging.LogRecord) -> str:
        try:
            text = _redact_then_cut(strip_controls(super().format(record)), self.LIMIT)
        except Exception:  # noqa: BLE001 - a redaction failure must not print the raw text instead
            return f"{record.levelname} {record.name}: (log text withheld)"
        # Every further line is indented, so text inside a record cannot pass for a record of its own
        # (third review: a message carrying "\n<date> INFO ...: approved" forged a line).
        return text.replace("\n", "\n    ")


class _StderrHandler(logging.StreamHandler):
    """Writes to whatever sys.stderr is when a record is written, not when the handler was made."""

    @property
    def stream(self):  # type: ignore[override]
        return sys.stderr

    @stream.setter
    def stream(self, _value) -> None:
        pass


def install_log_gate(level: int | None = None) -> None:
    """Every log record the process writes goes out through GatedFormatter, on stderr. Without a
    handler, Python's last-resort one prints a warning's raw text - exception text included - so every
    CLI command and the MCP server install this first (third review: only `warden worker` did)."""
    root = logging.getLogger()
    if not any(isinstance(h.formatter, GatedFormatter) for h in root.handlers):
        handler = _StderrHandler()
        handler.setFormatter(GatedFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
    if level is not None:
        root.setLevel(level)


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
