"""Item 7b: the runtime module can send WARDEN's spans over OTLP/HTTP - off by default, the endpoint given as
configuration only (SSM tf/otlp_endpoint), HTTPS on 443 through the egress the workers already have, and the app
reading it only when it is turned on, with OpenTelemetry's own exporter (pyproject's `otlp` extra, in uv.lock)."""

from __future__ import annotations

import pathlib
import re

import pytest

from warden import observability as obs

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = ROOT / "infra" / "terraform" / "modules" / "warden-runtime"
OFFICIAL = "opentelemetry-exporter-otlp-proto-http"
ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"


def _variable(name: str) -> str:
    text = (MODULE / "variables.tf").read_text(encoding="utf-8")
    start = text.index(f'variable "{name}"')
    return text[start:text.index("\n}\n", start)]


class _Rule:
    """The variable's validation as Terraform applies it: the URL shape, and no /v1/traces at its end."""

    def __init__(self, block: str) -> None:
        shape, suffix = re.findall(r'can\(regex\("(.+?)", var\.otlp_endpoint\)\)', block)
        assert f'!can(regex("{suffix}", var.otlp_endpoint))' in block
        self.shape, self.suffix = re.compile(shape), re.compile(suffix)

    def fullmatch(self, url: str) -> bool:
        return bool(self.shape.fullmatch(url)) and not self.suffix.search(url)


def _endpoint_rule() -> _Rule:
    return _Rule(_variable("otlp_endpoint"))


def test_the_exporter_is_off_by_default_everywhere():
    assert re.search(r"default\s*=\s*false", _variable("otlp_exporter"))
    assert re.search(r'default\s*=\s*""', _variable("otlp_endpoint"))
    root = (ROOT / "infra" / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
    assert 'otlp_exporter = lookup(local.tf, "otlp_exporter", "false") == "true"' in root
    assert 'otlp_endpoint = lookup(local.tf, "otlp_endpoint", "")' in root


def test_turned_on_it_needs_an_endpoint():
    assert '!var.otlp_exporter || var.otlp_endpoint != ""' in _variable("otlp_exporter")


@pytest.mark.parametrize("url", ["https://otlp.example.test", "https://otlp.example.test/", "https://otlp.example.test:443",
                                 "https://collector.example.test/otlp", "https://a.example.test:443/v1/x/"])
def test_an_https_endpoint_on_443_is_accepted(url):
    assert _endpoint_rule().fullmatch(url)


@pytest.mark.parametrize("url", ["http://otlp.example.test", "https://otlp.example.test:4318",
                                 "https://user:pw@otlp.example.test", "https://otlp.example.test/?key=x",
                                 "https://otlp.example.test/#x", "https://OTLP.example.test", "otlp.example.test",
                                 "https://otlp.example.test/a b", "https://otlp.example.test/v1/traces",
                                 "https://otlp.example.test/otlp/v1/traces/"])
def test_any_other_endpoint_is_refused(url):
    assert not _endpoint_rule().fullmatch(url)


def test_every_zone_gets_the_endpoint_only_when_it_is_on():
    compute = (MODULE / "compute.tf").read_text(encoding="utf-8")
    assert "var.otlp_exporter ? { OTEL_EXPORTER_OTLP_ENDPOINT = var.otlp_endpoint } : {}" in compute
    assert compute.count(ENV) == 1
    module = "\n".join(p.read_text(encoding="utf-8") for p in sorted(MODULE.glob("*.tf")))
    assert "OTEL_EXPORTER_OTLP_HEADERS" not in module  # no credential travels as a plain environment variable


def test_no_new_way_out_is_opened_for_it():
    """HTTPS on 443 is the egress the workers already have: the option adds no port and no rule."""
    network = (MODULE / "network.tf").read_text(encoding="utf-8")
    assert "otlp" not in network.lower()
    assert "4317" not in network
    assert "4318" not in network


def test_the_image_carries_the_official_exporter_from_the_lockfile():
    docker = re.sub(r"\\\n\s*", "", (ROOT / "warden" / "Dockerfile.runtime").read_text(encoding="utf-8"))  # continuations joined
    assert "--extra otlp" in re.search(r"uv sync --locked --no-build --no-editable(.*)", docker).group(1)
    py = (ROOT / "warden" / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'^otlp = \["{OFFICIAL}>=[0-9.]+"\]$', py, re.MULTILINE)
    assert f'name = "{OFFICIAL}"' in (ROOT / "warden" / "uv.lock").read_text(encoding="utf-8")


def test_the_app_ships_spans_only_when_the_endpoint_is_set(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.delenv("WARDEN_TRACE_CONSOLE", raising=False)
    assert obs._build_exporter() is None
    monkeypatch.setenv(ENV, "https://otlp.example.test")
    assert obs._build_exporter() is not None
