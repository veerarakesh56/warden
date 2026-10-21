"""Hidden warnings, evidence and incident lot (owner, 2026-10-17): a broad catch kept on a best-effort read now leaves
a record of what it caught - a PARTIAL line where the read has one, else a warning on the worker's log - never a
silent drop."""

from __future__ import annotations

import logging

from test_grafana_g10y import ENV, Fake
from test_grafana_g10y import _alert as _grafana_alert
from test_k8s_backend import FakeApps, FakeAutoscaling, FakeCore, _alert, _pod
from warden import aws_docs, grafana
from warden.k8s_backend import KubernetesBackend


def test_a_failed_aws_docs_lookup_adds_nothing_and_says_why(caplog):
    def broken(phrase):
        raise TimeoutError("slow")

    with caplog.at_level(logging.WARNING, logger="warden.evidence"):
        assert aws_docs.lookup("p", search=broken) == ""
    assert "the AWS documentation was not read (TimeoutError): no reference added" in caplog.text


def test_a_second_sources_failed_metrics_never_take_the_others_down_and_are_said(caplog):
    class Base:
        name = "stack"

        def metrics(self, alert):
            return {"errors": 3.0}

    class Broken(grafana.GrafanaReader):
        def metrics(self, alert):
            raise RuntimeError("down")

    both = grafana.WithSources(Base(), [Broken(env=ENV, get=Fake({}))])
    with caplog.at_level(logging.WARNING, logger="warden.evidence"):
        assert both.metrics(_grafana_alert()) == {"errors": 3.0}
    assert "grafana metrics not read (RuntimeError): the other sources' stand" in caplog.text


def test_unreadable_autoscalers_are_omitted_and_said(caplog):
    b = KubernetesBackend(core=FakeCore(pods=[_pod()]), apps=FakeApps(), autoscaling=FakeAutoscaling(raises=403))
    with caplog.at_level(logging.WARNING, logger="warden.evidence"):
        assert not any(k.startswith("hpa_") for k in b.metrics(_alert()))
    assert "autoscalers not read (_ApiErr): omitted" in caplog.text


class _UnreadableAudit:
    def entries(self, *a, **kw):
        raise OSError("the audit store is unreachable")


def test_an_unreadable_record_of_earlier_fixes_is_said_and_the_work_goes_on(caplog):
    from warden.activities import IncidentActivities, RemediationActivities

    with caplog.at_level(logging.WARNING, logger="warden.incident"):
        assert RemediationActivities(audit=_UnreadableAudit(), policy=None, platform=None)._own_fix_said("inc-1") == ""
        assert IncidentActivities(audit=_UnreadableAudit())._connected("inc-2", None) is None
    assert "earlier fixes not read for inc-1 (OSError): the request goes without them" in caplog.text
    assert "earlier fixes not read for inc-2 (OSError): nothing linked" in caplog.text
