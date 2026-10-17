"""Live, 2026-10-16 (fs-01): WARDEN made no rollback plan - "no single known-good to_version was read". The version to
go back to was the one that served the MOST in the lookback, refused unless known-good: the broken version 4 had served
3.5 erroring hours, the good version 3 two clean hours right up to the change, so 4 was taken and refused. The
version taken is now the one whose known-good stretch ended latest - the state just before the change."""

from __future__ import annotations

from datetime import timedelta

from test_aws_platform_g6 import FN, NOW

CHANGE = NOW
P = timedelta(minutes=5)


def _metrics(f, served):
    """served: version -> list of (start offset before the change, minutes, errors per period)."""
    def get_metric_data(MetricDataQueries, StartTime, EndTime, **kw):
        out = []
        for q in MetricDataQueries:
            dims = {d["Name"]: d["Value"] for d in q["MetricStat"]["Metric"]["Dimensions"]}
            v, metric = dims.get("ExecutedVersion"), q["MetricStat"]["Metric"]["MetricName"]
            stamps, values = [], []
            for before, minutes, errors in served.get(v, []):
                for i in range(minutes // 5):
                    stamps.append(CHANGE - before + i * P)
                    values.append(float(errors) if metric == "Errors" else 10.0)
            out.append({"Id": q["Id"], "StatusCode": "Complete", "Timestamps": stamps, "Values": values})
        return {"MetricDataResults": out}
    f.get_metric_data = get_metric_data


def test_the_last_known_good_version_is_taken_not_the_one_that_served_most(aws):
    f, p = aws
    _metrics(f, {"4": [(timedelta(hours=6), 210, 3)],      # 3.5 hours, erring every period
                 "3": [(timedelta(hours=2), 120, 0)]})     # 2 clean hours, up to the change
    assert p._served_before(FN, "live", ["3", "4"], CHANGE) == "3"


def test_of_two_known_good_versions_the_later_one_is_taken(aws):
    f, p = aws
    _metrics(f, {"2": [(timedelta(hours=6), 180, 0)], "3": [(timedelta(hours=2), 60, 0)]})
    assert p._served_before(FN, "live", ["2", "3"], CHANGE) == "3"


def test_none_known_good_is_no_version_and_a_short_clean_stretch_is_not_enough(aws):
    f, p = aws
    _metrics(f, {"4": [(timedelta(hours=6), 210, 3)], "3": [(timedelta(minutes=40), 25, 0)]})  # 25 min < KNOWN_GOOD
    assert p._served_before(FN, "live", ["3", "4"], CHANGE) == ""
