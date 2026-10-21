"""The database's own error log reaches the evidence (2026-10-15): of its newest file's last lines, only ERROR, FATAL
and PANIC ones, as untrusted LOG lines - "password authentication failed for user ..." names a cause the applications'
logs only echo."""

from __future__ import annotations

from warden import aws_stack, evidence
from warden.models import Alert, Severity

LINES = [
    "2026-10-15 05:29:01 UTC::@:[1]:LOG:  checkpoint starting: time",
    '2026-10-15 05:29:02 UTC:10.0.0.9(5):warden_dev_app@shop:[7]:FATAL:  password authentication failed for user "warden_dev_app"',
    '2026-10-15 05:29:03 UTC:10.0.0.9(6):warden_dev_app@shop:[8]:ERROR:  relation "orders" does not exist',
    "2026-10-15 05:29:04 UTC::@:[1]:LOG:  checkpoint complete",
]
LOG = chr(10).join(LINES)


class _Rds:
    def describe_db_log_files(self, DBInstanceIdentifier, FileLastWritten):
        return {"DescribeDBLogFiles": [{"LogFileName": "error/old.log", "LastWritten": 1},
                                       {"LogFileName": "error/new.log", "LastWritten": 9}]}

    def download_db_log_file_portion(self, DBInstanceIdentifier, LogFileName, NumberOfLines):
        assert LogFileName == "error/new.log"
        assert NumberOfLines == aws_stack.DB_LOG_LINES
        return {"LogFileData": LOG}


def _alert():
    return Alert(alert_id="a", name="n", service="db", environment="dev", severity=Severity.high, summary="",
                 started_at="2026-10-15T05:30:00+00:00", labels={})


def test_only_the_newest_files_error_lines_are_kept_as_untrusted_log_lines():
    b = aws_stack.StackBackend.__new__(aws_stack.StackBackend)
    b._rds = _Rds()
    out = aws_stack._Out()
    b._db_log(out, _alert(), "warden-dev-aurora-instance-1")
    assert [ln.split(":[", 1)[1][:12] for ln in out.lines] == ["7]:FATAL:  p", "8]:ERROR:  r"]
    assert all(ln.startswith("LOG rds/warden-dev-aurora-instance-1 ") for ln in out.lines)
    assert all(evidence._kind(ln) in evidence.UNTRUSTED_KINDS for ln in out.lines)


def test_a_refused_log_read_is_said_and_the_rest_go_on():
    class _Denied(_Rds):
        def describe_db_log_files(self, **kw):
            raise PermissionError("AccessDenied")
    b = aws_stack.StackBackend.__new__(aws_stack.StackBackend)
    b._rds = _Denied()
    out = aws_stack._Out()
    b._db_log(out, _alert(), "x")
    assert len(out.lines) == 1
    assert out.lines[0].startswith("TOOL-PARTIAL aurora logs: ")
