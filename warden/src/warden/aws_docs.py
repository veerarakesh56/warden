"""AWS's own documentation for an error code the model may not know (G10-C6; owner decision 2026-10-10).

Held-out G9-F: novel kinds were missed for want of AWS knowledge, not evidence - a clock skew rejecting SigV4, an
AppConfig deployment AWS had already rolled back. WARDEN asks the AWS Knowledge MCP server (free, no sign-in, AWS's
docs and Knowledge Center) about at most MAX_CODES error codes the evidence holds, and shows the model what it says:
- what is SENT is closed: a code from the typed facts (an identifier such as `ResourceInitializationError`, never a
  log's words) and a service word from WARDEN's own table - no name, no account, no log text;
- what is KEPT is a page of docs.aws.amazon.com or repost.aws/knowledge-center only, cut to MAX_CHARS, on one line;
- it is reference, never evidence: no id a citation can name, scanned by the injection tripwire as outside text, and
  rendered between data markers. A failed lookup adds nothing - it is no read of the incident.
Off unless WARDEN_AWS_DOCS=on (the cloud runtime sets it): tests and replays make no call.
"""

from __future__ import annotations

import functools
import json
import os
import re
import urllib.request
from collections.abc import Callable
from typing import Any

ENDPOINT = os.environ.get("WARDEN_AWS_DOCS_URL", "https://knowledge-mcp.global.api.aws")
MAX_CODES = 2
MAX_CHARS = 700
TIMEOUT_S = 8.0
_HOSTS = ("https://docs.aws.amazon.com/", "https://repost.aws/knowledge-center/")
# A code from the facts (quarantine `aws=` / `code=`): an identifier, and one that names a failure.
_FACT_CODE = re.compile(r"(?:^|; )(?:aws|code)=([A-Z][A-Za-z0-9.]{2,60})(?=;| \(|$)")
_LINES = re.compile(r"[(]x(\d+): ")
_GENERIC = frozenset({"Error", "Exception", "RuntimeError", "ValueError", "TypeError", "KeyError"})
# Only codes AWS or the platform itself reports: an AWS SDK service exception (`...Exception`, how every AWS API names
# its errors) or one of these documented failure codes. An application's own error names (`TaxEngineError`,
# `IndexError`) found only generic Lambda pages in the held-out dry run (2026-10-10), and a signal found Spot.
_PLATFORM_CODES = frozenset({"ResourceInitializationError", "CannotPullContainerError", "CannotStartContainerError",
                             "OutOfMemoryError", "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull",
                             "FailedScheduling", "OOMKilled", "Evicted", "EndpointConnectionError",
                             "ConnectTimeoutError", "ReadTimeoutError", "NoCredentialsError"})
# The service word sent with a code, from the alarm's label keys - WARDEN's words, never a resource's name.
_SERVICE = (("ecs", "Amazon ECS"), ("eks", "Amazon EKS"), ("namespace", "Kubernetes"), ("lambda", "AWS Lambda"),
            ("aurora", "Amazon Aurora"), ("rds", "Amazon RDS"), ("dynamodb", "Amazon DynamoDB"), ("sqs", "Amazon SQS"),
            ("sns", "Amazon SNS"), ("eventbridge", "Amazon EventBridge"), ("apigw", "Amazon API Gateway"),
            ("alb", "Elastic Load Balancing"), ("load_balancer", "Elastic Load Balancing"), ("athena", "Amazon Athena"),
            ("kinesis", "Amazon Kinesis"), ("elasticache", "Amazon ElastiCache"), ("state_machine", "AWS Step Functions"),
            ("asg", "Amazon EC2 Auto Scaling"), ("s3", "Amazon S3"), ("efs", "Amazon EFS"), ("nat", "NAT gateway"))


def enabled() -> bool:
    return os.environ.get("WARDEN_AWS_DOCS", "off").strip().lower() == "on"


def codes(fact_texts: list[str]) -> list[str]:
    """The error codes the typed facts hold, most frequent first - never more than MAX_CODES."""
    seen: dict[str, int] = {}
    for text in fact_texts:
        lines = int(m.group(1)) if (m := _LINES.search(text)) else 1  # an F item's own count of its lines
        for code in _FACT_CODE.findall(text):
            if code not in _GENERIC and (code.endswith("Exception") or code in _PLATFORM_CODES):
                seen[code] = seen.get(code, 0) + lines
    return [c for c, _ in sorted(seen.items(), key=lambda kv: -kv[1])][:MAX_CODES]


def service_word(labels: dict[str, str]) -> str:
    keys = " ".join(sorted(labels))
    return next((word for key, word in _SERVICE if key in keys), "AWS")


def _rpc(method: str, params: dict, session: str | None, rid: int) -> tuple[str | None, dict]:
    body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if session:
        headers["Mcp-Session-Id"] = session
    if not ENDPOINT.startswith("https://"):
        raise ValueError("the AWS docs endpoint must be https")
    request = urllib.request.Request(ENDPOINT, data=body, headers=headers)  # nosec B310 - https, checked above
    with urllib.request.urlopen(request, timeout=TIMEOUT_S) as resp:  # nosec B310 - https, checked above
        text = resp.read(200_000).decode("utf-8", "replace")
        if "text/event-stream" in (resp.headers.get("Content-Type") or ""):
            text = next((line[5:].strip() for line in text.splitlines() if line.startswith("data:")), "{}")
        return resp.headers.get("Mcp-Session-Id") or session, json.loads(text)


def _search(phrase: str) -> list[dict[str, Any]]:
    session, _ = _rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "warden", "version": "1"}}, None, 1)
    _, res = _rpc("tools/call", {"name": "aws___search_documentation",
                                 "arguments": {"search_phrase": phrase, "limit": 3, "topics": ["troubleshooting"]}},
                  session, 2)
    content = ((res.get("result") or {}).get("content") or [{}])[0].get("text") or "{}"
    return ((json.loads(content).get("content") or {}).get("result")) or []


def _one_line(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f\u2028\u2029]", " ", text)).strip()


@functools.lru_cache(maxsize=256)
def _lookup_cached(phrase: str) -> str:
    return lookup(phrase)


def lookup(phrase: str, search: Callable[[str], list[dict[str, Any]]] | None = None) -> str:
    """The first result on an allowed AWS host, as one line: `<title> (<url>): <text>`. "" when there is none."""
    try:
        results = (search or _search)(phrase)
    except Exception:  # noqa: BLE001 - reference only: no answer adds nothing
        return ""
    for r in results:
        url = str(r.get("url") or "")
        if url.startswith(_HOSTS) and r.get("context"):
            line = f"{_one_line(str(r.get('title', '')))} ({url}): {_one_line(str(r['context']))}"
            return line[:MAX_CHARS]
    return ""


def references(labels: dict[str, str], fact_texts: list[str],
               search: Callable[[str], list[dict[str, Any]]] | None = None) -> list[str]:
    """What AWS's documentation says about the evidence's error codes - empty when off or when nothing matched."""
    if not enabled() and search is None:
        return []
    word = service_word(labels)
    out = []
    for code in codes(fact_texts):
        phrase = f"{word} {code}"
        found = lookup(phrase, search) if search is not None else _lookup_cached(phrase)
        if found:
            out.append(f"{code}: {found}")
    return out
