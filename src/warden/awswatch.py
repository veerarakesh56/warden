"""The AWS updates watch (owner item B6, 2026-10-17): once a day WARDEN reads what AWS announced - the What's New feed,
the AWS News Blog and AWS Health's scheduled changes for its account - and says, by fixed rules over its own
inventory, which items touch what it runs.

- **Sources.** Two RSS feeds, fetched in the read zone: exactly FEEDS, over HTTPS, on aws.amazon.com only, no redirect
  followed, size and time capped - the only egress this adds. AWS Health's scheduled changes come in through
  EventBridge to the alarm Lambda (frontdoor.tf), which records each one (`health_notice`) and starts nothing.
- **Untrusted text.** An item's words are outside text, as a log line is. They never leave the read zone (the Lambda,
  for a Health notice): each item is redacted, scanned by the injection tripwire (a flagged item is held back whole),
  and reduced to facts of fixed shapes - the services of WARDEN's own table it names, kinds from a closed list
  (end of support, security, price, availability), versions in the shapes AWS writes them (`python3.10`,
  `PostgreSQL 13`), dates, whether it names a Region, and its link when the link is AWS's own shape. No model reads
  any of it, and nothing it says can choose what WARDEN does: the rules below are plain code.
- **Inventory.** What WARDEN uses is not written here: `data/aws_inventory.json` is made from WARDEN's own Terraform
  and environments.yaml by `scripts/aws_inventory.py`, and a test fails when the two differ.
- **Rules** (`verdict`). An item about no service WARDEN uses is counted, never shown. An end-of-support or security
  item on one it uses is checked against the versions WARDEN runs: a version WARDEN runs is `affected`; versions it
  does not run, when WARDEN's own are all known, are `not affected`; anything it cannot tell - no version named, or
  a resource whose version is not pinned - is `check`. `affected` and `check` are each alarmed once, in the alerts
  channel (done means delivered: a failed post is made again the next day); every other kept item is in the daily
  digest only. Each run reads the last MAX_LOOKBACK and shows only what no delivered digest showed. A launch in other Regions only is dropped.
- **Where it goes.** The digest, at 09:00 in the display zone (environments.yaml: Asia/Kolkata, so 03:30 UTC), in
  the discussion channel; each alarm in the alerts channel - both from the per-environment maps, read as strictly as
  the incidents' (`settings.by_environment`): the nonprod environment's channel, as the watch is about WARDEN's own
  stack, or for a Health notice naming a watched resource, that resource's environment. A malformed map sends
  nothing and says so on the record.

WARDEN changes nothing here: there is no write to AWS, and no plan, fix or incident is started.
"""

from __future__ import annotations

import email.utils
import hashlib
import html
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from importlib import resources
from typing import Any
from xml.parsers import expat

from temporalio import activity

SCHEDULE_ID = "warden-aws-updates"
HEALTH_ID = "awswatch-health"  # the audit's correlation id for every Health notice the alarm Lambda records
FEEDS = {"whats-new": "https://aws.amazon.com/about-aws/whats-new/recent/feed/",
         "news-blog": "https://aws.amazon.com/blogs/aws/feed/"}
FEED_NAMES = {"whats-new": "What's New", "news-blog": "AWS News Blog", "health": "AWS Health"}
MAX_FEED = 5_000_000  # bytes; the What's New feed is about 100 items of a few hundred bytes each
MAX_ITEMS = 300  # per feed
MAX_FIELD = 20_000  # characters of one item's field
MAX_INTEREST = 15  # "of interest" lines in one digest; the rest are counted
DEFAULT_AT = "09:00"  # in the display zone
MAX_LOOKBACK = timedelta(days=7)
_TIMEOUT_S = 20.0
_AT = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")


class FeedError(RuntimeError):
    """A feed that could not be read: an HTTP status or an error's kind only, never an answer's text."""


def configured() -> bool:
    """On only when WARDEN_AWSWATCH=on: it is the one part of WARDEN that reads the public web."""
    return os.environ.get("WARDEN_AWSWATCH", "off").strip().lower() == "on"


def at() -> tuple[int, int]:
    """When the digest goes out, in the display zone: WARDEN_AWSWATCH_AT (HH:MM), 09:00 when not set."""
    raw = os.environ.get("WARDEN_AWSWATCH_AT", "").strip() or DEFAULT_AT
    m = _AT.fullmatch(raw)
    if not m:
        raise ValueError(f"WARDEN_AWSWATCH_AT must be HH:MM, not {raw!r}")
    return int(m.group(1)), int(m.group(2))


# ------------------------------------------------------------------ WARDEN's words: services and versions


@dataclass(frozen=True)
class Service:
    name: str  # as a person reads it
    prefixes: tuple[str, ...]  # Terraform resource types that use it (scripts/aws_inventory.py)
    words: tuple[str, ...]  # how AWS's text names it (case as written)
    slugs: tuple[str, ...] = ()  # What's New `general:products/<slug>` categories
    health: str = ""  # AWS Health's `service` code


SERVICES: dict[str, Service] = {
    "lambda": Service("AWS Lambda", ("aws_lambda_",), ("AWS Lambda", "Lambda"), ("aws-lambda",), "LAMBDA"),
    "ecs": Service("Amazon ECS", ("aws_ecs_",), ("Amazon ECS", "Elastic Container Service", "Fargate"),
                   ("amazon-ecs", "aws-fargate"), "ECS"),
    "ecr": Service("Amazon ECR", ("aws_ecr_",), ("Amazon ECR", "Elastic Container Registry"), ("amazon-ecr",), "ECR"),
    "eks": Service("Amazon EKS", ("aws_eks_",), ("Amazon EKS", "Elastic Kubernetes Service"), ("amazon-eks",), "EKS"),
    "rds": Service("Amazon RDS", ("aws_db_",), ("Amazon RDS", "RDS for PostgreSQL"), ("amazon-rds",), "RDS"),
    "aurora": Service("Amazon Aurora", ("aws_rds_cluster",), ("Aurora",), ("amazon-aurora",), "RDS"),
    "elasticache": Service("Amazon ElastiCache", ("aws_elasticache_",), ("ElastiCache",), ("amazon-elasticache",),
                           "ELASTICACHE"),
    "dynamodb": Service("Amazon DynamoDB", ("aws_dynamodb_",), ("DynamoDB",), ("amazon-dynamodb",), "DYNAMODB"),
    "s3": Service("Amazon S3", ("aws_s3_",), ("Amazon S3", "S3 Object Lock"), ("amazon-s3",), "S3"),
    "sqs": Service("Amazon SQS", ("aws_sqs_",), ("Amazon SQS", "Simple Queue Service"), ("amazon-sqs",), "SQS"),
    "sns": Service("Amazon SNS", ("aws_sns_",), ("Amazon SNS", "Simple Notification Service"), ("amazon-sns",), "SNS"),
    "eventbridge": Service("Amazon EventBridge", ("aws_cloudwatch_event_",), ("EventBridge",), ("amazon-eventbridge",),
                           "EVENTS"),
    "cloudwatch": Service("Amazon CloudWatch", ("aws_cloudwatch_metric_alarm", "aws_cloudwatch_log_"),
                          ("CloudWatch",), ("amazon-cloudwatch",), "CLOUDWATCH"),
    "apigateway": Service("Amazon API Gateway", ("aws_apigatewayv2_", "aws_api_gateway_"), ("API Gateway",),
                          ("amazon-api-gateway",), "APIGATEWAY"),
    "elb": Service("Elastic Load Balancing", ("aws_lb",), ("Elastic Load Balancing", "Application Load Balancer"),
                   ("elastic-load-balancing",), "ELASTICLOADBALANCING"),
    "vpc": Service("Amazon VPC", ("aws_vpc", "aws_subnet", "aws_nat_gateway", "aws_internet_gateway", "aws_route",
                                  "aws_eip", "aws_security_group"),
                   ("Amazon VPC", "NAT gateway", "security group"), ("amazon-vpc",), "VPC"),
    "ec2": Service("Amazon EC2", ("aws_launch_template", "aws_instance", "aws_ec2_"), ("Amazon EC2",),
                   ("amazon-ec2",), "EC2"),
    "iam": Service("AWS IAM", ("aws_iam_",), ("AWS IAM", "Identity and Access Management", "IAM role"),
                   ("aws-iam",), "IAM"),
    "kms": Service("AWS KMS", ("aws_kms_",), ("AWS KMS", "Key Management Service"),
                   ("aws-key-management-service",), "KMS"),
    "secretsmanager": Service("AWS Secrets Manager", ("aws_secretsmanager_",), ("Secrets Manager",),
                              ("aws-secrets-manager",), "SECRETSMANAGER"),
    "ssm": Service("AWS Systems Manager", ("aws_ssm_",), ("Systems Manager", "Parameter Store"),
                   ("aws-systems-manager",), "SSM"),
    "cloudtrail": Service("AWS CloudTrail", ("aws_cloudtrail",), ("CloudTrail",), ("aws-cloudtrail",), "CLOUDTRAIL"),
    "budgets": Service("AWS Budgets", ("aws_budgets_",), ("AWS Budgets",), ("aws-budgets",), "BUDGETS"),
}

# A version family: the service it belongs to, and the patterns that find it in AWS's text, each made into the one
# spelling the inventory uses (`Python 3.10` and `python3.10` are both `python3.10`).
FAMILY_SERVICE = {"runtime": ("lambda",), "postgresql": ("rds", "aurora"), "redis": ("elasticache",),
                  "kubernetes": ("eks",)}
FAMILY_NAME = {"runtime": "Lambda runtimes", "postgresql": "PostgreSQL", "redis": "Redis", "kubernetes": "Kubernetes"}
_VERSIONS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("runtime", re.compile(r"\bpython ?3\.(\d{1,2})\b", re.IGNORECASE), "python3.{}"),
    ("runtime", re.compile(r"\bnode(?:\.?js)? ?(\d{2})(?:\.x)?\b", re.IGNORECASE), "nodejs{}.x"),
    ("runtime", re.compile(r"\bjava ?(\d{1,2})\b", re.IGNORECASE), "java{}"),
    ("runtime", re.compile(r"\bruby ?(3\.\d)\b", re.IGNORECASE), "ruby{}"),
    ("runtime", re.compile(r"(?:\.NET|\bdotnet) ?(\d{1,2})\b", re.IGNORECASE), "dotnet{}"),
    ("runtime", re.compile(r"\bprovided\.(al2(?:023)?)\b"), "provided.{}"),
    ("postgresql", re.compile(r"\bPostgreSQL (?:version )?(\d{1,2})(?:\.\d{1,2})?\b"), "{}"),
    ("redis", re.compile(r"\bRedis(?: OSS)? (?:version )?(\d)(?:\.\d{1,2})?\b"), "{}"),
    ("kubernetes", re.compile(r"\b(?:Kubernetes|EKS)(?: version)? (1\.\d{2})\b"), "{}"),
)
# The shapes of a Lambda runtime identifier, for scripts/aws_inventory.py.
RUNTIME_ID = re.compile(r"python3\.\d{1,2}|nodejs\d{2}\.x|java\d{1,2}|ruby3\.\d|dotnet\d{1,2}|provided(?:\.al2(?:023)?)?")

# Kinds, from a closed list. Order is precedence: the first that fits is the item's kind.
LIFECYCLE, SECURITY, PRICE, AVAILABILITY, NEWS = "end of support", "security", "price", "availability", "news"
_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (LIFECYCLE, re.compile(r"deprecat|end[ -]of[ -](?:standard )?(?:support|life)|\bEOL\b|extended support|"
                           r"\bretir(?:e|es|ed|ing|ement)\b|\bsunset|discontinu|no longer (?:be )?(?:available|supported)|"
                           r"action required|required action|must (?:upgrade|migrate)|breaking change",
                           re.IGNORECASE)),
    (SECURITY, re.compile(r"security bulletin|vulnerabilit|\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    (PRICE, re.compile(r"\bpric(?:e|es|ing)\b", re.IGNORECASE)),
    (AVAILABILITY, re.compile(r"now available in|available in (?:the )?(?:additional|more|new)|expands? to", re.IGNORECASE)),
)
ALARMED_KINDS = (LIFECYCLE, SECURITY)
# A Region as AWS's text names one: "Asia Pacific (Hyderabad)", "Europe (Frankfurt)".
_ANY_REGION = re.compile(r"\b(?:US East|US West|Asia Pacific|Europe|Canada|Canada West|South America|Middle East|"
                         r"Africa|Israel|Mexico|AWS GovCloud \(US[^)]{0,10}\)|China) \(")
_MONTHS = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December")
_DATE_WORDS = re.compile(r"\b(" + "|".join(_MONTHS) + r") (\d{1,2}), (20\d\d)\b|\b(\d{1,2}) (" + "|".join(_MONTHS)
                         + r") (20\d\d)\b")
_DATE_ISO = re.compile(r"\b(20\d\d)-(\d\d)-(\d\d)\b")
_TAG = re.compile(r"<[^<>]*>")
_SLUG = re.compile(r"general:products/([a-z0-9-]{1,80})")
_LINK = re.compile(r"https://aws\.amazon\.com/(?:about-aws/whats-new/20\d\d/\d\d|blogs/aws)/[A-Za-z0-9-]{1,160}/?")
# "Upgrade to Python 3.13", "migrate your functions to Node.js 22": the version AWS points to, not the one it retires.
_TOWARD = re.compile(r"\b(?:upgrad|migrat|mov|switch|updat)\w*\b", re.IGNORECASE)
_TO = re.compile(r"\bto\b[^.;:]{0,80}")
_HEALTH_CODE = re.compile(r"AWS_[A-Z0-9_]{3,120}")
_HEALTH_SERVICE = re.compile(r"[A-Z0-9_]{2,40}")
MAX_DATES = 3


def _words_re(words: tuple[str, ...]) -> re.Pattern[str]:
    return re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(w) for w in words) + r")(?![\w-])")


_SERVICE_WORDS = {key: _words_re(s.words) for key, s in SERVICES.items()}
_SLUG_SERVICE = {slug: key for key, s in SERVICES.items() for slug in s.slugs}
_HEALTH_SERVICES = {s.health: key for key, s in SERVICES.items() if s.health}


# ------------------------------------------------------------------ the inventory


def inventory() -> dict[str, Any]:
    """WARDEN's own AWS inventory, made from its Terraform by scripts/aws_inventory.py (never edited by hand)."""
    return json.loads(resources.files("warden.data").joinpath("aws_inventory.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ reading the feeds (read zone)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a moved feed is an error to read, never a host to follow


def fetch(url: str, *, opener: Any = None) -> bytes:
    """One of FEEDS, as bytes. Any other URL is refused before anything is sent."""
    if url not in FEEDS.values():
        raise ValueError("only WARDEN's listed AWS feeds are read")
    req = urllib.request.Request(url, headers={"User-Agent": "warden-awswatch", "Accept": "application/rss+xml"},
                                 method="GET")
    open_ = opener or urllib.request.build_opener(_NoRedirect).open
    try:
        with open_(req, timeout=_TIMEOUT_S) as resp:
            body = resp.read(MAX_FEED + 1)
    except urllib.error.HTTPError as exc:
        raise FeedError(f"HTTP {exc.code}") from None
    except OSError as exc:  # URLError and TimeoutError are OSErrors
        raise FeedError(type(exc).__name__) from None
    if len(body) > MAX_FEED:
        raise FeedError("answer too large")
    return body


_FIELDS = frozenset({"title", "link", "guid", "description", "pubDate", "category"})


class _Rss:
    """RSS 2.0 items as {field: text}, `category` a list. A document type or an entity declaration is refused: no
    entity is ever expanded, so neither an external file nor a "billion laughs" can be (defusedxml's rule)."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.item: dict[str, Any] | None = None
        self.field = ""
        self.text: list[str] = []

    @staticmethod
    def refuse(*_: Any) -> None:
        raise FeedError("a document type or entity declaration")

    def start(self, name: str, _attrs: dict[str, str]) -> None:
        if name == "item":
            self.item, self.field = {"category": []}, ""
        elif self.item is not None and name in _FIELDS:
            self.field, self.text = name, []

    def data(self, text: str) -> None:
        if self.field and sum(map(len, self.text)) < MAX_FIELD:
            self.text.append(text)

    def end(self, name: str) -> None:
        if name == "item" and self.item is not None:
            if len(self.items) < MAX_ITEMS:
                self.items.append(self.item)
            self.item = None
        elif self.item is not None and name == self.field:
            value = "".join(self.text)[:MAX_FIELD].strip()
            if name == "category":
                self.item["category"].append(value)
            else:
                self.item[name] = value
            self.field = ""


def parse(body: bytes) -> list[dict[str, Any]]:
    """The items of an RSS 2.0 document; FeedError for anything that is not one."""
    rss = _Rss()
    p = expat.ParserCreate()
    p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    p.StartDoctypeDeclHandler = rss.refuse
    p.EntityDeclHandler = rss.refuse
    p.ExternalEntityRefHandler = rss.refuse
    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = rss.start, rss.end, rss.data
    try:
        p.Parse(body, True)
    except expat.ExpatError as exc:
        raise FeedError(f"not XML ({expat.ErrorString(exc.code)})") from None
    return rss.items


def plain(fragment: str) -> str:
    """HTML (an item's description) as one line of plain text."""
    return " ".join(html.unescape(_TAG.sub(" ", fragment)).split())


def _published(value: str) -> datetime | None:
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            when = datetime.fromisoformat(value)
        except ValueError:
            return None
    return when.astimezone(UTC) if when.tzinfo else None


def dates(text: str) -> list[str]:
    """The calendar dates a text names, as YYYY-MM-DD, at most MAX_DATES, in order."""
    out: list[str] = []
    for m in _DATE_WORDS.finditer(text):
        month, day, year = (m.group(1), m.group(2), m.group(3)) if m.group(1) else (m.group(5), m.group(4), m.group(6))
        out.append(f"{year}-{_MONTHS.index(month) + 1:02d}-{int(day):02d}")
    out += [f"{a}-{b}-{c}" for a, b, c in _DATE_ISO.findall(text)]
    valid = []
    for d in dict.fromkeys(out):
        try:
            date.fromisoformat(d)
        except ValueError:
            continue
        valid.append(d)
    return valid[:MAX_DATES]


def without_targets(text: str) -> str:
    """The text less what follows "upgrade ... to", "migrate ... to" (within 60 characters): the versions AWS
    recommends moving to are not the ones an end of support is about."""
    out, start = [], 0
    for m in _TOWARD.finditer(text):
        if m.start() < start:
            continue
        to = _TO.search(text, m.end(), m.end() + 60 + 80)
        if to and to.start() - m.end() <= 60:
            out.append(text[start:to.start()])
            start = to.end()
    return " ".join([*out, text[start:]])


def versions(text: str) -> dict[str, list[str]]:
    """{family: [versions]} a text names, each in the inventory's spelling - not those it says to move to."""
    text = without_targets(text)
    out: dict[str, list[str]] = {}
    for family, rx, shape in _VERSIONS:
        for m in rx.finditer(text):
            v = shape.format(m.group(1).lower())
            if v not in out.setdefault(family, []):
                out[family].append(v)
    return {k: sorted(v) for k, v in out.items() if v}


def services(text: str, categories: list[str] = (), health: str = "") -> list[str]:
    """The keys of SERVICES a text, its What's New categories or a Health `service` code name."""
    found = {key for key, rx in _SERVICE_WORDS.items() if rx.search(text)}
    found |= {_SLUG_SERVICE[s] for c in categories for s in _SLUG.findall(c) if s in _SLUG_SERVICE}
    if health in _HEALTH_SERVICES:
        found.add(_HEALTH_SERVICES[health])
    return sorted(found)


def facts(text: str, *, categories: list[str] = (), health: str = "", regions: list[str] = ()) -> dict[str, Any]:
    """An item's text - already redacted - as facts of fixed shapes; nothing of the text itself. `regions`: AWS's
    names of WARDEN's Regions."""
    ours = [r for r in regions if r in text]
    return {"services": services(text, categories, health),
            "kind": next((kind for kind, rx in _KINDS if rx.search(text)), NEWS),
            "versions": versions(text), "dates": dates(text),
            "regions_named": bool(_ANY_REGION.search(text)), "our_region": bool(ours)}


def link(value: str) -> str:
    """The item's link when it is AWS's own shape for one, else ""."""
    from .evidence import STEER

    value = value.strip()
    return value if _LINK.fullmatch(value) and not STEER.search(value.replace("-", " ")) else ""


def _item_id(feed: str, item: dict[str, Any]) -> str:
    key = item.get("guid") or item.get("link") or item.get("title") or ""
    return hashlib.sha256(f"{feed}\n{key}".encode()).hexdigest()[:16]


def _recent_texts(feed: str, items: list[dict[str, Any]],
                  since: datetime) -> dict[str, tuple[str, dict[str, Any], datetime]]:
    """{item id: (its redacted text, the item, when it was published)} for the items published since `since`."""
    from .redaction import redact

    texts: dict[str, tuple[str, dict[str, Any], datetime]] = {}
    for item in items:
        when = _published(str(item.get("pubDate") or ""))
        if when is None or when < since:
            continue
        words = " ".join([plain(str(item.get("title") or "")), plain(str(item.get("description") or "")),
                          *(plain(c) for c in item.get("category") or [])])
        texts[_item_id(feed, item)] = (redact(words).text, item, when)
    return texts


def reduce(feed: str, items: list[dict[str, Any]], *, since: datetime, regions: list[str],
           classify: Any = None) -> tuple[list[dict[str, Any]], str]:
    """(fact rows, tripwire status) for one feed's items published since `since`: each redacted, scanned and reduced.
    A row the tripwire flags keeps only its id, feed, time and link: `held`. FeedError when the tripwire is required
    and could not run."""
    from . import tripwire

    texts = _recent_texts(feed, items, since)
    status, scores = tripwire.scan({}, classify, outside={k: t for k, (t, _, _) in texts.items()})
    if tripwire.mode() == "required" and not tripwire.ran(status):
        # Fail closed, once for the feed: no item's facts are kept, and the digest says the feed was not read. The
        # next day's run reads the same window again (MAX_LOOKBACK), so nothing is lost while the detector is down.
        raise FeedError(f"the injection detector did not run: {status}")
    flagged = set(scores)
    rows = []
    for key, (text, item, when) in texts.items():
        row = {"id": key, "feed": feed, "published": when.isoformat(), "link": link(str(item.get("link") or ""))}
        if key in flagged:
            row["held"] = "the injection detector flagged it"
        else:
            row.update(facts(text, categories=list(item.get("category") or []), regions=regions))
        rows.append(row)
    return rows, status


# ------------------------------------------------------------------ AWS Health's scheduled changes (alarm Lambda)


def _health_time(value: Any) -> str:
    when = _published(str(value or ""))
    return when.isoformat() if when else ""


def _entities(detail: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(every affected entity's name, the watched environments' among them, sorted)."""
    from .environments import env_of_name
    from .models import NAME_PATTERN

    entities = [e for e in detail.get("affectedEntities") or [] if isinstance(e, dict)]
    names = [re.split(r"[/:]", str(e.get("entityValue") or ""))[-1] for e in entities]
    return names, sorted({n for n in names if n and re.match(NAME_PATTERN, n) and env_of_name(n)})


def _description(detail: dict[str, Any]) -> str:
    return " ".join(str(d.get("latestDescription") or "") for d in detail.get("eventDescription") or []
                    if isinstance(d, dict))[:MAX_FIELD]


def health_notice(event: dict[str, Any]) -> dict[str, Any] | None:
    """An AWS Health scheduled change as a fact row, or None for any other event. AWS's own notice - a maintenance,
    a planned lifecycle event such as a runtime's end of support - is no incident: the row is recorded and the
    next digest weighs it. The affected entities are kept by name only when the name is a watched environment's
    (`warden-<env>-...`); the rest are counted. The shape is AWS's "AWS Health events Amazon EventBridge schema"."""
    if event.get("source") != "aws.health" or event.get("detail-type") != "AWS Health Event":
        return None
    detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
    code, service = str(detail.get("eventTypeCode") or ""), str(detail.get("service") or "")
    if (detail.get("eventTypeCategory") != "scheduledChange" or not _HEALTH_CODE.fullmatch(code)
            or not _HEALTH_SERVICE.fullmatch(service)):
        return None
    from .environments import env_of_name
    from .redaction import redact

    names, ours = _entities(detail)
    row = {"id": hashlib.sha256(str(detail.get("eventArn") or code).encode()).hexdigest()[:16], "feed": "health",
           "published": _health_time(event.get("time")) or datetime.now(UTC).isoformat(), "link": "",
           "code": code, "status": str(detail.get("statusCode") or "")[:20],
           "scope": str(detail.get("eventScopeCode") or "")[:20], "start": _health_time(detail.get("startTime")),
           "end": _health_time(detail.get("endTime")), "ours": ours[:20],
           "environment": (env_of_name(ours[0]) or "") if ours else "", "others": len(names) - len(ours)}
    row.update(facts(redact(plain(_description(detail))).text, health=service, regions=inventory()["regions"]))
    return row


# ------------------------------------------------------------------ the rules (core zone)


AFFECTED, CHECK, NOT_AFFECTED, INTEREST = "affected", "check", "not affected", "of interest"


def _version_verdict(item: dict[str, Any], used: set[str], inv: dict[str, Any]) -> tuple[str, str]:
    """For an end-of-support or security item on a service WARDEN uses: its versions against WARDEN's."""
    named = {f: v for f, v in (item.get("versions") or {}).items()
             if f in FAMILY_SERVICE and used & set(FAMILY_SERVICE[f])}
    if not named:
        return CHECK, "it names no version WARDEN can compare with its own"
    found: list[str] = []
    for family, said in named.items():
        mine = inv["versions"].get(family) or {"known": [], "unknown": True}
        hit = sorted(set(said) & set(mine["known"]))
        if hit:
            return AFFECTED, f"WARDEN runs {', '.join(hit)}"
        if mine["unknown"]:
            return CHECK, f"a {FAMILY_NAME[family]} version WARDEN uses is not pinned in its Terraform"
        found.append(f"WARDEN's {FAMILY_NAME[family]}: {', '.join(mine['known']) or 'none'}")
    return NOT_AFFECTED, "; ".join(found)


def _health_verdict(item: dict[str, Any]) -> tuple[str, str] | None:
    if item.get("status") == "closed":
        return "", "AWS closed it"
    if item.get("ours"):
        return AFFECTED, f"it names WARDEN's {', '.join(item['ours'][:5])}"
    if item.get("scope") == "ACCOUNT_SPECIFIC" and item.get("others"):
        return CHECK, f"it names {item['others']} resource(s) in WARDEN's account"
    return None


def verdict(item: dict[str, Any], inv: dict[str, Any]) -> tuple[str, str]:
    """(verdict, why) for one fact row: "" when it is about nothing WARDEN uses (counted, not shown)."""
    if item.get("held"):
        return CHECK, "held back unread: the injection detector flagged its text"
    if item.get("feed") == "health" and (said := _health_verdict(item)) is not None:
        return said
    used = set(item.get("services") or []) & set(inv["services"])
    if not used:
        return "", "no service WARDEN uses"
    if item.get("kind") in ALARMED_KINDS:
        return _version_verdict(item, used, inv)
    if item.get("regions_named") and not item.get("our_region"):
        return "", "only Regions WARDEN does not run in"
    return INTEREST, ""


# ------------------------------------------------------------------ the digest and the alarms


def _when(iso: str) -> str:
    from .environments import both_times

    try:
        return both_times(datetime.fromisoformat(iso), seconds=False)
    except ValueError:
        return "time unknown"


def line(item: dict[str, Any], said: str, why: str) -> str:
    """One item as one line of facts - never its words."""
    parts = [f"{FEED_NAMES.get(item['feed'], item['feed'])}, {_when(item['published'])}"]
    if item.get("held"):
        parts.append("held back")
    else:
        parts.append(item.get("code") or item.get("kind") or NEWS)
        parts.append(", ".join(SERVICES[s].name for s in item.get("services") or [] if s in SERVICES) or "no service")
        parts += [f"{FAMILY_NAME[f]} {', '.join(v)}" for f, v in sorted((item.get("versions") or {}).items())
                  if f in FAMILY_NAME]
        if item.get("dates"):
            parts.append(f"dates named {', '.join(item['dates'])}")
        if item.get("start"):
            parts.append(f"from {_when(item['start'])}")
    out = " · ".join(parts) + (f" → *{said}*" if said else "") + (f": {why}" if why else "")
    return out + (f" · `{item['link'].removeprefix('https://')}`" if item.get("link") else "")


def _inventory_line(inv: dict[str, Any]) -> str:
    def fam(f: str) -> str:
        v = inv["versions"].get(f) or {"known": [], "unknown": True}
        return f"{FAMILY_NAME[f]} {', '.join(v['known']) or '-'}" + (" (one not pinned)" if v["unknown"] else "")

    regions = ", ".join(inv["regions"])
    return (f"Checked against WARDEN's own inventory (its Terraform): {len(inv['services'])} services; "
            f"{'; '.join(fam(f) for f in FAMILY_NAME)}; Regions {regions}.")


_TITLES = {AFFECTED: "Affects WARDEN - a person acts", CHECK: "A person checks", NOT_AFFECTED: "Not affected",
           INTEREST: "Of interest"}


def _judged(rows: list[dict[str, Any]],
            inv: dict[str, Any]) -> tuple[dict[str, list[str]], list[dict[str, Any]], int]:
    """(the digest's lines by verdict, the rows to alarm, how many are about nothing WARDEN uses), newest first."""
    groups: dict[str, list[str]] = {AFFECTED: [], CHECK: [], NOT_AFFECTED: [], INTEREST: []}
    alarms, skipped = [], 0
    for row in sorted(rows, key=lambda r: r["published"], reverse=True):
        said, why = verdict(row, inv)
        if not said:
            skipped += 1
            continue
        groups[said].append(line(row, said, why))
        if said in (AFFECTED, CHECK):
            alarms.append({**row, "verdict": said, "why": why})
    return groups, alarms, skipped


def _section(key: str, lines: list[str], digest_id: str) -> list[str]:
    if not lines:
        return []
    shown = lines[:MAX_INTEREST] if key == INTEREST else lines
    more = [f"• and {len(lines) - len(shown)} more, on the record ({digest_id})"] if len(lines) > len(shown) else []
    return ["", f"*{_TITLES[key]}* ({len(lines)})", *(f"• {s}" for s in shown), *more]


def digest(digest_id: str, since: datetime, now: datetime, rows: list[dict[str, Any]], unread: list[str],
           inv: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """(the digest's text, the rows to alarm): every row judged by `verdict`."""
    groups, alarms, skipped = _judged(rows, inv)
    counts = {f: sum(1 for r in rows if r["feed"] == f) for f in FEED_NAMES}
    out = [f"*AWS updates for WARDEN* - {_when(now.isoformat())}, new items since {_when(since.isoformat())}",
           "Read: " + ", ".join(f"{FEED_NAMES[f]} {n}" for f, n in counts.items()) + "."]
    if unread:
        out.append(f"Not read: {'; '.join(unread)}.")
    out.append(_inventory_line(inv))
    for key, lines in groups.items():
        out += _section(key, lines, digest_id)
    if not any(groups.values()):
        out += ["", "Nothing new about what WARDEN uses."]
    out += ["", (f"About nothing WARDEN uses: {skipped}. AWS's words are not shown: they are outside text, reduced "
                 "to these facts. Read an item on AWS's site.")]
    return "\n".join(out), alarms


def alarm_text(row: dict[str, Any]) -> str:
    head = "AWS update affects WARDEN" if row["verdict"] == AFFECTED else "AWS update: a person checks"
    return "\n".join([f"*{head}*", line(row, row["verdict"], row["why"]),
                      ("Nothing was changed. Next: the owner of the named service reads AWS's notice and plans "
                       "the change; WARDEN says this once.")])


# ------------------------------------------------------------------ where it goes


def channel(per_env: str, single: str, environment: str = "") -> str:
    """The channel for `environment` (or, with none, the nonprod one) from the strict map `per_env` - a malformed
    map raises ValueError, never a guess - else the one channel setting; "" when neither names one."""
    from .environments import default_environment_policies
    from .settings import by_environment

    if pairs := by_environment(per_env):
        if environment:
            return pairs.get(environment, "")
        policies = default_environment_policies()
        nonprod = sorted(n for n in policies.known_environments if policies.for_env(n).tier == "nonprod")
        return next((pairs[n] for n in nonprod if pairs.get(n)), "")
    return os.environ.get(single, "").strip()


def _run_id() -> str:
    try:
        return activity.info().workflow_run_id
    except RuntimeError:
        return "direct"


def _at(digest_id: str) -> datetime:
    return datetime.strptime(digest_id.removeprefix("awswatch-"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


class AwsWatchActivities:
    """The watch's steps, each in its zone: the feeds read and reduced in read, the rules and the record in core, the
    posts in notify. `opener` fetches (tests give a fake); `classify` is the tripwire's classifier."""

    def __init__(self, *, audit: Any, opener: Any = None, classify: Any = None) -> None:
        self.audit, self.opener, self.classify = audit, opener, classify

    def _sent(self) -> set[str]:
        """What the notify step delivered: "digest" posts by their digest id, alarms by their item id."""
        return {e["correlation_id"] if e["body"].get("what") == "digest" else str(e["body"].get("what"))
                for e in self.audit.entries(kinds=("awswatch.post",)) if e["body"].get("result") == "sent"}

    def _shown(self, sent: set[str]) -> set[str]:
        """The ids of the items a delivered digest already showed."""
        return {r["id"] for e in self.audit.entries(kinds=("awswatch.digest",)) if e["correlation_id"] in sent
                for r in e["body"].get("rows") or []}

    @activity.defn
    def awswatch_read(self, digest_id: str) -> dict[str, Any]:
        """Read zone: both feeds' items of the last MAX_LOOKBACK, as fact rows - the same window every day, so a feed
        that could not be read is read again tomorrow; core leaves out what a delivered digest already showed.
        Nothing of an item's text leaves this step."""
        since, regions = _at(digest_id) - MAX_LOOKBACK, inventory()["regions"]
        snap: dict[str, Any] = {"since": since.isoformat(), "rows": [], "unread": [], "tripwire": []}
        for feed, url in FEEDS.items():
            try:
                rows, status = reduce(feed, parse(fetch(url, opener=self.opener)), since=since, regions=regions,
                                      classify=self.classify)
            except FeedError as exc:
                snap["unread"].append(f"{FEED_NAMES[feed]} ({exc})")
                continue
            snap["rows"] += rows
            snap["tripwire"].append(f"{feed}: {status}")
        self.audit.append(digest_id, "awswatch.read", {"run_id": _run_id(), "since": snap["since"],
                                                       "rows": len(snap["rows"]), "unread": snap["unread"],
                                                       "tripwire": snap["tripwire"]})
        return snap

    @activity.defn
    def awswatch_review(self, digest_id: str, snap: dict[str, Any]) -> dict[str, Any]:
        """Core zone: every row and every recorded Health notice judged; the digest of what no delivered digest showed
        yet; an alarm for each affected or to-check item whose alarm was not delivered yet. An alarm is done only once
        notify delivered it (`awswatch.post` "sent"): one that failed is made again the next day."""
        now, since = _at(digest_id), datetime.fromisoformat(snap["since"])
        latest: dict[str, dict[str, Any]] = {}
        for e in self.audit.entries(HEALTH_ID, kinds=("awswatch.health",)):
            latest[e["body"]["id"]] = e["body"]  # an updated notice: its latest row
        rows = list(snap.get("rows") or []) + list(latest.values())
        inv, sent = inventory(), self._sent()
        shown = self._shown(sent)
        fresh = [r for r in rows if r["id"] not in shown]
        text, _ = digest(digest_id, since, now, fresh, list(snap.get("unread") or []), inv)
        new = [a for a in _judged(rows, inv)[1] if a["id"] not in sent]
        for a in new:
            self.audit.append(digest_id, "awswatch.alarm", {"run_id": _run_id(), "id": a["id"], "feed": a["feed"],
                                                            "verdict": a["verdict"], "why": a["why"]})
        self.audit.append(digest_id, "awswatch.digest", {
            "run_id": _run_id(), "rows": [{"id": r["id"], "feed": r["feed"], "verdict": verdict(r, inv)[0]}
                                          for r in fresh],
            "alarms": [a["id"] for a in new], "sha256": hashlib.sha256(text.encode()).hexdigest()})
        return {"digest": text, "alarms": [{"id": a["id"], "environment": a.get("environment", ""),
                                            "text": alarm_text(a)} for a in new]}

    @staticmethod
    def _post_one(key: str, text: str, setting: str, environment: str = "") -> str:
        """One text to its channel: "sent", or "not sent: <why>"."""
        from .chatops import SlackBotSink, notify
        from .reporting import Report

        token = os.environ.get("WARDEN_SLACK_BOT_TOKEN", "").strip()
        try:
            where = channel(setting + "S", setting, environment)
        except ValueError:  # the worker refuses to start on a malformed map (cli.py); never sent to a guess
            return f"not sent: {setting}S is malformed"
        if not token or not where:
            return f"not sent: no channel ({setting}S / {setting}) or no bot token"
        [sent] = notify(Report(markdown=text, data={"alert": {"id": key}}, promotion=()),
                        sinks=[SlackBotSink(token, where, live=os.environ.get("WARDEN_CHATOPS_LIVE") == "1")])
        return "sent" if sent.delivered else "not sent: " + sent.detail[:200]

    @activity.defn
    def awswatch_post(self, digest_id: str, made: dict[str, Any]) -> dict[str, Any]:
        """Notify zone: the digest in the discussion channel, each alarm in the alerts channel - through the outbound
        gate and the redactor, as everything WARDEN sends."""
        said = {"digest": self._post_one(digest_id, made["digest"], "WARDEN_DISCUSS_CHANNEL")}
        self.audit.append(digest_id, "awswatch.post", {"run_id": _run_id(), "what": "digest", "result": said["digest"]})
        for a in made.get("alarms") or []:
            said[a["id"]] = self._post_one(f"awswatch-{a['id']}", a["text"], "WARDEN_SLACK_CHANNEL",
                                           a.get("environment", ""))
            self.audit.append(digest_id, "awswatch.post", {"run_id": _run_id(), "what": a["id"], "result": said[a["id"]]})
        return said


# ------------------------------------------------------------------ the schedule


def _schedule() -> Any:
    from temporalio.client import (
        Schedule,
        ScheduleActionStartWorkflow,
        ScheduleCalendarSpec,
        ScheduleOverlapPolicy,
        SchedulePolicy,
        ScheduleRange,
        ScheduleSpec,
    )

    from .environments import display_zone
    from .workflows import MAIN_QUEUE, AwsWatchWorkflow

    hour, minute = at()
    return Schedule(
        action=ScheduleActionStartWorkflow(AwsWatchWorkflow.run, id="awswatch", task_queue=MAIN_QUEUE,
                                           execution_timeout=timedelta(hours=1)),
        spec=ScheduleSpec(calendars=[ScheduleCalendarSpec(hour=[ScheduleRange(hour)], minute=[ScheduleRange(minute)],
                                                          comment="the AWS updates digest")],
                          time_zone_name=str(display_zone())),
        policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP, catchup_window=timedelta(hours=6)))


async def sync_schedule(client: Any) -> str:
    """The Temporal Schedule as the settings say: made or brought up to date when the watch is on, deleted when it is
    off. Returns what was done: "created", "updated", "removed" or "off"."""
    from temporalio.client import ScheduleAlreadyRunningError, ScheduleUpdate
    from temporalio.service import RPCError, RPCStatusCode

    if not configured():
        try:
            await client.get_schedule_handle(SCHEDULE_ID).delete()
        except RPCError as exc:
            if exc.status == RPCStatusCode.NOT_FOUND:
                return "off"
            raise
        return "removed"
    schedule = _schedule()
    try:
        await client.create_schedule(SCHEDULE_ID, schedule)
        return "created"
    except ScheduleAlreadyRunningError:
        await client.get_schedule_handle(SCHEDULE_ID).update(lambda _: ScheduleUpdate(schedule=schedule))
        return "updated"
