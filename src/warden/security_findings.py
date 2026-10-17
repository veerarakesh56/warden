"""Security findings as intake events (item 15): Amazon GuardDuty and AWS Security Hub CSPM, through EventBridge.

A security finding is never a fault one of WARDEN's fixes mends. Its catalogue restarts, scales, rolls back and closes
idle sessions; none of them contains a compromise, and a restart or rollback of a compromised task throws away what a
person investigating it needs. So every finding WARDEN takes is escalate-only: WARDEN reads the evidence of the
resource it names, with its read-only identity, and hands the incident to a person - the model is asked for nothing
and no plan is opened (`intake.AlarmEvent` refuses a security event without its reason to escalate, and
`intake.decide` sends one nowhere else). It is never held as expected down, never folded into another alarm's
incident, and never taken as a sign that a fix of WARDEN's did not work.

What is taken, and what is not - deterministic, from the finding's own fields:

- Only a finding on a resource whose name says which watched environment it is in (`warden-<env>-...`), as an AWS
  Health notice is (lambdas.health_event). A finding that names none of ours - an account-level one, a resource of
  another team - stays in GuardDuty or Security Hub and their own notifications.
- Severity medium, high or critical (GuardDuty: 4.0 to 10.0; Security Hub: MEDIUM, HIGH, CRITICAL). Low and
  informational are a port scan or a failed attempt: noted by AWS, not an incident.
- GuardDuty: not archived, not one of GuardDuty's sample findings (those are made on request, to test).
- Security Hub: an ACTIVE finding whose workflow is NEW or NOTIFIED, of a threat-shaped type (`TTPs/`, `Effects/`,
  `Unusual Behaviors/`) - never a failed posture check (a finding with a compliance status) or a vulnerability - and
  never one GuardDuty made: GuardDuty's findings come in directly, and twice would be two incidents.
- Anything malformed - a severity that is not a number in range, a type or name that is not AWS's shape, a detail
  that is not an object - is refused: None, and the Lambda says it ignored the event.

The finding's resource details (addresses, keys, instance ids, account ids, ARNs) are redacted as WARDEN redacts every
alert's text before it is put in the summary. The rule, which intake records and the Lambda logs, carries no
identifier: the product, the finding type and a digest of the finding's id - so the same finding updated is the same
alarm, and its incident, while it runs, is told of it rather than a second one started.

Shapes: GuardDuty's "GuardDuty Finding" event, whose detail is one finding as GetFindings returns it, and Security
Hub CSPM's "Security Hub Findings - Imported", whose detail holds ASFF findings - from AWS's GuardDuty and Security
Hub user guides and the GuardDuty and Security Hub API models (botocore 1.43.114), read 2026-10-17. The severity bands
are GuardDuty's "Severity levels of GuardDuty findings": Low 1.0-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical
9.0-10.0. Security Hub's OCSF findings ("Findings Imported V2") are not taken yet: no rule subscribes to them, and
this module refuses them.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from typing import Any

from .intake import AlarmEvent
from .models import NAME_PATTERN, Alert, Severity

GUARDDUTY = ("aws.guardduty", "GuardDuty Finding")
SECURITY_HUB = ("aws.securityhub", "Security Hub Findings - Imported")

# GuardDuty's bands, lowest value of each; below MEDIUM is low and not taken.
GUARDDUTY_BANDS = ((9.0, Severity.critical), (7.0, Severity.high), (4.0, Severity.medium))
MIN_GUARDDUTY_SEVERITY = 4.0
SECURITY_HUB_LABELS = {"CRITICAL": Severity.critical, "HIGH": Severity.high, "MEDIUM": Severity.medium}
SECURITY_HUB_WORKFLOW = ("NEW", "NOTIFIED")
# ASFF type namespaces that describe something happening, not a configuration to improve.
THREAT_TYPES = ("TTPs/", "Effects/", "Unusual Behaviors/")

# UnauthorizedAccess:EC2/SSHBruteForce, CryptoCurrency:EC2/BitcoinTool.B!DNS, AttackSequence:EKS/CompromisedCluster
_GD_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9]{1,63}:[A-Za-z0-9]{1,63}/[A-Za-z0-9][A-Za-z0-9._!-]{0,127}")
_ASFF_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9 /:.!_-]{2,255}")
_PRODUCT = re.compile(r"[A-Za-z][A-Za-z0-9 ._-]{0,63}")
_NAMED = re.compile(NAME_PATTERN)
_SUMMARY_MAX = 4000


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _last(value: Any) -> str:
    """A resource's own name: an ARN's last part (after `/` or `:`), or the value itself."""
    return re.split(r"[/:]", str(value or ""))[-1]


def _tag(tags: Any, key: str) -> str:
    """A tag's value from GuardDuty's [{key, value}] list or Security Hub's {key: value} map."""
    if isinstance(tags, dict):
        return str(tags.get(key) or "")
    return next((str(t.get("value") or "") for t in _list(tags) if isinstance(t, dict) and t.get("key") == key), "")


def watched(candidates: list[str]) -> str:
    """The first candidate that is a plain name of a watched environment's resource; "" when none is."""
    from .environments import env_of_name

    return next((n for n in candidates if n and _NAMED.match(n) and env_of_name(n)), "")


def _guardduty_names(resource: dict[str, Any]) -> list[str]:
    """The names a GuardDuty finding's resource carries, most specific first: an ECS task's service, a function, a
    database, a cluster, a bucket, an instance's Name tag, the role a key belongs to."""
    ecs = _obj(resource.get("ecsClusterDetails"))
    group = str(_obj(ecs.get("taskDetails")).get("group") or "")
    rds = _obj(resource.get("rdsDbInstanceDetails"))
    key = _obj(resource.get("accessKeyDetails"))
    return [group.removeprefix("service:") if group.startswith("service:") else "",
            str(_obj(resource.get("lambdaDetails")).get("functionName") or ""),
            str(rds.get("dbInstanceIdentifier") or ""), str(rds.get("dbClusterIdentifier") or ""),
            str(ecs.get("name") or ""), str(_obj(resource.get("eksClusterDetails")).get("name") or ""),
            *(str(_obj(b).get("name") or "") for b in _list(resource.get("s3BucketDetails"))),
            _tag(_obj(resource.get("instanceDetails")).get("tags"), "Name"),
            str(key.get("userName") or "") if key.get("userType") in ("AssumedRole", "Role") else ""]


def _guardduty_details(resource: dict[str, Any], service: dict[str, Any]) -> list[str]:
    """The resource details a person looks at first, as text to be redacted."""
    inst, key = _obj(resource.get("instanceDetails")), _obj(resource.get("accessKeyDetails"))
    out = [f"resource type: {resource.get('resourceType') or 'unknown'}"]
    if inst.get("instanceId"):
        out.append(f"instance: {inst['instanceId']}")
    for nic in _list(inst.get("networkInterfaces"))[:3]:
        nic = _obj(nic)
        out.extend(f"{k}: {nic[k]}" for k in ("privateIpAddress", "publicIp") if nic.get(k))
    if key.get("accessKeyId"):
        out.append(f"access key: {key['accessKeyId']}")
    action = _obj(service.get("action"))
    for kind in ("networkConnectionAction", "awsApiCallAction", "portProbeAction", "dnsRequestAction"):
        remote = _obj(_obj(action.get(kind)).get("remoteIpDetails"))
        if remote.get("ipAddressV4"):
            out.append(f"remote address: {remote['ipAddressV4']}")
    if service.get("count"):
        out.append(f"seen {service['count']} time(s), first {service.get('eventFirstSeen', '?')}, "
                   f"last {service.get('eventLastSeen', '?')}")
    return out


def _summary(title: str, description: str, details: list[str]) -> str:
    """The alert's summary - the finding's own words and its resource's details - redacted as every alert's text
    is before it goes anywhere."""
    from .redaction import redact

    text = "\n".join([title.strip(), description.strip(), *details])
    return redact(text).text[:_SUMMARY_MAX]


def _event(product: str, kind: str, finding_id: str, name: str, severity: Severity, when: datetime, summary: str,
           via: str, sample: str = "") -> AlarmEvent:
    from .environments import env_of_name

    digest = hashlib.sha256(finding_id.encode()).hexdigest()[:12]
    return AlarmEvent(
        source="security", rule=f"{via}:{kind}:{digest}"[:512], state="ALARM", transitioned_at=when, stateless=True,
        escalate=(f"{product} reports a {severity.value} security finding ({kind[:60]}) on {name}{sample}: a "
                  "possible attack or misuse. No fix on WARDEN's list answers it; a person decides")[:300],
        alert=Alert(alert_id="sec", name=kind[:512], severity=severity, service=name,
                    environment=env_of_name(name) or "", summary=summary, started_at=when.isoformat(),
                    labels={"via": via}))


def _when(*values: Any) -> datetime | None:
    for v in values:
        try:
            when = datetime.fromisoformat(str(v))
        except ValueError:
            continue
        if when.tzinfo is not None:
            return when
    return None


def guardduty(event: dict[str, Any]) -> AlarmEvent | None:
    """A GuardDuty finding event as an escalate-only intake event; None for anything not taken (module docstring)."""
    if (event.get("source"), event.get("detail-type")) != GUARDDUTY:
        return None
    d = _obj(event.get("detail"))
    sev, kind, fid = d.get("severity"), str(d.get("type") or ""), str(d.get("id") or "")
    if isinstance(sev, bool) or not isinstance(sev, int | float) or not math.isfinite(sev) or not 1.0 <= sev <= 10.0:
        return None
    service, resource = _obj(d.get("service")), _obj(d.get("resource"))
    if (sev < MIN_GUARDDUTY_SEVERITY or not _GD_TYPE.fullmatch(kind) or not fid or service.get("archived") is True
            or _obj(service.get("additionalInfo")).get("sample") is True):
        return None
    name = watched(_guardduty_names(resource))
    when = _when(d.get("updatedAt"), event.get("time"))
    if not name or when is None:
        return None
    level = next(s for floor, s in GUARDDUTY_BANDS if sev >= floor)
    summary = _summary(str(d.get("title") or kind), str(d.get("description") or ""),
                       [f"GuardDuty severity {sev:.1f} ({level.value})", *_guardduty_details(resource, service)])
    return _event("GuardDuty", kind, fid, name, level, when, summary, "guardduty")


def security_hub(event: dict[str, Any]) -> AlarmEvent | None:
    """A Security Hub CSPM finding event (ASFF) as an escalate-only intake event; None for anything not taken."""
    if (event.get("source"), event.get("detail-type")) != SECURITY_HUB:
        return None
    findings = _list(_obj(event.get("detail")).get("findings"))
    if len(findings) != 1 or not isinstance(findings[0], dict):
        return None  # AWS sends one finding per event: anything else is not its shape
    f = findings[0]
    product, fid = str(f.get("ProductName") or ""), str(f.get("Id") or "")
    label = str(_obj(f.get("Severity")).get("Label") or "")
    types = [str(t) for t in _list(f.get("Types")) if isinstance(t, str)]
    threat = next((t for t in types if t.startswith(THREAT_TYPES) and _ASFF_TYPE.fullmatch(t)), "")
    if (label not in SECURITY_HUB_LABELS or not _PRODUCT.fullmatch(product) or product == "GuardDuty" or not fid
            or not threat or f.get("RecordState") != "ACTIVE" or f.get("Sample") is True
            or _obj(f.get("Workflow")).get("Status") not in SECURITY_HUB_WORKFLOW
            or _obj(f.get("Compliance")).get("Status")):
        return None
    resources = [_obj(r) for r in _list(f.get("Resources"))]
    name = watched([n for r in resources for n in (_last(r.get("Id")), _tag(r.get("Tags"), "Name"))])
    when = _when(f.get("UpdatedAt"), event.get("time"))
    if not name or when is None:
        return None
    level = SECURITY_HUB_LABELS[label]
    details = [f"Security Hub severity {label}", f"type: {threat}",
               *(f"resource: {r.get('Type') or 'unknown'} {r.get('Id') or ''}".rstrip() for r in resources[:5])]
    summary = _summary(str(f.get("Title") or threat), str(f.get("Description") or ""), details)
    kind = threat.rsplit("/", 1)[-1] or threat
    return _event(f"Security Hub ({product})", kind, fid, name, level, when, summary, "securityhub")


def finding_event(event: dict[str, Any]) -> AlarmEvent | None:
    """Either source's finding as an intake event, or None."""
    return guardduty(event) or security_hub(event)
