"""The deterministic gate. This is what decides — the model only ever proposes.

Every rule here is plain Python over typed data. No model call, no probability, no prompt. That is
the point: if the reasoning layer is stochastic, the deciding layer must not be, or the system has
no floor. Each rule returns a policy id so a rejection can be explained to an auditor without
re-running anything.
"""

from __future__ import annotations

from .environments import EnvironmentPolicies, default_environment_policies
from .models import (
    ACTION_FACTS,
    ActionKind,
    Alert,
    ContextBundle,
    RemediationProposal,
    RootCause,
    Verdict,
    VerdictStatus,
)

# Actions genuinely inert enough to skip human approval. Deliberately only the two that CANNOT
# touch running infrastructure: doing nothing, and handing off to a person. `clear_cache` was here
# and was removed - flushing a production cache can cause a stampede/latency spike, so it is a real
# action and belongs behind approval like the others. The project's whole claim is "nothing risky
# runs without a human"; this list is where that claim is enforced, so it stays as short as possible.
AUTO_SAFE_ACTIONS = {ActionKind.no_action, ActionKind.escalate_to_human}

# Actions exempt from the EVIDENCE floor (P4, P8, P9). Only escalating to a person: handing an
# incident to a human is the right answer to weak evidence, so measuring the evidence before
# allowing it would be circular.
#
# ⛔ `no_action` was in this set and is not any more. On a real AWS account, 14 of 42 runs answered
# `no_action` about a service with a live fault and the gate allowed every one - two of them at 0.25
# confidence while their own `tool_errors` recorded that WARDEN could not read the logs at all
# (docs/bench/wave1-2026-09-11T155744Z). "Nothing is wrong" is a CLAIM ABOUT THE EVIDENCE, so it
# must clear the same evidence floor as any other claim. A well-evidenced, confident `no_action` is
# still auto_safe - the tool looked properly and found nothing.
EVIDENCE_EXEMPT_ACTIONS = {ActionKind.escalate_to_human}

# The per-environment allow-list is no longer hardcoded here — it lives in environments.yaml so an
# operator can add an environment (qa-staging, pre-prod, qa-prod, ...) or tighten an allowlist without
# editing this gate. P1 consults it below. An unknown environment resolves to the restrictive default
# and fails closed.

MIN_CONFIDENCE = 0.55

# Thresholds for P9. Deliberately modest — this is a floor for "somebody looked at something",
# not a quality bar. Tune per deployment; the point is that it is OUR number, not the model's.
MIN_LOG_LINES = 3
MIN_METRICS = 2


def _evidence_is_substantial(context) -> bool:
    """Is there enough gathered evidence to justify touching production?

    Counted, not asked. A model reporting high confidence over two log lines is the exact failure
    this exists to catch, and it was observed on a live model, not hypothesised.
    """
    has_logs = len(context.logs) >= MIN_LOG_LINES
    has_metrics = len(context.metrics) >= MIN_METRICS
    has_deploys = bool(context.recent_deploys)
    # Two independent kinds of evidence, or a deploy plus one other kind.
    return sum([has_logs, has_metrics, has_deploys]) >= 2


def _log_has(context, *needles: str) -> bool:
    return any(n in line for line in context.logs for n in needles)


def _oom_seen(context) -> bool:
    return context.metrics.get("oom_killed_containers", 0) > 0 or _log_has(context, "OOMKilled", "OOMKilling")


REPLICA_LAG_SYMPTOM_S = 30.0


def symptoms(context) -> list[str]:
    """Things the EVIDENCE says are broken - counted, never judged from rates.

    Each is a count of broken objects or an explicit failure state the backends emit, so none of
    them depends on a threshold someone has to tune, except replica lag (named above). Used by P12
    to stop "nothing is wrong" being waved through when the evidence says otherwise.
    """
    m = context.metrics
    out: list[str] = []
    if _oom_seen(context):
        out.append("containers were OOM-killed")
    if m.get("crashloop_containers", 0) > 0 or _log_has(context, "CrashLoopBackOff"):
        out.append("containers are crash-looping")
    if _log_has(context, "ErrImagePull", "ImagePullBackOff"):
        out.append("an image cannot be pulled")
    if "pods_total" in m and m.get("pods_ready", m["pods_total"]) < m["pods_total"]:
        out.append(f"only {m.get('pods_ready', 0):.0f} of {m['pods_total']:.0f} pods are ready")
    if "replicas_desired" in m and m.get("pods_ready", 0) < m["replicas_desired"]:
        out.append(f"{m.get('pods_ready', 0):.0f} ready of {m['replicas_desired']:.0f} replicas desired")
    if "tasks_desired" in m and m.get("tasks_running", 0) < m["tasks_desired"]:
        out.append(f"{m.get('tasks_running', 0):.0f} of {m['tasks_desired']:.0f} tasks running")
    if m.get("deployments_failed", 0) > 0 or m.get("deployment_failed_tasks", 0) > 0:
        out.append("a deployment has failed tasks")
    # A full pool is an explicit state, not a rate: every connection the server (or the app's pool)
    # allows is taken. Live backends report `connections_used_pct`; recorded incidents the pool pair.
    # Added 2026-09-25: inc-005's report said "no failing component" beside a 100/100 pool.
    pool_size = m.get("connection_pool_size", 0)
    if m.get("connections_used_pct", 0) >= 1.0 or (pool_size and m.get("connection_pool_used", 0) >= pool_size):
        out.append("the connection pool is full")
    if _log_has(context, "stuck connection:"):
        out.append("sessions have been idle inside a transaction past the stuck threshold")
    if m.get("locks_waiting", 0) > 0:
        n = int(m["locks_waiting"])
        out.append(f"{n} session{'s are' if n != 1 else ' is'} waiting on a lock")
    if m.get("long_running_queries", 0) > 0:
        n = int(m["long_running_queries"])
        out.append(f"{n} quer{'ies have' if n != 1 else 'y has'} been running over 60s")
    if m.get("replica_lag_seconds", 0) >= REPLICA_LAG_SYMPTOM_S:
        out.append(f"replica lag is {m['replica_lag_seconds']:.0f}s")
    return out


def _every_pod_failing(context) -> bool:
    """No pod is reliably serving: none is ready, or every pod has a crash-loop / back-off record.

    ⛔ `pods_ready == 0` alone is a coin-flip for a crash-looping pod. With no readiness probe,
    Kubernetes marks it Ready for the moments between crashes - in CI the same OOM workload read as
    ready=1 from outside the cluster and ready=0 from inside it, seconds apart, and P11 fired on only
    one of them. A pod Ready between crashes is not serving traffic; a pod with a back-off record is
    failing whatever its readiness says at the instant it was sampled.
    """
    m = context.metrics
    total = m.get("pods_total")
    if not total:
        return False
    if m.get("pods_ready", total) == 0 or m.get("crashloop_containers", 0) >= total:
        return True
    backing_off = {
        line.split("Pod/", 1)[1].split(":", 1)[0]
        for line in context.logs
        if line.startswith("EVENT ") and ("BackOff" in line or "CrashLoopBackOff" in line) and "Pod/" in line
    }
    return len(backing_off) >= total


def _contradiction(proposal, context) -> str | None:
    """Why the proposed action cannot fix what the evidence shows - or None.

    Only contradictions that follow from how the action works, not from judgement: each is a case
    where the action demonstrably leaves the evidenced cause in place, or harms what is working.
    """
    a, m = proposal.action, context.metrics
    # scale_up on OOM is NOT always wrong: when memory grows with load, more replicas mean less load,
    # and less memory, per replica (the bundled inc-002 is that case). It is wrong when no replica is
    # failing (none ready, or every pod crash-looping / backing off - see _every_pod_failing) - then
    # none is reliably serving traffic, so load is not what fills memory, and every new replica
    # is killed at startup the same way (the EKS k8s-02/03 case: 900 MiB allocated at start, 48 MiB
    # limit). A first version flagged all scale_up-on-OOM and the inc-002 tests caught it.
    if a is ActionKind.scale_up and _oom_seen(context) and _every_pod_failing(context):
        return ("scale_up adds replicas, but every pod is failing: they are OOM-killed before serving "
                "traffic, so load is not what fills memory and every new replica dies at startup the "
                "same way. The per-replica memory limit or the application's memory use is the cause.")
    if a is ActionKind.scale_down and _oom_seen(context):
        return ("scale_down with OOM kills in the evidence: fewer replicas cannot lower any replica's "
                "memory use, and if memory grows with load it pushes more load onto each one.")
    if a is ActionKind.restart_pods and _log_has(context, "ErrImagePull", "ImagePullBackOff"):
        return "restart_pods re-pulls the same image, and the evidence shows that image cannot be pulled."
    if (a is ActionKind.terminate_connections and "long_running_queries" in m
            and m.get("long_running_queries", 0) > 0 and m.get("idle_in_transaction", 0) == 0
            and m.get("locks_waiting", 0) == 0):
        return ("terminate_connections with nothing idle in a transaction and nothing blocked: the only "
                "long sessions in the evidence are ACTIVE queries, and terminating them destroys work "
                "in progress.")
    # ⛔ Only when lag was MEASURED. An absent metric is not zero lag: ECS, Kubernetes and Redis report
    # none, and the MCP gate got none at all, so until 2026-09-25 every failover proposal from those
    # escalated with a false reason ("no replica lag in the evidence").
    if a is ActionKind.failover_replica and "replica_lag_seconds" in m and m["replica_lag_seconds"] < 1:
        return "failover_replica with no replica lag in the evidence - there is nothing lagging to fail over from."
    return None


def verify(
    alert: Alert,
    context: ContextBundle,
    root_cause: RootCause,
    proposal: RemediationProposal,
    *,
    policies_config: EnvironmentPolicies | None = None,
) -> Verdict:
    """Return the binding decision for one proposal.

    `policies_config` lets a caller/test inject a specific environment policy set; by default the
    bundled/operator-configured one is used.
    """
    env_policies = policies_config or default_environment_policies()
    env = env_policies.for_env(alert.environment)

    reasons: list[str] = []
    policies: list[str] = []
    rejected = False
    escalate = False

    # P1 — the action must be permitted in this environment at all (from environments.yaml).
    if not env.permits(proposal.action):
        rejected = True
        policies.append("P1-ENV-ALLOWLIST")
        reasons.append(
            f"{proposal.action.value} is not permitted in {alert.environment}."
        )

    # P2 — nothing irreversible in a production-tier environment, ever, regardless of confidence.
    #
    # ⛔ READS THE TABLE, NOT THE PROPOSAL. `proposal.reversible` is written by the model, and by
    # any caller of the MCP server, so keying a rejection on it let a proposal widen its own
    # permissions: two live models reported opposite values for the identical operation and got
    # opposite verdicts (docs/live-model-run-2026-09-06.md §3). The claim is not discarded — P10
    # escalates when it contradicts the table.
    if env.tier == "prod" and not proposal.table_reversible:
        rejected = True
        policies.append("P2-IRREVERSIBLE-IN-PROD")
        reasons.append(
            f"{proposal.action.value} is classified irreversible in WARDEN's action table, and "
            f"{alert.environment} is production-tier. The proposal claimed "
            f"reversible={proposal.reversible}; the table decided, not the claim."
        )

    # P3 — evidence is a precondition for action, not an optional extra.
    if context.is_empty() and proposal.action not in AUTO_SAFE_ACTIONS:
        rejected = True
        policies.append("P3-NO-EVIDENCE")
        reasons.append("No logs, metrics or deploy history were gathered; refusing to act blind.")

    # P4 — a low-confidence hypothesis is a question, not a plan.
    if root_cause.confidence < MIN_CONFIDENCE and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        escalate = True
        policies.append("P4-LOW-CONFIDENCE")
        reasons.append(
            f"Confidence {root_cause.confidence:.2f} is below the {MIN_CONFIDENCE} threshold."
        )

    # P5 — you cannot roll back a deploy that the evidence does not show.
    if proposal.action is ActionKind.rollback_deploy and not context.recent_deploys:
        rejected = True
        policies.append("P5-NO-DEPLOY-TO-ROLL-BACK")
        reasons.append("Rollback proposed but no recent deploy appears in the gathered context.")

    # P6 — wide blast radius is always a human's call. The table sets a FLOOR per action and the
    # proposal may only ever widen it: a model asking for a human is always allowed to, while
    # understating the reach of an action must buy it nothing.
    effective_radius = proposal.effective_blast_radius
    if effective_radius in ("multi_service", "region"):
        escalate = True
        policies.append("P6-BLAST-RADIUS")
        floor = ACTION_FACTS[proposal.action][1]
        reasons.append(
            f"Blast radius '{effective_radius}' exceeds the unattended limit (WARDEN's floor for "
            f"{proposal.action.value} is '{floor}', the proposal claimed "
            f"'{proposal.blast_radius}'; the wider of the two applies)."
        )

    # P7 — proportionality. Don't fail over a database because something is 'low'.
    heavy = {ActionKind.failover_replica, ActionKind.rollback_deploy}
    if proposal.action in heavy and alert.severity.value in ("low", "medium"):
        escalate = True
        policies.append("P7-DISPROPORTIONATE")
        reasons.append(
            f"{proposal.action.value} is disproportionate to a {alert.severity.value} alert."
        )

    # P8 — a tool failing means the picture is partial. Say so rather than pretending.
    if context.tool_errors and proposal.action not in EVIDENCE_EXEMPT_ACTIONS:
        escalate = True
        policies.append("P8-PARTIAL-CONTEXT")
        reasons.append(f"{len(context.tool_errors)} context tool(s) failed; evidence is incomplete.")

    # P9 — evidence measured by US, not confidence reported by the model.
    #
    # Added after running against a live model: it returned confidence 0.85 on ALL the bundled
    # incidents (four then; five in the recorded run, docs/live-model-run-2026-09-06.md), including
    # the one whose entire evidence is two vague log lines. A model's
    # self-reported confidence is not calibrated, so P4 alone would essentially never fire — the
    # gate would be relying on a number the model has no incentive or ability to get right.
    #
    # This counts what was actually gathered. It cannot be talked around by a confident tone.
    if proposal.action not in EVIDENCE_EXEMPT_ACTIONS and not _evidence_is_substantial(context):
        escalate = True
        policies.append("P9-THIN-EVIDENCE")
        reasons.append(
            f"Evidence is thin ({len(context.logs)} log line(s), {len(context.metrics)} metric(s), "
            f"{len(context.recent_deploys)} deploy(s)); a human should look before acting."
        )

    # P10 — the proposal warns that this cannot be undone while the table says it can.
    #
    # P2 reads the table so the model cannot decide; ignoring a warning is a different thing from
    # refusing to obey one. `escalated` and `rejected` both mean nothing runs and both require a
    # person, so escalating here preserves the warning without handing the decision back.
    if proposal.claim_contradicts_table:
        escalate = True
        policies.append("P10-CLAIM-CONTRADICTS-TABLE")
        reasons.append(
            f"The proposal claims {proposal.action.value} is irreversible; WARDEN's action table "
            "classifies it reversible. A human should reconcile that before anything runs."
        )

    # P11 — the action cannot fix what the evidence shows.
    #
    # ⛔ Added 2026-09-25 from measured failures, which is disclosed with it: all three runs the EKS
    # wave let through wrongly were `scale_up` against `oom_killed_containers = 2` - more replicas of
    # a container killed at 48 MiB are killed the same way - and nothing in P1-P10 read the evidence
    # against the action. A re-run of the same scenarios is therefore NOT an independent test of this
    # policy. Escalates, never rejects: the rules are how the actions work, but a human decides.
    contradiction = _contradiction(proposal, context)
    if contradiction:
        escalate = True
        policies.append("P11-ACTION-CONTRADICTS-EVIDENCE")
        reasons.append(contradiction)

    # P12 — "nothing to do" while the evidence shows something broken.
    #
    # no_action became subject to P4/P8/P9 after Wave 1, but a CONFIDENT no_action over plenty of
    # evidence still went out auto_safe even with pods OOM-killed or not ready. In the measured runs
    # low confidence happened to catch every such case; that was luck, not a rule. Same disclosure
    # as P11: written after seeing the runs.
    if proposal.action is ActionKind.no_action:
        found = symptoms(context)
        if found:
            escalate = True
            policies.append("P12-NO-ACTION-WITH-SYMPTOMS")
            reasons.append("No action proposed, but the evidence shows: " + "; ".join(found) + ".")

    if rejected:
        return Verdict(
            status=VerdictStatus.rejected,
            reasons=reasons,
            policy_ids=policies,
            requires_approval=True,
        )
    if escalate:
        return Verdict(
            status=VerdictStatus.escalated,
            reasons=reasons or ["Escalated for human judgement."],
            policy_ids=policies,
            requires_approval=True,
        )
    if proposal.action in AUTO_SAFE_ACTIONS:
        return Verdict(
            status=VerdictStatus.auto_safe,
            reasons=["Action is inert or advisory; no approval required."],
            policy_ids=policies,
            requires_approval=False,
        )
    return Verdict(
        status=VerdictStatus.approved_for_human,
        reasons=["Passed all policies. Held for operator approval before execution."],
        policy_ids=policies,
        requires_approval=True,
    )
