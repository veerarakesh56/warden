# G10 held-out benchmark: integration and edge services

Written 2026-10-10 by an independent Claude agent (Claude Code, Opus 5.5) for the WARDEN owner. The agent was not
tuned on WARDEN's playbooks, catalogue or earlier benchmarks, and did not read them.

42 incident cases covering SQS (standard and FIFO), SNS, EventBridge rules, EventBridge Scheduler, Step Functions,
Kinesis Data Streams, Firehose, MSK, API Gateway (REST and HTTP APIs), ALB, NLB, CloudFront and Route 53.

| kind | count | correct_actions rule |
|---|---|---|
| fault (single) | 25 | the best available action(s) given `ACTION_MEANINGS` |
| multi_fault | 5 | one action per fault, in the order a person should take them |
| no_fault (healthy control) | 6 | exactly `["no_action", "escalate_to_human"]` |
| incomplete (evidence unreadable) | 6 | exactly `["escalate_to_human"]` |

21 of the 42 cases (50%) are marked `novel` (kinds outside the classic set): FIFO head-of-line poison, visibility
timeout shorter than the function's run time, FIFO content-based dedup collisions, SNS filter-policy drops, EventBridge
input-transformer failures, Scheduler flexible-window bursts, Step Functions 256 KiB payload limit, Kinesis retention
cut below consumer lag, Firehose S3 KMS denial, MSK partition-leadership skew, the API Gateway 29 s integration timeout,
HTTP API JWT issuer rotation, NLB client IP preservation against a security group, CloudFront Origin Shield 504s, a
Route 53 health check aimed at a name only private DNS resolves, plus novel multi-faults and controls.

## Layout

- `incidents/<id>.json`: `{"id", "alert", "context"}`. The alert carries `resources.labels_for(...)` of the alarm's
  metric(s) plus `alarm`. The context holds what the stack backend's readers would emit, in reader order:
  `logs`, `metrics`, `recent_deploys`, `tool_errors`, plus `empty_reads` where `gather()` would record one.
- `key.json`: per case `kind`, `service`, `novel`, `cause`, `cause_evidence`, `cause_evidence_untrusted`,
  `correct_actions`, `harmful_actions`, and `target`. Some cases also carry `alternatives`, `assumes` and
  `tool_error_expected`.
  - `cause_evidence` spans are exact substrings of the item texts of `warden.evidence.index(ContextBundle(...))`:
    what WARDEN numbers and shows. Tool errors appear in `tool_error_text`'s reduced form.
  - `cause_evidence_untrusted` lists the spans found only in untrusted L/E items. The model sees those only as
    quarantine facts. Every case also has at least one span in a trusted item.
  - `alternatives`: actions that are acceptable but not the best answer.
  - `assumes: ["cloudtrail-resource-name"]`: the case depends on assumption 5, and a live re-validation may drop it.
  - `tool_error_expected: true`: the evidence has a tool error by design (a WARDEN reader gap), so a gate escalation
    can be attributed.
- `generator/`: `fmt.py` (line builders), `cases_single.py`, `cases_other.py`, `build.py`, `validate.py`.

Rebuild and check (from `generator/`):

```
set PYTHONPATH=C:\work\warden-g1\src
C:\work\warden\.venv\Scripts\python.exe build.py
C:\work\warden\.venv\Scripts\python.exe validate.py
```

`validate.py` checks each case against WARDEN's own types:

- `Alert(**alert)` has no `rejected_labels`.
- `ContextBundle(**context)` parses.
- Every action is an `ActionKind`.
- No action is both correct and harmful.
- The no-fault and incomplete keys are exactly the required lists.
- Every `cause_evidence` string is a substring of an `evidence.index` item text, and at least one is in a trusted
  item.
- `cause_evidence_untrusted` matches what `evidence.index` says.
- No case id appears inside the evidence.
- `alternatives` are valid and are neither correct nor harmful.
- Every line has a reader's prefix.
- No structured line is demoted to untrusted by a name the author chose.
- Lambda log lines fall inside the reader's window.
- No more Lambda log lines than the reader keeps, unless its own truncation tool error is present.

Last run: 42 cases, OK.

## Independence rules followed

- Read only these files, and only to copy formats: `src/warden/aws_stack.py`, `aws_describe.py`, `resources.py`,
  `aws_backend.py`, `tools.py`, `quarantine.py`, `evidence.py`, `models.py` (in `C:\work\warden-g1`).
  `k8s_backend.py` and `database.py` were allowed but not needed: no case uses EKS or a database.
- Did not read, grep or open `src/warden/data/`, `fixtures/`, `verifier.py`, `grounding.py`, `graph.py`, `catalog.py`,
  `resolver.py`, `platforms/`, `knowledge.py`, `playbook.py`, `runbook.py`, `investigation.py`, `scenarios/`, `docs/`,
  `tests/`, `evals/`, `scripts/`, `~/warden-bench-runs`, `~/warden-heldout/g9-2026-10-10`, or `~/.claude`.
  The sibling groups under `g10-2026-10-10` (`compute/`, `data/`) were not opened either.
- Nothing under `C:\work` was modified. No AWS calls, no network, no secrets.
- The generator imports `_safe`, `_dims` and `_key` from `aws_stack`, `state_line` from `aws_describe`, and
  `labels_for` from `resources`, so tokens, STATE lines and labels are produced by WARDEN's own code. The validator
  imports `evidence._kind`/`_CONFIG` and `models`. Importing executes these modules; no other module was read.

## Formats reproduced (from the readers)

- `ALARM <ns>/<metric> <dims> stat=... period=Ns threshold <op> <float> datapoints=a/b missing=... state=...`.
  Metric-math alarms produce `ALARM metric-math threshold ...` and no alarm metrics.
- Alarm metric `alarm_<key>` (Sum is summed over the window, any other stat is the window's maximum) and siblings
  `alarm_sibling_<ns tail>_<key>` (maximum). A series with no datapoint is absent, never 0.
- `CHANGE <Z> <source> <EventName> on <name> by <principal>`, newest first per name (LookupEvents order). Names are
  the alarm's resource labels in sorted key order, excluding `apigw_stage`, at most 3. Otherwise the line is
  `CHANGE none on <name> in the 6 h before the alert`. More than 20 writes become the `changes: more writes ...`
  partial. Lambda event names carry their API-version suffix (`UpdateAlias20150331`). People appear as
  `role/AWSReservedSSO_...`, as an SSO session would.
- The Lambda reader, in this order:
  - `LOG lambda/<fn> <Z> <message>` (START/END dropped, REPORT kept);
  - the Insights metrics;
  - `CONFIG lambda ...` with the env allowlist;
  - `ESM <fn> <- <arn tail> State=... BatchSize=... LastProcessingResult=...`;
  - the lambda deploy dict;
  - the lambda metrics.
- The other readers:
  - `QUEUE ...` with the `sqs_*` and `dlq_visible` metrics;
  - `STATE <label> <name> ...` from `aws_describe.state_line`;
  - `STATE states ... failed execution ...` plus `EVENT states ... failure: ...`;
  - `TARGETGROUP`, `TARGET` (non-healthy only), `CONFIG alb ...` with the per-zone metrics;
  - `POLICY sqs <queue> allows_sns_topic=<topic>:yes|no`;
  - `RULE <rule> State=... schedule=...`.
- Partial reads appear as `tool_errors` exactly as `gather()` writes them: `logs: <reader>: [<outcome> on <Op>] <first
  line>`.

## Assumptions that matter

1. **Alert `service`** is the application's name (orders, billing, ...). The CloudWatch-to-Alert adapter was not on
   the read list, so how WARDEN fills `service` from an alarm is assumed.
2. **Region and account.** Regional resources sit in `ap-south-1`. The account is AWS's documentation placeholder
   `111122223333`, which appears only in Step Functions ARNs. us-east-1 alarms (CloudFront, Route 53) reach WARDEN
   through a forwarding rule. WARDEN's intake then adds the label `"alarm_region": "us-east-1"` and the reads run in
   that Region (coordinator, 2026-10-10). The three CloudFront/Route 53 cases whose evidence was read there carry the
   label. `int-inc-cloudfront-wrong-region` deliberately lacks it: it is the case of a missing forwarding rule, read in
   the stack's own Region, so `DescribeAlarms` finds nothing.
3. **Metric-math alarms** are used where a realistic alarm watches a queue and its consumer (or an API and its
   handler). `labels_for` gives both resources, so both readers run. Such alarms produce no alarm metrics.
4. **AppConfig.** The reader role may list AppConfig applications and no environment monitors these alarms, so no
   `CONFIG appconfig` lines appear. If the real role is refused, every case would gain an `appconfig` tool error.
5. **CloudTrail `ResourceName` lookups** are taken to match the plain resource name. Examples: a topic for
   `SetSubscriptionAttributes`, a target group for `DeregisterTargets`/`ModifyTargetGroupAttributes`, a schedule group
   for `UpdateSchedule`, an API name for `UpdateStage`. Real CloudTrail often records ARNs or ids, so a live lookup can
   miss some of these. `int-sqs-esm-disabled` assumes exactly that miss for `UpdateEventSourceMapping`, which is
   recorded under the mapping's UUID.
6. **AWS facts from knowledge, not verified live** (no network was used):
   - SQS's `NumberOfDeduplicatedSentMessages` metric for FIFO queues.
   - Firehose's `S3.KMS.AccessDenied` behaviour.
   - Step Functions' `States.DataLimitExceeded` text.
   - Scheduler's `ScheduleGroup` dimension.
   - The REST API 29 s integration timeout. Since 2024 it can be raised for Regional REST APIs by a quota request,
     which is not WARDEN's `raise_limit`; hence `escalate_to_human`.
7. **Key semantics.** Any action in `correct_actions` is an acceptable proposal. For multi_fault, the list is the order
   to take them. `alternatives` are acceptable but weaker. `harmful_actions` are plausible wrong proposals that would
   worsen the incident or act on a decoy. `target` is the resource the best action acts on.
8. **Lambda log volume.** Every case with a busy function is generated from one invocation stream: START, the
   function's messages, END and REPORT per invocation. `generator/fmt.py` `Ev.lam_stream` replays `AwsBackend.logs`
   on that stream:
   - the window is alert ±15 min, with data up to the read at 08:02;
   - the near window (from 07:55) is read first, then the earlier part;
   - 200 events a page, 10 pages;
   - the newest 120 events are kept, plus up to 30 older error-looking ones;
   - START and END count against these limits and are dropped afterwards;
   - both truncation tool errors are worded exactly as the reader writes them.

   The same stream gives `lambda_invocations`, `lambda_errors` and `lambda_duration_max_ms` (invocations starting
   07:50-08:02) and the Logs Insights counts.

## Findings about WARDEN made while authoring (not part of the scoring)

- **Every API Gateway STATE line is demoted to untrusted.** `aws_describe` emits the field
  `disableExecuteApiEndpoint` (REST) / `DisableExecuteApiEndpoint` (HTTP). `evidence._kind` squashes the line and
  finds "execute" in `_SQUASHED_STEER`, so WARDEN's own structured read of an API becomes an L item the model never
  sees. Cases keep the lines exactly as emitted. Affected: the 6 cases with an `apigw_rest`/`apigw_id` label.
- **The EventBridge rule reader cannot read a rule on a custom bus.** `describe_rule(Name=...)` is called without
  `EventBusName`, so a rule on `orders-bus` gives a `not found on DescribeRule` partial. This is reproduced in
  `int-eventbridge-input-transformer` because it is what WARDEN would gather.
- **CloudFront and Route 53 have no state reader** (they are not in `aws_describe.TABLE`). Their evidence is the alarm,
  its siblings and CloudTrail only.
- **A resource name containing a steering stem demotes all of its structured lines.** For example, a state machine
  named `refund-approval` squashes to "approv". The author renamed the one case that hit this; a real estate would
  not get to.

## Review fixes applied 2026-10-10

The fixes come from `REVIEW.md`. Applied: HIGH 2-5, every MED about case realism or keys, and the LOW format and
number slips. Per the coordinator, ids and severities are unchanged: ids are made opaque and severities uniform at
merge. All fixes are in the generator, and `validate.py` reports 0 failures after the rebuild.

**Changes across many cases**
- `cause_evidence` is now checked against what WARDEN shows (`evidence.index` item texts).
  - Tool-error spans use the reduced form, e.g. `alarm: access denied on DescribeAlarms`, with no brackets and no
    exception text.
  - `PartialData` and "more writes" tool errors render only as `failed (unclassified)`, so they were dropped as cause
    spans wherever a visible span carries the cause.
- New key field `cause_evidence_untrusted` marks the L/E-only spans.
- New key fields `alternatives`, `assumes: ["cloudtrail-resource-name"]` and `tool_error_expected`.
- No case id appears in any evidence text; the validator checks this.
- Lambda log volume (HIGH 2) is now generated from one invocation stream through an exact replay of `AwsBackend.logs`
  (assumption 8). The truncation tool errors appear exactly as the reader writes them: page exhaustion and the
  120-line cut. Invocations, errors, duration and Insights counts follow from the same stream. Cases:
  - int-sqs-dlq-redrive-after-fix
  - int-sqs-visibility-shorter-than-timeout
  - int-sqs-backlog-reserved-concurrency
  - int-multi-apigw-stage-and-concurrency
  - int-multi-httpapi-jwt-and-deploy
  - int-multi-kinesis-deploy-and-shards
  - int-sqs-fifo-poison-head-of-line (LOW count slip: it now shows 15 invocations and 12 errors in the metric window,
    with no truncation)

  int-apigw-integration-timeout-29s left this list because it no longer reads the function (below).

**Per case**
- **int-cloudfront-origin-shield-504, int-route53-healthcheck-private-ip, int-ok-route53-checker-blip:** gained the
  `alarm_region: us-east-1` label (HIGH 3). int-inc-cloudfront-wrong-region keeps no label; its cause now names the
  missing forwarding rule.
- **int-multi-apigw-stage-and-concurrency** (HIGH 4): now a single fault (`kind: fault`, service `lambda`). The
  reserved concurrency was cut to 5, and the 07:48 UpdateStage is a stated decoy (access logging). Key:
  `["revert_change", "raise_limit"]`, target `checkout-handler`.
- **int-multi-alb-healthpath-and-az** (HIGH 5):
  - The zone of the timing-out targets is not in the evidence, so the key is now `["revert_change",
    "escalate_to_human"]`.
  - LOW numbers: `alb_elb_5xx=21400`, sibling `healthyhostcount=4`, so the timeouts predate the change.
- **int-apigw-integration-timeout-29s** (MED):
  - Now a plain `AWS/ApiGateway/5XXError` alarm. `alarm_5xxerror=612` and the capped
    `alarm_sibling_apigateway_integrationlatency=29001` and `latency=29014` carry the cause.
  - A decoy TagResource CHANGE was added.
  - The function is no longer read, so the duration mismatch is gone.
- **int-apigw-stage-throttle-change** (MED): key is `["revert_change"]`; `raise_limit` moved to `alternatives`. No
  metric shows 429s.
- **int-httpapi-jwt-issuer-rotation** (MED): `alarm_4xx=13870`, now below 10 min × 1460 requests a minute.
- **int-route53-healthcheck-private-ip** (MED and coordinator): Route 53 refuses a health check on a private IP. The
  cause is now a change to an internal domain name (private hosted zone only) that the internet checkers cannot
  resolve. The evidence is unchanged.
- **int-cloudfront-origin-shield-504** (MED): the CHANGE event is `UpdateDistribution2020_05_31`.
- **int-kinesis-retention-cut** (MED): the trigger was re-cast so the alarm really transitions.
  - The threshold is 23 h (`82800000`) and the age is `8.295e+07`. The backfill lag crosses 23 h at 08:00, and after
    the 07:30 cut to 24 h retention, loss is imminent.
  - `ConsumerCount=0`, so the shared-throughput consumer is the one measured.
- **int-msk-leadership-skew** (MED): `LeaderCount=398` (broker 2's own ~200 plus most of broker 1's). The cause no
  longer claims auto-rebalancing is visible.
- **int-multi-kinesis-deploy-and-shards** (MED):
  - A second `UpdateShardCount` (07:26) was added, since 8→2 needs two calls.
  - Key is `["rollback_deploy", "revert_change"]`; `scale_up` moved to `alternatives`.
  - The cause says fault 2 shows only as the capacity cut.
- **int-multi-httpapi-jwt-and-deploy** (MED): the failing route is stated to be public, and fault 2 (401s on
  authorised routes) is documented as evidenced by its CHANGE line only.
- **int-scheduler-flexible-window-burst** (MED): the cause span is `UpdateSchedule on billing-reminders by
  role/terraform-apply` (20 trusted items), not the `failed (unclassified)` partial. Marked
  `assumes: cloudtrail-resource-name`.
- **int-ok-alb-scale-out** (MED): the principal is `role/AWSServiceRoleForAutoScaling` (the service-linked role).
- **int-inc-alb-throttled** (MED):
  - The alarm is `HTTPCode_ELB_5XX_Count` on `LoadBalancer` only, so there is no `alb_target_group` label and no
    DescribeTargetGroups error.
  - The target is the load balancer.
- **Decoys (MED, blind-strategy weakness):**
  - Recent decoy CHANGEs, where the right answer is not to revert them:
    - int-sqs-fifo-poison-head-of-line: UpdateFunctionConfiguration, never published to `live`.
    - int-sfn-payload-size-limit: TagResource.
    - int-apigw-integration-timeout-29s: TagResource.
    - int-multi-apigw-stage-and-concurrency: UpdateStage.
  - Benign recent CHANGEs in two controls:
    - int-ok-sqs-batch-drain: SetQueueAttributes by Terraform.
    - int-ok-kinesis-iterator-recovered: IncreaseStreamRetentionPeriod.
- **`assumes: cloudtrail-resource-name`** added where the CHANGE is recorded under an ARN or id in real CloudTrail:
  - int-sns-filter-policy-drop
  - int-multi-sns-filter-and-policy
  - int-alb-targets-deregistered
  - int-nlb-client-ip-preservation
  - int-apigw-stage-throttle-change
  - int-apigw-stage-broken-deployment
  - int-eventbridge-input-transformer
  - int-multi-alb-healthpath-and-az
  - int-scheduler-flexible-window-burst
- **LOW fixes:**
  - int-alb-single-az-impaired: `alb_elb_5xx=3810`.
  - int-sns-filter-policy-drop: delivered 9420.
  - int-sqs-visibility-shorter-than-timeout: durations jittered, "render started" seconds before its REPORT, and
    `rollback_deploy` no longer harmful.
  - int-sqs-backlog-reserved-concurrency: `escalate_to_human` added as an alternative.
  - int-sqs-fifo-dedup-collision: the cause says collisions and retries cannot be told apart.
  - int-inc-lambda-consumer-unreadable: "a disabled mapping" dropped from the cause.
  - int-eventbridge-input-transformer: `tool_error_expected`.
  - int-sqs-esm-disabled and int-nlb-client-ip-preservation: summaries no longer give the diagnosis.
  - int-sqs-dlq-redrive-after-fix, int-eventbridge-schedule-disabled and int-ok-eventbridge-offhours-schedule: the
    cause says the 08:00 page is a re-notification of a standing ALARM.

**Not applied, with reasons**
- **HIGH 1 (opaque ids) and MED severity leak:** the coordinator handles both at merge.
- **int-ok-alb-scale-out zone minimum (`alb_healthy_hosts_ap-south-1c=1`):** `_cw_read` takes the window's *maximum*
  of each per-zone Minimum series, so the 07:52 target does count and 3+3+2=8 is what the reader emits.
- **int-eventbridge-schedule-disabled alarm redesign:** a metric-math `FILL` alarm would drop the alarm metrics and
  still has no clean 08:00 transition. The case is kept and documented as a re-notification.
- **Near-duplicate fault components (LOW):** accepted as the review allows.
- **Full AccessDenied wording (optional LOW):** not done. It never reaches the model (T items render from the tag
  only).
- **REVIEW's "always-escalate / revert-latest baselines":** a scoring concern, left to the harness.

**Reader version.** While these fixes were being applied, WARDEN's working tree in `C:\work\warden-g1` had
uncommitted edits to `aws_backend.py`, `aws_stack.py`, `evidence.py` and `tools.py`. The author did not make them;
nothing under `C:\work` was modified by this work. They answer the findings below. The cases now follow that current
code:
- The `PartialData` partial reads `[output truncated on GetMetricData] <key> PartialData (the series may be
  incomplete)`, rendered `output truncated on GetMetricData`.
- The CloudTrail truncation reads `[output truncated on LookupEvents] more writes to <name> than were read`.
- `_kind` no longer demotes the API Gateway STATE lines (the first finding above).
- `ListExecutions` and `StartQuery` are now in `READ_OPERATIONS`.

The generator imports these modules, so a rebuild follows whatever the working tree holds. If those edits are reverted,
the two partial texts in the cases must be reverted too.

Still true: API Gateway symptom metrics are never read behind a metric-math alarm, and CloudFront and Route 53 have no
state reader.
