# Changelog

All notable changes to WARDEN are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, so a minor
bump may carry a breaking change.

## [Unreleased] - becomes 0.10.1 (G1, security-critical fixes)

### Security
- **Tool errors reach the model as fixed words** (audit A-C-2). A failed read used to show the model
  its raw exception text as a trusted T item. That text can quote log content: a `KeyError` names
  the key it looked up. The model now sees `<reader>[ <source>]: <outcome>[ on <read operation>]`,
  built from a fixed vocabulary (access denied, timed out, not found, ...). The redacted raw text
  stays in the audit and in the human report. The outcome is tagged where the error is raised
  (ea65387); an error recorded before that carries no tag and reaches the model as "failed
  (unclassified)", never as its text.
- **A log stream name can no longer forge a trusted config item** (audit A-C-3). Any task role can
  create a CloudWatch stream and choose its name, spaces included, and the name sits where WARDEN's
  own line structure is. Two fixes:
  - stream names are reduced to one safe token;
  - the `LOG k8s/<ns>/<deployment>` prefix is trusted only before the rollout history, with
    Kubernetes-shaped names.
- **The alert's own text is inert** (audit A-C-1, A-C-13). The environment must be a name, and
  the start time a timestamp. The name and summary reach the model on one line each, inside
  nonce-marked "data only" markers. People see them as a single inline code span. A forged
  "approved fix" heading or command block in a summary now shows as the words it is.
- **Every way out passes the outbound gate** (audit A-C-8). That covers:
  - chat sinks, with the secret check (G5) now over the text as built rather than after
    re-redaction, where it could never fire;
  - stdout, with no secrets and no terminal escape sequences;
  - the `--json` artefact, redacted again with the run's map;
  - MCP results and error text.
  The old test that reached BLOCK only by monkeypatching the gate is replaced by one where the
  pipeline really missed a secret.
- **The link rule (G3) closes its gaps** (audit A-C-9):
  - `//host` links and link reference definitions are removed;
  - `<img/src=...>` is caught, and bare domains are defanged;
  - control and bidi characters are removed;
  - fences are tracked the CommonMark way, and text after an unclosed fence is sanitised;
  - fences in deployed-source lines are escaped.
- **Redaction** (audit A-C-4, A-C-5, A-C-22, A-C-23):
  - The literal sweep no longer rewrites short values everywhere. `user_id=500` used to turn every
    HTTP 500 into the tenant placeholder. The new rules:
    - 12+ characters are swept everywhere;
    - 6-11 characters only as a standalone token;
    - shorter values only where a pattern matched them.
  - Tool errors now share the run's one placeholder map, so `<IPV4_1>` cannot mean one host in a
    tool error and another in the logs.
  - Newly masked:
    - `--password`/`--api-key` style flags;
    - `whsec_` and `xapp-` tokens;
    - PGP private key blocks;
    - EC2 host names that carry an IP.
  - The redactor no longer claims to be "verified" (A-C-23). Its re-scan could only look for values
    it had already found; it is removed (below), and the gate's G5 is the independent check.
- **P15 needs evidence that bears on the action** (audit A-C-6):
  - a key must start a word ("ready" no longer matches "already");
  - generic symptoms (error, 5xx, timeout, request) no longer support `scale_up`;
  - `scale_down` on replica lag is now a P11 contradiction.

  Replayed over the 60 recorded reports that carry citations (2026-09-30; the bench reports carry
  none, so P13-P15 never ran on them): the first version changed three verdicts (k8s-02, -04, -05,
  found by the second review); 45773cb restores them.
- **The mutation check really runs every mutation on Windows.** It read files as bytes, so each
  multi-line anchor in a CRLF checkout was reported "missing" (6 of 35). It now matches line
  endings and restores byte for byte, and a test runs its real code path on every file. All 35 are
  caught.
- **Each model host gets only its own key** (audit A-C-18). `OPENAI_API_KEY` used to go to Groq,
  OpenRouter and any custom host. Keys by host now:
  - Groq reads `GROQ_API_KEY`;
  - OpenRouter reads `OPENROUTER_API_KEY`;
  - a custom `WARDEN_BASE_URL` reads `WARDEN_API_KEY`;
  - a loopback model needs no key.
- **The Claude CLI works behind a proxy, with a private CA, and in a minimal container** (audit
  A-C-19). The proxy and CA-bundle variables pass to the CLI, and so do HOME/USERPROFILE and
  `CLAUDE_CODE_OAUTH_TOKEN`.
  - Why HOME/USERPROFILE now pass (decided 2026-09-30):
    - they had been stripped because a 2026-09 measurement showed them loading the operator's own
      configuration;
    - that measurement predates the isolation flags (no setting sources, no tools, no MCP servers);
    - re-measured with the flags: no configuration loaded either way, and the same latency.
  - Still stripped:
    - `CLAUDE_CONFIG_DIR` and `XDG_CONFIG_HOME`, which point the CLI at other configuration;
    - `ANTHROPIC_API_KEY`, which would switch the subscription to API billing.
- **Console tracing writes to stderr** (audit A-C-20). Spans on stdout corrupted the MCP server's
  JSON-RPC stream. A test runs the real server with tracing on and parses every stdout line. The
  span `service.version` now comes from the package: it said 0.8.0.
- **Small correctness fixes** (audit A-C-24, A-C-25):
  - the gate's withheld notice now names its alert (it read the wrong key);
  - P5 needs a deploy of the rollback's target, not of any service;
  - P14 refuses targets that read as a flag or an assignment.

  Replayed over the 60 recorded reports that carry citations (2026-09-30): one verdict changed. A
  db-05 proposal to act on `pid=4934` went from escalated to rejected; it names no resource and was
  already P13.
- **The outbound gate writes only text it has checked** (second review, A-C-1, A-C-8, A-C-9).
  - HTML entities are neutralised, never decoded.
  - `<` is neutralised outside placeholders, so no HTML block, comment or autolink can start.
  - Link reference definitions and setext headings are broken.
  - Control characters and CR are removed before fences are found.
  - A run of three backticks is broken inside a line, because Slack opens code there.
  - A `~~~` block is sanitised, because Slack has no such fence.
  - Every domain outside inline code is defanged, including emails and any top-level domain.
  - The tool-error span attribute and the worker's log lines pass the gate.
  - `--json` refuses a secret the pipeline missed.

  Proven by rendering the reviewer's 30 payloads with a CommonMark parser and reading them as Slack
  does. Each of the 17 rules is plant-checked.
- **A Temporal payload cannot stall or cross workflows, and `apply` trusts no activity result**
  (second review, A-B-L13).
  - A payload that does not decrypt now becomes the refused marker instead of raising. That covers a
    forged "encrypted" payload, another key, and changed bytes.
  - Every ciphertext is bound to its namespace and workflow, so an approval recorded in one workflow
    no longer decrypts in another.
  - `apply` re-reads WARDEN's own audit log. It needs the plan WARDEN made for this workflow (same
    entry and parameters, no problems) and enough recorded approvals for that exact plan hash.
  - Known limits, stated in `codec.py`:
    - anyone who can complete a workflow's activity tasks can stop it, but the same principals can
      terminate it;
    - a `Replayer` must be given the recording namespace.
- **Redaction treats an incident's text as one text** (second review; A-C-4, A-C-5, A-C-22, A-C-23).
  - Logs, deploys, the alert's summary, name and labels, and tool errors are redacted together. A
    secret found in any of them is masked in all of them; before, a later find stayed in clear in
    earlier lines. MCP context shares the same single map.
  - A label is redacted with its key: `tenant_id=acme-7` is a tenant. The label keys WARDEN reads as
    resource names are the exception.
  - A plain word after a credential key or flag is not taken for its value: "--token not set",
    "api_key=true", "password: field required". Before, it was also swept out of every other line.
  - New credential shapes:
    - `whsec_` with `+`;
    - prefixed and JSON-argv flags;
    - `sqlcmd -P`, `ldapsearch -w`, `htpasswd -b`, `curl -u` with no space, `mariadb -p`,
      `mongosh`/`az login -p`;
    - `*_AUTH=` variables;
    - legacy Vault tokens;
    - a no-break space before a value.
  - The re-scan inside `redact()` could never fire, so it is removed. The docs now name the gate's G5
    as the independent check.
- **The tripwire reads what came from outside, not WARDEN's own words** (second review, A-C-11).
  - The real Prompt Guard 2 scored WARDEN's header 0.98.
  - Measured 2026-09-30 on 36 benign alert texts: 0 flagged, down from 7 in WARDEN's own run and 9 in the second review's.
  - "Ignore previous instructions" in an alert is still caught (0.997-0.999).
  - Label values can no longer rewrite WARDEN's prompt markers.
- **An apply is approved for its own run, or not at all** (third review, A-B-L13).
  - `rem-<service>` is reused. The codec binds only the namespace and the workflow id, so payloads
    recorded in an earlier run, or in another step of the same run, could carry a run past its
    approval, gate or precheck.
  - A kill switch tripped during the approval wait was also missed, with no attacker needed.
  - `apply` now counts only WARDEN's own audit rows of its own Temporal run: the plan, the
    approvals, and a clean precheck after them. It also re-checks the bounds and the kill switch.
  - The workflow treats only an explicit empty gate or precheck answer as clean.
  - The reviewer's six attack scripts now end with nothing applied.
- **No real-looking token in the repository** (2026-09-30).
  - A test held a string shaped exactly like a Stripe webhook signing secret. It was the review's
    invented example, not a real key, and GitHub secret scanning flagged it.
  - Every vendor-token-shaped test value is now built from parts.
  - `check_publishable` gained the shapes it lacked: Stripe, GitHub fine-grained, GitLab, npm,
    SendGrid, Vault, Slack app.
- **Vacuous tests now fail without their guard** (audit A-C-VT; 16 plant checks).
  - Each redaction row asserts its own placeholder kind.
  - Each injection payload carries its own marker, and all of them fail with the quarantine off.
  - `node_redact` and `notify` are tested on their own output.
  - The eval pins its safe-action set.
  - LLM call counts are exact.
  - The rewrite found two real gaps, both fixed:
    - base64 of an instruction passed the quarantine;
    - the high-entropy backstop never matched a value right after `key=`.
- **The model budget is checked before every call** (A-C-15, A-C-16, A-C-17). The call over the
  ceiling is never made. Retries are checked too. An explicit budget wins over `WARDEN_MAX_USD`, and
  a budget that is not a positive number is refused.
- **The proving ground's proof script** looked for leftovers by the old `Project` tag. Its
  post-destroy check could only ever report 0 left. A test now reads it.
- **A failed read's outcome comes from what failed, not from what its message says** (second
  review, A-C-2).
  - WARDEN writes a tag such as `[access denied on FilterLogEvents]` where it catches the failure.
    The tag comes from the exception's type and structured codes: botocore's error code and
    operation, the Kubernetes status, the database SQLSTATE. The trusted T item reads only the tag.
  - A KeyError quoting "AccessDenied when calling the DescribeSecret operation" is now
    "failed (unclassified)".
  - A pod name is no longer taken for a reader tag.
  - A config line with run-together steering words is no longer trusted.
  - Replays of runs recorded before this change show their tool errors as "failed (unclassified)",
    because those strings carry no tag.
- **Verifier, tripwire and provider fixes** (second review: A-C-6, A-C-12, A-C-18, A-C-25, A-C-26).
  - **P11** reads every lag metric the backends emit, `redis_replication_lag_s` included. It takes the
    unit from the metric's own name: a resource suffix such as `__payments_msvc` read seconds as ms.
  - **P14** accepts a resource kind named with `=` (`deployment=checkout (namespace=shop)`). Three
    correct recorded proposals had been rejected; a selector such as `app=x` is still refused.
    Invisible characters (soft hyphen, U+180E) can no longer hide a flag.
  - **P15** reads WARDEN's own fact spellings (`OOMKilled`, `exitCode=137`, `CPUUtilization`,
    "deadlock").
  - **P5** accepts a target that names both the service and its deployed function.
  - Replayed over the 60 recorded reports that carry citations: exactly the three wrongly rejected
    verdicts changed. The earlier bench replay had no citations, so P13-P15 were never tested there.
  - **Tripwire:**
    - one scan is capped at 32,768 tokens, and more escalates;
    - `prepare` retries at most 3 times instead of forever;
    - the threshold is capped at 0.99;
    - a model without a MALICIOUS label is reported unavailable, not silently scored 0.
  - **Providers:**
    - the Gemini key goes only to Google (`GOOGLE_GEMINI_BASE_URL` sent it anywhere);
    - OpenAI organisation and project ids go only to OpenAI;
    - the Claude CLI no longer saves each prompt to the operator's profile
      (`--no-session-persistence`).
- **The tripwire scores what the model sees, and fails closed** (audit A-C-11, A-C-12, A-C-21;
  commits bdb8a13 and e8278f2).
  - It is scored by token ids in windows of up to 512 tokens, so nothing is truncated.
  - Everything the model reads that came from outside WARDEN is scanned, each part on its own: the
    alert's name and summary, its labels, and each trusted item. The typed facts (F items) are not
    scanned themselves; they are covered through the log lines they came from, which a scan past its
    budget may skip ("ran-partial"). The raw log lines, which the model
    never sees, get the remaining budget; lines past it are reported as "ran-partial", not escalated.
  - In `required` mode, anything but a detector that actually ran escalates.
  - A threshold that is not a number is refused.
  - Scoring works without torch (CI runs without it).
- **The outbound gate reads code blocks the way CommonMark does** (third review, A-C-9, A-C-8).
  - A line-by-line fence tracker could not follow a fence inside a list item or a quote. Python's
    `strip()` also closed a fence on a no-break space, where CommonMark keeps it open. Code regions
    now come from a CommonMark parser (markdown-it-py, MIT, now a core dependency).
  - Only the body of a closed backtick fence stays verbatim. The gate parses its own output again;
    if the fences differ from the ones it kept, it cleans everything as prose.
  - Removing a Slack token or a tag could join what was left into a link or an image. Removals now
    run until nothing changes.
  - Removing a tag could leave a heading (`<b>## Fix - approved`). A line the gate changed now starts
    no block.
  - All 5,725 inputs of the review's render harness render with no link, image, raw HTML, new
    heading or new code block, and the gate is idempotent on each (`tests/test_gate_review3.py`).
  - Logs and span errors are redacted before they are cut: a key on the cut left its prefix.
  - A logged message can no longer pass for a log line of its own.
  - Every command and the MCP server gate their logs; only `warden worker` did.
  - The log formatter imports nothing while it runs. Imported lazily, it ran under Temporal's
    workflow sandbox importer whenever a workflow logged (180 warnings; a pytest `filterwarnings =
    error` did not catch it, because the error is swallowed inside the worker - a test records it).
  - Readability cost: a line the gate changed loses its list or heading formatting.
- **Verifier and provider fixes** (third review, A-C-6, A-C-18, A-C-25).
  - P15: `restartCount=0`, `OOMKilled=false` and "no OOMKilled events" support no action. The
    camelCase split (45773cb) had hidden the zero from the check.
  - Replica lag named with a unit and a suffix (`replica_lag_seconds_max`, `replica_lag_msec`) is
    read again, in seconds.
  - P5: a deployed name counts as the alert's service only behind a configured environment prefix
    (`warden-dev-checkout`). `payments-orders` is not `orders`.
  - P14 refuses any invisible character, a flag after a quote, bracket or comma, every Unicode dash,
    patterns and lists (`pod=orders-*`), and a whole namespace or cluster.
  - `OPENAI_CUSTOM_HEADERS` is refused for any host but OpenAI: the SDK sent those headers,
    Authorization included, everywhere. The Gemini client's debug mode is set off explicitly:
    `GOOGLE_GENAI_CLIENT_MODE=replay` answered from files on disk.
  - Replayed over the 337 recorded reports: no verdict changed.
- **Redaction, evidence and quarantine fixes** (third review, A-C-2, A-C-4, A-C-10, A-C-23).
  - A failed read's outcome tag is read behind any depth of WARDEN's own prefixes. Nested stack
    lines read "unclassified" (a regression in ea65387). The previous-revision gap line is tagged.
  - A log writer could erase chosen words from all evidence, WARDEN's own config read included,
    with one planted `password=<word>`: every copy of a secret was swept. 932d515 stopped sweeping a
    secret that is a plain word or an assignment. **Withdrawn (fourth review):** that exemption left
    real secrets in clear in other lines - a base64 key ending in `==`, a passphrase, a letters-only
    password - and the gate passed them. Every copy of every secret is masked again; the planted-word
    masking is an open, recorded limit (B-N4).
  - `redact_many` is fast again: 300 lines took 122 s, now 0.45 s; 2,000 lines take 13.6 s. The
    output is byte-identical.
  - The prompt is redacted as one text with one map: two new values in two parts got the same
    placeholder. WARDEN's facts-block markers are never redacted: a label `token=DATA` rewrote them.
    A resource label is no longer masked as a secret in the prompt.
  - Quarantined facts must be ASCII, and the steering check also reads digits as letters
    (`r0llb4ck`): Cyrillic, fullwidth and zero-width look-alikes spelled instructions.
  - The README no longer describes the removed re-scan.
  - Replayed over the recorded runs: no context, fact or verdict changed.
- **The tripwire reads short windows and single sentences too** (fourth review, A-C-11).
  - Benign padding in the same part diluted an injection: about 300 characters before it in an
    alert summary, a long alert name, or ten fields in a deploy record let 12 of 35 padded
    placements through. The parts the model reads are now also scored in 64-token windows and
    sentence by sentence (field by field).
  - Real Prompt Guard 2, 2026-09-30: 34 of 35 padded placements caught (was 23). On the 132-placement
    set, 51 caught (was 46). No benign alert of 36 was flagged. 3 of 14 instruction-worded benign
    texts (a "Revert: disregard the previous release" deploy note, a SYSTEM_PROMPT config) now
    escalate to a person, up from 1. The owner chose this trade: a false alarm costs a review.
  - The scan reads the labels key by key, as the prompt does: redacted as one dict,
    `{'token': '<SECRET_1>'}` scored 0.93 and escalated every such incident.
  - In required mode only the exact `ran-partial: <n> of <m> log lines` counts as a run (C-9): any
    status merely starting with "ran-partial" passed.
  - Correction found by re-timing with the real model (2026-10-01): the short windows were batched with
    the long ones and padded to their length, so a 4,003-token scan took 102 s (15.5 s before), and the
    budget counted every re-scoring, so 8,000 tokens of evidence - under what recorded incidents need -
    escalated as too much text. Windows are now scored in length order (scores identical: 28 windows,
    difference 0.000000) and the budget counts the text once: 4,003 tokens take 26 s, 14,003 take 86 s.
- **Every copy of every secret is masked again** (fourth review, B-N1, a regression in 932d515).
  An exemption for "plain words and assignments" left a base64 key, a passphrase and a letters-only
  password in clear wherever they were repeated, and the outbound gate passed them. A test covers
  each shape and checks the gate. Open (B-N4): a planted `password=<word>` still masks that word in
  WARDEN's own reads; the planned fix escalates such an incident rather than leaving any copy
  unmasked (a trusted-lines exemption was tried and dropped: it left a user id from a log line in
  clear inside a config read).
- **A fix is verified only by the run's own health checks** (fourth review, B-N2). `rem-<service>`
  is reused and a payload is bound to the workflow id, not the run, so an earlier run's "healthy"
  result, completed into a later run's check, marked that run recovered with no check made: no
  rollback, and a signed audit row saying ok. Each real check now writes an audit row with its run;
  the verdict is taken from those rows and returned with the run id, and the workflow accepts only
  its own. A forged claim leaves a `remediation.result_mismatch` row. Test fails without the fix.
- **Redaction stays fast whatever the logs hold** (fourth review, B-N3). The sweep tested every found
  value against every line: 2,000 lines of ten values each took 217 s, and prepare runs it two or
  three times, so a log writer could push an incident past its timeout. One trie-shaped finder now
  tells each line which values it holds, and the map is kept once per call instead of copied per
  line: that case takes 4.3 s, and 2,000 ordinary lines 0.9 s (13.6 s before). Values nested too
  deeply for the finder (a planted chain) are checked one by one, alone. The output is
  byte-identical: benchmark digests, the reviewer's inputs and all 337 recorded contexts.
  Follow-up found by a re-test: building the finder was itself quadratic (a set rebuilt for every
  value) and compiled a pattern for every found identifier; it now takes 1.1 s for 6,000 values
  (6.7 s before), identifier patterns are compiled only for values a line holds, and the timing test
  compares 4x the input against 1x instead of a wall-clock limit. Output still byte-identical.
- **Apply bookkeeping is per run; the end record states what the audit shows** (fourth review,
  B-N6, B-N9). "Already applied" was checked across runs: a second approved run of the same plan applied
  nothing, then rolled back a change it never made, and tripped the kill switch. A refused apply was
  recorded as "apply_failed, may be half-made" with approved and prechecked true; it is now
  `refused_at_apply` (nothing changed), and the signed end row takes its checklist from the run's
  audit rows, keeping any unbacked claim only as `claimed_checklist`.
- **A failed read keeps its outcome whatever the case of the name** (fourth review, B-N5, a
  regression in 932d515). Mixed-case log groups (SAM/CDK `/aws/lambda/ShopStack-OrdersFn…`,
  `/ecs/Orders`), the k8s reader's `<pod>/<container> (previous)` and the ECS reader's
  `deploys: <family>:<revision>` all read "failed (unclassified)" instead of, say, "access denied on
  FilterLogEvents". Upper case is accepted only behind `/` or a kind prefix and `<family>:<revision>`
  only after `deploys`, so free text still cannot place a tag.
- **Slack text, log lines and the MCP server's errors hold their shape** (fourth review, A-2, A-3,
  A-4, A-8). The Slack conversion tracked code fences at column 0 only, so a split inside an indented
  block left the rest - URLs included - as prose; it now tracks a fence anywhere in the line. Line and
  paragraph separators (U+2028/2029), which Markdown does not break on, became headings in Slack; they
  are spaces there now, and a no-break space after `#` no longer makes a heading. In log lines they
  are line breaks, indented like any other, so they cannot forge a record. The MCP server prints an
  uncaught error as one gated line on stderr instead of a raw traceback, and routes warnings through
  the same gate.
- **More steering spellings stay out of the facts; hex keys under any key name are masked** (fourth
  review, B-N7, B-N8). `ro11back`, `roIIback`, `ro||back` (read as `l`), `rolback`, `revert`, and key
  names like `rootcause=` reached the model as facts, as values or through the `code=`/`object=`
  carriers. A 32+ character hex value after a name ending in "key" (`ENCRYPTION_KEY=`, `hmac_key=`,
  `Ocp-Apim-Subscription-Key:`) is now masked; the entropy backstop needed upper case. Over every
  recorded run the 8,485 facts, the 337 trusted items and the 337 redacted contexts are unchanged.
  Still open: other leetspeak (`8` for `c`) - the quarantine is one layer, not the only one.
- **The verifier reads evidence and targets as they are written** (fourth review, C-4, C-6, C-7).
  - P15 read `restarts: 0 -> 6`, "could not obtain lock", "no free memory" and "no response from
    primary" as no support (22 of the reviewer's 36), and let `"restartCount": 0`, `== 0`, `(0)`,
    "never restarted" and `exit code 0` support an action (16 of 37). It now reads the value a key
    reports - a transition's last value, zeros written any way - and a negation reaches only its own
    clause; a zero of something good ("0/3 passing", "cache hit: 0%") is a shortage. Both tables: 0.
  - P14 accepted a flag after `=`, `/`, `:` or `@`, dash look-alikes outside the dash category,
    lists without `=` (`orders payments`, `{orders,payments}`), patterns (`.+`, `%`), whole-namespace
    spellings (`namespace/x`, `(namespace=x)`, "all pods in x", the bare namespace), redirects and
    commands. Targets are ASCII, and a namespace that only qualifies a resource is looked past, so
    `deployment=checkout, namespace=shop` is no longer refused.
  - Replica lag is read through a unit whitelist: `replication_lag_bytes`, `_count`, `_alarm` and
    `_threshold` were lag in seconds, and `replica_lag_p99_ms` read 40,000 ms as 40,000 s.
  - Over the 337 recorded reports no verdict changes; of their targets only a no_action "A and B"
    now reads as a list.
- **Database logins per environment (G1-I, A-I-1/A-I-2)**: the database users are named for their environment
  (`warden_<env>_app`, `_catalog`, `_ro`), so a grant in one environment names no user in another's cluster;
  the boundary allows `rds-db:connect` only as the environment's own users and denies the master `postgres`.
  Terraform publishes the names (`db_users` in stack.json); bootstrap.sql and the k8s config are filled from
  them, each checked to be a plain user name; the apps no longer default to `app`/`catalog`. A live window
  proves it before any row closes. The boundary is now at 6,140 of IAM's 6,144 characters.
  The deploy role also gets what the first real deploy needed and only the operator was given: Aurora
  express's `default` subnet group, and tagging event source mappings (A-I-5, A-I-6).
  WARDEN's reader role names only the stack's own resources wherever AWS allows it and the code passes
  the resource (16 reads); 11 that AWS cannot scope keep "*" (A-I-19; AWS's Service Reference, read
  2026-10-01).
  Each deploy role's trust also requires the main branch and one of the two reusable deploy workflows
  (`ref`, `job_workflow_ref`; A-I-10's code half - the GitHub half is the owner's step G1).
  Event source mappings and task definitions are the environment's own (`lambda:FunctionArn`, the
  family name); only DeregisterTaskDefinition, which AWS gives no resource or condition, stays
  region-bound (A-I-8).
  A ValidatingAdmissionPolicy holds the Kubernetes remediator's patches to the replica count (within two)
  and the restart annotation; a pod spec change by it is refused on the real API server in CI (A-I-11).
- **Sixth independent review, the write path** (2026-10-01; rows A-R6): a failed rollback ends
  `rollback_failed`, signed, and trips the kill switch (it crashed the workflow); a rollback undoes only
  what its own run applied, and its row names the run and plan; a fix with nothing to undo (a restart)
  ends `not_recovered`, not `rolled_back`; a plan is refused unless the request's service is the target
  the fix changes, and health is asked only of the platform that made the change; MySQL closes sessions
  by idle time, not transaction age; the database platform refuses an allowlist naming its own login.
- **Sixth independent review, lower findings**: P15 no longer reads another field's number after "then",
  takes a missing value or headroom ("cpu: null", "0 MiB free") as scale_down's idle use, or hides "0 free"
  and "0 available" shortages (all three regressions from 7c0dd34); "not a single pod restarted" and
  "0 days ago" read right. A failed incident may be diagnosed again (Temporal's ALLOW_DUPLICATE_FAILED_ONLY);
  a completed one still may not, and a test now starts it twice on the time-skipping server. The log gate
  installs its hooks only where Python's defaults are, leaving another program's (pytest's) in place.
  Redaction: a lowercase-hex credential under vault/consumer/root/data/deploy/host/KMS key names is masked
  again (the fifth review's narrowing left them out), and cookie, `mysql -p` and `"auth"` values never wrap
  a placeholder in a second one (restore left the inner one in an operator's report).
  The database platform uses its connection one thread at a time and reopens one that failed (it kept a
  broken connection until a restart). README: the Kubernetes example uses the namespace the RBAC binds, and
  states that a count moving between the final precheck and the write is stepped from (sixth review).
  A plan names the Kubernetes API server or database server it writes to (`warden status` shows it, the
  plan hash covers it), so staging's plan and prod's no longer look the same.
  A scale is held to the replica count the plan was approved on: a count that moved just before the
  write was stepped from (2 -> 4 with 3 approved) and is now refused with nothing changed.
  A Deployment is healthy only once its controller has seen the current spec and its rollout has not
  stalled (observedGeneration, Progressing).
  P14 refuses a command before a period (`orders (rm.)`, `kubectl.exe`) and kill, pkill, terraform,
  shutdown, reboot, eksctl, systemctl. Replica lag in days and weeks is converted, more unit spellings
  are read right, more non-lag words refused, and DocumentDB's and Aurora Global Database's CloudWatch
  lag names read (milliseconds). The lag list stays open-ended by design: an unknown word is a resource.
  A platform's refusal before writing anything (a count that moved, a bound re-checked, an unreadable
  target) ends `refused_at_apply`, not `apply_failed`. P14 takes every spelling of a namespace or cluster
  label as a scope (`aurora_cluster`, `NAMESPACE`, `k8s_namespace`, an ElastiCache group); a failover may
  name the cluster its alert labels and never a namespace. The stub of a withheld report redacts its
  alert id as well as defanging it. An invisible character at a dot (`evil.<ZWSP>com`) no longer keeps a domain
  whole. The register guard judges a whole-suite run however its path is spelled (`.`, `tests/.`).
  The package and the image keep out every secret-bearing file .gitignore names (tfstate, tfvars, saved
  plans, key stores, databases) - checked by building a wheel and an sdist with a planted tfstate - and
  the Slack fence tests use nested list markers (a weaker fence check passed them).
  CI · apps also runs weekly, so the deployed requirements are audited without a change; an interrupted
  mutation check stops its workers before restoring the mutated file.
  Still open: "not a single one of the pods restarted", "cpu (idle): 0%" and "probe: 0 ok" in P15; a second
  resource written as an image reference or behind a scope word (`orders (payments:latest)`,
  `orders (namespace payments)`) still passes P14.
- **Sixth independent review, the records**: the register guard refuses a cited test rebound to another
  function (`globals()` reached it unseen) and is tested itself; a collect-only run is no longer judged (it
  always failed); the register reads every row GitHub shows - indented, without a leading pipe - and refuses a
  table whose Group or Status column was renamed; R4-E-5 cites the test that proves it. Corrections: the A-R5
  note said "one commit, each with a test"; the commit 9d01dfd said each new test fails on the previous code,
  which the concurrency test does not (its control predates it); README's live-test counts (24: 13
  Kubernetes, 11 databases) and mutation count (37). Commits pushed together get CI on the last one only: five
  commits since 9551288 had no run of their own (4a7afe0, 7c0dd34, 0981974, 6530fc0, 1ee7ca3); from 3bd757c
  on, commits are pushed one at a time.
- **Sixth independent review, the tripwire** (7f0178e): only the placeholders WARDEN issued are removed
  from what is scanned (any `<WORD_N>` was, hiding an injection written in that shape), and labels are
  scanned as sentences - a credential-named label no longer escalates a clean incident on the real model.
- **Ninth independent review** (2026-10-01): a terminal colour code glued to a key (`ESC[1m<key>`) hid it from
  every pattern needing a word boundary - the terminal, the gate, MCP data and the log sent it whole (HIGH,
  pre-existing). Redaction now removes escape sequences first. The gate's G5 checks every view of a text - as
  written, without escapes, without controls, without invisibles, and what G3 made of it: checking only the
  normalised text glued `x<BEL>` to a key (a regression from c52f6db), and removing a tag from inside a key
  assembled one G5 never saw (pre-existing). The log formatter redacts before it normalises. Invisible
  characters are removed only between ASCII name characters, so emoji and CJK selectors pass unchanged. A
  one-letter or bare scheme (`p://evil.com`) is a link.
  Cookies are masked in every written form - Go's `Cookie:[...]` and prefixed keys (`X-Auth-Cookie`,
  `HTTP_COOKIE`) slipped past ace3572's patterns (HIGH, a regression), and CGI, PHP, HAR, curl, a cookie jar and
  escaped quotes were never reached. A Bearer or Basic token whose start was masked is masked whole; a JSON
  `"authorization":` is matched. A tool saying there is none (`<nil>`, `<none>`, `cookie=missing`) is not a
  secret, and a value the cleaning did not assemble is not a new leak. A secret inside a compound value is swept
  alone too.
  A VPC's default network ACL, default security group and main route table are untagged, so no environment's
  boundary held them - any environment's role could rewrite prod's default NACL (HIGH, pre-existing). The boundary
  now denies changing a NACL entry, a security group's rules or a route on an untagged ACL, group or table; the
  stacks never change one, and a rule being created is untagged, so the deny names the three resource types.
  P14: a key led by an acronym (`ECSCluster`, `K8SNamespace`, `AWSECSCluster`) is split into words again, and plural,
  `compute_`, `fargate_`, `k3s_`, `ocp_` and platform-only keys are scopes (a regression from 71b0d0d). A failover,
  cache clear or connection kill names no namespace or compute cluster anywhere in its target - a kind word hid the
  second one, and a failover of the namespace named like its service passed. A cluster qualifying a pod target
  (`cluster/service`, `service (cluster)`) is not a second target; after an arrow, a comma or "and" it is.
  The carried model budget: only a request provably never sent (refused, unresolved) or answered with an error
  status is "unanswered" - a provider's own read timeout and a 200 it could not read may have been billed and are
  carried (a regression from af2a361: 18 requests went where the ceiling allowed 4). The claude CLI's API error
  status and connection failures are read from its output, so an outage still never locks an incident.
  The boundary also denies changing account- and region-wide settings (EBS encryption and instance metadata
  defaults, block public access for images, snapshots and the VPC, ECS account defaults, account log policies),
  ways out (another account's access to a queue, topic or layer, peering, accepting an attachment) and committing
  money (reservations, purchases); a Lambda permission names exactly the two service principals the stack grants.
  A database plan's `server` is read the way libpq reads a URL - after the last `@`: a password holding `?` or `#`
  put the user and the password's start into the plan the approver signs (pre-existing). What is left must look
  like hosts, or it is not shown.
  The register guard: only the file's one module-level `def` under the cited name is evidence (a same-named
  staticmethod, or a second `def`, counted); its verdicts travel on the reports from its own records, not in
  user_properties a fixture can forge or strip; a callback replayed by a wrapper is no return; a blank `-k` no
  longer turns judging off, and `--cache-show` is not judged. A table behind a quote or a list marker is refused
  in the registers. Every weakening a reviewer named is now caught by the guard's own tests.
  A remediation run cancelled once apply was sent ends on the record and trips the kill switch: a cancel during an
  activity arrived as an ActivityError and left no end row, and a cancel during apply read as "cancelled".
- **Eighth independent review** (2026-10-01): the gate withheld every report quoting a masked cookie - its
  re-scan took `Cookie: <SECRET_1>` for a new secret, because the "nothing but placeholders" skip needed the
  redactor's map (a regression from a95f171; MED). The skip now goes by the value's shape, and no value class
  stops at `<` any more: the part of a credential after a placeholder an earlier pattern placed
  (`password=<UUID>.x`, `Bearer <JWT>.x`, a quoted `"<JWT> x"`) went out in clear (HIGH, pre-existing).
  Cookies written as JSON, a dict, a list or an assignment are masked too; only `Cookie:` was (HIGH,
  pre-existing). The redaction replay over 337 contexts is byte-identical.
  An incident's carried model budget counts what may have been billed - answered and timed-out calls -
  not requests that reached no model: carrying those let three runs during a provider outage use up the
  call ceiling, and the incident could never be diagnosed after the provider recovered (a regression from
  8f575b8). A timed-out call now counts as a call; it counted nowhere.
  P14 refuses a data target with a whole namespace or cluster beside it (`aurora -> ecs`; a regression from
  8ce403d), reads scope labels in any spelling (`ClusterName`, `k8s.namespace.name`, `gke_cluster`) as words, not
  substrings (`sandbox_namespace` held "db"), and never lets a failover target the alert's namespace even when it
  is named like the service. The verify replay over 337 reports and the 2,696-row target replay are unchanged.
  The outbound gate normalises first: control characters and the code points a URL parser drops are
  removed before the leak check and before links are removed. Removed after, `htt<SHY>p://evil.com/x` hid
  from link removal and the gate itself joined it into a live link (a regression from d5763ff, widened by
  d40fc9a; MED), and a key split by one invisible or control character passed G5 and went out whole -
  from Slack, the terminal, MCP results, and the CLI's argument errors (MED). The stub of a withheld
  report redacts its id with the blocked data too, and leaves it out when it is part of a withheld value.
  The register guard compares the code that ran with what pytest compiled from the test file, and counts it
  only when it started, returned and never raised: eight more bypasses passed a full run with an `assert False`
  body - a rebuilt `__code__`, a nested def, `compile()` padded to the line, a failure swallowed by a wrapper, a
  hook, a report rewrite or a thread, `sys.monitoring` deleted by a fixture (MED). Planted into a real full run,
  all eight are named and fail it. On Python 3.11, which has no `sys.monitoring`, the run says it did not check.
  The boundary denies RunTask and StartTask: they carry no subnet key and ECS's own role makes the task's network
  interface, so a dev role could run a task with prod's subnets and security groups and reach prod's Redis
  (HIGH; nothing in the stack runs one). It also holds daemons to their own cluster, denies EventBridge's bus
  policy API and account-wide log policies, and allows a function permission only for an AWS service - not
  another account by id, which IAM Access Analyzer misses on an alias. An ECS service may still be given another
  environment's subnets (no IAM key ties a subnet to an environment) - Redis authentication and TLS are the
  planned fix. The owner's CloudShell step stops on any error and on an unread account number.
  The admission policy bounds the count only when it changes - a restart of a Deployment above ten was
  refused - and a refusal is read as the policy's, not as a moved count, whatever the Deployment is called
  ("test" in `latest-api` read it as moved). CI now refuses removing a template annotation, pausing and a big
  step down on the real API server. The policy does not hold `metadata.managedFields` (the API server rewrites
  it itself); README and the manifest say so.
  A remediation run cancelled after its fix was applied ends on the record, `cancelled_after_apply`, and trips
  the kill switch - it left no end row and the switch off. Every unknown end is its own trip, and a reset
  must name the latest: a second one while the switch was on left no row, and one reset signed for the first
  cleared both. `warden killswitch` lists every trip since the last reset. A retried `finish` writes one end row.
  The plan's "where" reads a libpq key=value DSN pair by pair (text inside a password was read as a host),
  shows `service=` and PGHOST when they decide the server, and shows MySQL's TCP default and ignores `?host=`
  there, as the driver does. A Kubernetes write that never reached the API server ends refused - it tripped
  the global kill switch through apply_failed. PostgreSQL's own-login check uses `session_user`. CI's live
  PostgreSQL and SQL Server tests now prove the idle threshold and that a session running a statement - or,
  on SQL Server, one with no open transaction - is never selected.
  P15 reads "0 remaining / left / free" as a shortage only when nothing bad is named in the measure - "blocked
  connections: 0 remaining" or "probe failures: 0 left" still supported an action - and counts a capacity word
  between the key and the value ("queue slots: 0 free"). "Idle" is a shortage again for scale_up only: an
  exhausted pool ("pool: 0 idle") had stopped supporting it (a regression from 88bb9e5). The verify replay is unchanged.
  A five-part JWE is masked whole (the JWT pattern took three segments and left its ciphertext and tag). The
  reader's ARN test refuses a widening `*` before the stack's name, an environment may not be named like
  another's prefix (`qa` beside `qa-prod` would collide in every IAM pattern), and the proving ground's alert says
  why it carries `environment: prod` (the benchmark's policy environment, whatever stack it runs on).
  The packaging excludes are still a list, and the seventh entry's "every secret-bearing name stays out" was
  an overclaim: 27 more shipped (`plan.json`, `*.tfstate~`, `.pgpass`, `.my.cnf`, `.kube/config`, `secrets.yaml`,
  key stores...). Each is excluded now - a real build with 56 planted names ships none. Tests that weaker code
  passed now fail it: every one of the 270 invisible code points, a valid cron, the image's final stage copying
  only the installed environment, and no `.dockerignore` line re-including what the excludes keep out.
  The registers may hold no table inside a block quote and no raw HTML table: GitHub shows both and the
  register parser reads neither - planted on the real audit, a quoted row marked DONE-local with Evidence "trust
  me" passed every check. README's test counts are 3,709 unit tests (3,631 counted the evals twice) and 38 live
  tests (27 Kubernetes, 11 databases), and a test now holds the live counts to what pytest collects.
  The audit's A-R8 section holds every eighth-review defect of medium-low and above with its commit, and the
  open items as R8-O1..O4: a model call abandoned mid-flight can be paid again by the next run; an ECS service
  may be given another environment's subnets and the boundary pins no account; the admission policy does not hold
  managedFields; and lesser gaps. The seventh review's rows carry the eighth's PARTIAL verdicts.
- **Seventh independent review** (2026-10-01): a token masked inside a cookie header no longer ends the match: every cookie
  after it went out in clear, past the gate's re-scan (a regression from 3acea5b, which kept `<` out of
  the value to stop a placeholder being wrapped; HIGH). A value that holds a placeholder is now stored
  restored, so restore() gives it back in one step and no value class has to stop at `<`.
  A failed incident that runs again keeps one model budget: each run started a fresh client, so a model
  answering invalid JSON was paid for 10 times over 5 restarts, $3.00 against a $0.50 cap (a regression
  from e94365a; MED). Every run records its spend in the audit, failed or not, and the next starts from
  the total - failed requests included, so an outage uses part of the incident's call ceiling.
  The Kubernetes admission policy holds the Deployment's own owners, finalizers, labels and annotations,
  its rollout fields (history, readiness, deadline) and the pods' finalizers, and caps the count at ten: one
  allowed patch adding a dangling owner reference had the garbage collector delete the Deployment (A-I-11;
  HIGH). The unit test places every field of the API's DeploymentSpec and ObjectMeta, and CI refuses each
  change on the real API server. A write the API server refuses (RBAC, a policy) ends refused - it never
  persisted - not "may be half-made".
  ECS writes stay in the environment's own clusters: a service's ARN is `service/<cluster>/<name>`, so
  the dev deploy role's `*/warden-dev-*` matched a dev-named service in prod's cluster, and CreateService
  authorizes the new, untagged service - the tag deny never fired; RunTask authorizes only the task
  definition (HIGH). The boundary, which binds every role the deploy role creates, denies ECS writes on
  `ecs:cluster` unless the cluster is `warden-<env>-*`; its IAM ceiling folds the list and
  instance-profile actions into two wildcards on the same resources to make room.
  `aurora_express.py create` writes the application user Terraform names (`warden_<env>_app`) into the
  app secret - it wrote `app`, which no IAM grant names, so orders-api would have signed its token for
  the wrong user (MED) - and refuses a stack.json naming another. It acts only on `warden-<env>-aurora`
  itself: a name prefix let `WARDEN_ENV=qa` delete `warden-qa-prod-aurora` (MED).
  The proving ground's alert names the run's own environment's stack: the template named dev's and
  nothing rewrote it, while the reader is scoped to its own stack, so outside dev every scoped read was
  AccessDenied (MED).
  The register guard checks, during each cited test's call, that the code its file's `def` compiles to
  actually started: five one-line bypasses passed the full run with an `assert False` body - a `__code__`
  swap, a renamed no-op or a wrapper bound under the name, a `pytest_pyfunc_call` answering for the call, a
  fixture swapping the test object (MED). Three of them, planted into a real full run, are now each named
  and fail it. The guard's own wiring (exit status, the rebound state, the worker check) is unit-tested.
  The register parser ends lines only at a line feed and tables only at a real heading or quote, and the
  registers may hold no invisible line break at all: one U+2028 after a row hid the rest of the A-I table
  from it while GitHub showed every row, and `#X-2 | ...` ended a table GitHub kept (MED-LOW).
  A plan's "where" never stops a plan being made, and says where libpq really connects: a multi-host
  DSN made the lookup raise on every attempt, so no plan was written (a regression from c56fa13), and a
  `?host=`/`hostaddr=` override or a socket was not shown. In a cluster the API server's address is the
  same everywhere, so `WARDEN_CLUSTER_NAME` names the cluster in the plan.
  A run that ends `rollback_failed` or `apply_failed` trips the kill switch whatever ended it: only the
  rollback activity's own failure did, so a rollback past its timeout or on a worker that died left the
  switch off and later fixes ran (LOW-MED).
  P15 reads "0 free / remaining / left / passing" as a shortage only for a measure of capacity (memory,
  cpu, a pool, connections, probes): "queue: 0 remaining", "restarts: 0 left" and "connections: 0 idle"
  supported an action again (a regression from e94365a). The verify replay over 337 reports is unchanged.
  P14 takes a database or cache cluster the alert labels as the resource of a data action (clearing a
  cache, closing sessions, a failover, scaling) and as a whole scope only for an action on pods: the
  natural targets of clear_cache and terminate_connections on the recorded wave-4 alert were rejected (a
  regression from ac1e2ab). A failover never targets the alert's namespace or ECS/EKS cluster - by name,
  `namespaces/x` or the word - while a database named `orders-ns-db` passes. The verify replay over 337
  reports is unchanged.
  The stub of a withheld report redacts its alert id together with the blocked text, so an id that is a
  secret only in context is masked too. Inside a name, the gate looks past every code point a WHATWG URL
  parser drops from a host (270, not 4; measured on Node 22) and no longer past ZWNJ/ZWJ, which it keeps:
  removing them rewrote Persian text.
  The database platform's own login is refused in any letter case (MySQL and SQL Server match logins
  without it), and CI's live MySQL test now proves a session running a statement inside a transaction is
  never selected and idle time is what counts: removing the "sleeping only" filter passed every test.
  The proving ground's app deploy accepts only the database users Terraform derives for the stack's own
  environment - a shape check took another environment's names, or one name for all three. The
  service-account token test reads ReplicaSets and CronJobs too, and CI's throwaway Deployment mounts no token.
  The sixth review's "every secret-bearing pattern .gitignore names" was false: `plan.out` and
  `trust.local.json`, which .gitignore names, and tfvars.json, .netrc, kubeconfig, SQLite -wal files, SSH
  keys and key stores still shipped from a local build. Every one is excluded now, measured by building a
  wheel and an sdist from a copy with 29 names planted (21 shipped before, none now), and the image is
  built in two stages so no layer of it holds the source. Patterns are case-sensitive (`Server.PEM`).
  The proving ground's public API writes JSON access logs to `/aws/vendedlogs/warden-<env>-api-access`
  (A-I-13, logging half). The owner creates the account's one delivery policy for `/aws/vendedlogs/warden-*`
  in CloudShell (OWNER-CONSOLE-STEPS 2b), so the deploy role gets the log-delivery actions but never
  `logs:PutResourcePolicy`, which the boundary denies. Unproven live until the first window; the API's
  authentication is still open.
  Three tests that weaker code passed now fail it: the hook test judges each hook by itself (a fix
  taking all three whenever `sys.excepthook` is Python's - pytest's own case - passed), the fence test
  uses markers past 12 characters, and the weekly-audit test checks that its cron fires every week.
  A bad command-line argument is printed through the gate like every other error: argparse echoed it raw,
  so an escape sequence or a key typed on the command line reached the terminal (sixth review NEW-3, still
  present at the seventh). A usage error now exits 2 with one gated line.
  CI's k3d job waits for the API server to serve before its first kubectl call: k3d reported the cluster
  ready and the next call got ServiceUnavailable (CI on 71790df, a flake unrelated to the change).
  No role inside the boundary can share an EventBridge bus or the image registry outside the account
  (`events:PutPermission`, `ecr:PutRegistryPolicy`, `ecr:PutReplicationConfiguration` denied): the owner's
  IAM Access Analyzer reports the other ways out - role trusts, Lambda, SQS, SNS, ECR repositories, DynamoDB -
  but does not analyze those two. A role trusting another account can still be created (no IAM condition
  key covers a trust document); the analyzer reports it.
  Corrections to the sixth review's entries above: the register read "every row GitHub shows" only once
  e8d4f4c ended lines and tables where GitHub does; the guard judged a run "however its path is spelled" except
  a shell-expanded list of every file (still); it was "tested itself" but not its wiring until d3a9019;
  README's live-test counts went stale with efcf115 and are 33 (22 Kubernetes, 11 databases); the pinned
  "placeholder" was the full stack's ECS image. The audit's A-R7 section holds every seventh-review defect of
  medium-low and above with its commit, and A-R6 the rows it left out (R6-E1..E3, R6-B4).
  Still open (rows R7-O1..O4): a database session listed then killed without a re-check; P14's, P15's and
  the lag and hex-key name lists are open-ended by design, and the tripwire's unit tests use a spy; the
  admission policy bounds each request, not a series, and is unconfirmed on EKS; a mutation check killed by
  TerminateProcess leaves its mutation; transitive extras are not followed; the packaging excludes are
  case-sensitive; a role trusting another account can be created (the owner's Access Analyzer reports it).
  Each of the reader's scoped ARNs is checked against the format AWS's Service Reference gives its resource:
  the scoping test checked where each action sits, not its ARN, and seven format mutants passed (all fail now).
- **Infrastructure and IAM hardening, first part (G1-I)** (2026-10-01): EKS nodes' IMDS hop limit is 1,
  so pods cannot take the node role (A-I-12); the owner's address is a sensitive value in plans
  (A-I-14); the deploy role reads only `/warden/<env>/tf/*` parameters (A-I-17) and can no longer
  rewrite a role's trust (A-I-21); Terraform and every provider are bounded and CI's pinned version
  satisfies every bound (A-I-22); `aurora_express.py` acts only on the environment it is told and
  writes no region (A-I-23); no service-account token is mounted except in WARDEN's own Job (A-I-26).
  Then: the deploy role attaches only the eight AWS-managed policies Terraform uses (A-I-3); the
  guardrails that roles inside the boundary could break - public buckets, shared snapshots, images,
  secrets and logs, public function URLs, invoke by anyone - are denied in the boundary (A-I-3,
  A-I-20); `ec2:CreateTags` only on create, on the environment's own resources or its EKS cluster
  security group (A-I-7). The EC2 statements are a second deploy policy, `deploy-ec2.json`
  (`WardenEnvDeployEc2-<env>`): one would pass IAM's 6,144-character limit.
  The IAM template changes reach the live account in the next owner window.
- **Fifth independent review, fixed** (2026-10-01; rows A-R5 in the audit). Each with a test that fails
  without the fix:
  - Supply chain: Dependabot could not run uv (`required-version` is now a range CI's pin lies in); the
    deploy jobs restore no uv cache (uv does not re-verify unpacked entries); a local `.env` or log can
    no longer reach the wheel or the image; the wheel carries the LICENSE again (the "every file" claim
    of 00c08ab was false); the image is compiled to bytecode and keeps neither uv's cache nor the source
    copy; the deployed app and Lambda requirements are audited and the deployed code bandit-scanned where
    it changes; CI's image builds use the host network (the k8s job's build crawled; measured after: 97 s, from 264-320 s); the
    mutation check kills its workers on POSIX too.
  - Redaction: a shorter secret starting where a longer found value starts is masked again (a
    regression in e809f4b); the hex-key rule takes credential names only (it erased `cache_key=<sha>`
    from WARDEN's own deploy record); one credential gets one placeholder.
  - Workflow records: the signed end row says approved only with the tier's quorum; a success needs
    this run's apply; one alert is one incident - its workflow id is never reused, so the model budget is
    per incident.
  - Tags: `sqs/<q> dlq <MixedCase>`, `sns policy <queue>` and `eventbridge/<Rule>` keep their outcome.
  - Tripwire and verifier: WARDEN's placeholders are not scanned as injections; P15 no longer reads the
    next field as what was counted, reads "0s ago" and "then", and takes zero use as scale_down's
    evidence; P14 accepts the dashes, curly quotes and symbols of ordinary prose (a dash before a word is
    still a flag); lag units in more spellings, hours and CloudWatch's own names.
  - Records and owner steps: the full run fails if cited evidence did not run and pass; malformed
    register rows are errors; the GitHub steps say the ruleset's boxes are ticked by default, note the
    admin bypass, and cite the right test; the undo and trust-copy steps are clearer; R31 states its
    scope; the Postgres terminate integration test waits for the session to go.
  - Redaction cost: values nested past the finder's depth are split into shallow groups with a finder
    each, instead of being checked one by one against every segment - the reviewer's worst case (a comb
    of 8,008 values within the log caps) went from 126-144 s to 9.8-18.4 s a pass (two measurements under
    load); output identical.
  - P14: a second resource in parentheses or after an arrow is refused (an image to return to is not
    one); every cluster label scopes the target; a command after punctuation is refused; a failover may
    name its cluster.
  - The orphaned Dependabot `pip` pull requests (#5-#15) were closed with the owner's agreement.
  - Logging and Slack (area A): warnings, uncaught errors of any kind, errors in threads and in
    `__del__`, and a `SystemExit` carrying a tuple go through the log gate; a `~~~` block stays code in
    the Slack conversion; full-width dots are defanged; the stub of a withheld report cleans the alert
    id; a long record joined by any whitespace is cut, not withheld.
  - CI (area E, low): the path guard reads joined spellings (`ROOT / "k8s" / "fullstack"`); the Lambda
    build checks the requirements of the extras each Lambda asks for (`psycopg[binary]`); the k3s node
    image, k3d's tools image and the full stack's placeholder ECS image (terraform/fullstack/ecs.tf) are pinned by digest (read
    2026-10-01 09:45 UTC / 15:15 IST); a test keeps every push to main checked (no cancelled runs).
  - Register: the review-4 rows the fifth review confirmed are DONE-local (B-N1, B-N2, C-1, C-3, A-1,
    A-2, E-5, E-6); the others carry its verdict and stay open.
  - Still open: Dependabot does not renew the digests of workflow service images, `k8s/test` and k3d's
    images; downloads after cloud credentials in the deploy jobs are hash-checked but not ordered
    before them; quarantine spellings (an open-ended list); P14 still needs a label to know a bare name
    is a namespace or cluster; Temporal's own core logs to stdout ungated (no secret with WARDEN's
    codec); the link-label pattern is quadratic on a line of about 10,000 `[`.
- **One write path: the RemediationWorkflow and its platforms** (decision D16; audit A-B-H1..H3). The
  in-process live backends (`remediation_k8s.py`, `database_remediation.py`, `WARDEN_REMEDIATION=live`)
  are removed; `warden run --principal --approve` is a dry run. A live change goes through the
  workflow's signed approval of the exact plan, carried out by platforms a worker connects with
  `warden worker --platform k8s|db|all`:
  - Kubernetes (`platforms/k8s.py`): a rollout restart, or a scale up by at most two replicas, written
    only if the count is still the one just read - a count that moved since the approval is refused,
    where the old backend re-read and stepped. It reads one Deployment with `get`: the write
    ServiceAccount cannot list, and a first version that listed would have failed closed on every
    real cluster; CI now runs the platform impersonating that ServiceAccount. Rollout undo stays
    refused until an admission policy narrows the write (A-I-11).
  - Databases (`platforms/db.py`): sessions idle in a transaction, only in the connected database and
    only for the application's logins (`WARDEN_DB_APP_USERS`) - the old selection crossed every
    database on the server (A-B-H1). PostgreSQL, MySQL, SQL Server; Redis terminate is dropped (A-B-H3)
    and MongoDB's (which killed running operations, not idle sessions) with it.
  - The mutation check's seven mutations of the removed modules become nine of the platforms.
- **Every install is hash-locked and every image pinned by digest** (audit A-I-9, A-I-24; fourth review
  E). Deploy jobs ran unpinned `pip install` while holding cloud credentials. Now one `uv.lock` holds every
  version and hash - the package, CI's tools and the pipelines' helpers - and every workflow installs
  with `uv sync --locked` (a planted wrong hash is refused), with uv 0.12.21 pinned and its checksum
  checked, before any credentials. The package builds with uv's bundled backend, so no unpinned build
  tool is downloaded (the wheel holds the same files, plus one setuptools left out). The image installs
  from the lock; base images, CI service images and test workloads are pinned by digest; a
  `.dockerignore` allowlist keeps local files out of the build; the demo apps' requirements carry
  hashes. The vulnerability audit now covers every locked package (163), not only one job's install.
  Dependabot follows `uv.lock`. Still by tag: the proving ground's python:3.12-alpine (its faults
  change the tag on purpose).
  - Correction: the first push (00c08ab) turned every pipeline red - the lock predated the last
    dependency group, and `uv sync --locked` refused it. Fixed in 362356c; a test now compares the lock
    with `pyproject.toml` locally. CI · apps and CI · infra install from the lock but did not run when
    it changed; they do now, and a test keeps every path-filtered workflow that installs from it so.
  - The k8s job installs first (pip took 98 s; uv takes seconds), starts the OOM workload as soon as
    the cluster is up so its crash loop builds during the checks, and drops its teardown.
- **The GitHub settings the owner applies are written out** (`docs/OWNER-CONSOLE-STEPS.md`, G1-G5):
  environments deployable from `main` only, with approval for pre-prod, qa-prod and prod; a ruleset
  so `main` is never deleted or force-pushed; actions required to be pinned to a commit; Dependabot
  alerts and security updates; CodeQL default setup. Required status checks wait for a pull-request
  flow: with them, a direct push to `main` is refused.
- **The mutation check finishes again** (5236b21). It ran the whole suite serially for each of 35
  mutations - 17 minutes a run - so it no longer finished. Each mutation now runs the tests that name
  the mutated file, on parallel workers, and the whole suite only before reporting a survivor; a run
  past its limit is stopped with its workers and counts as caught, labelled. Run 2026-10-01 05:51 to
  06:13 UTC (11:21 to 11:43 IST): all 35 caught. (The commit message of 5236b21 says 06:40 UTC / 12:10
  IST; that was written before checking and is wrong.)
- **The register guard closes the fourth review's bypasses** (review D #3). A module-level
  `importorskip`, a multi-line `pytestmark` list, `from pytest import mark` aliases, an alias imported
  from a helper module, `xfail`, a citation the cell calls "NOT covered", and a DEFERRED cell saying
  "NOT owner-agreed" or dated 9999-99-99 all counted as evidence. Only decorators known never to skip
  are accepted, DEFERRED must start with a real past agreement, and `::test_x` shorthands are checked.
  Correction (fifth review): a source check cannot list every way pytest skips (a decorator over two
  lines, `raise unittest.SkipTest`, an empty parametrize, a skipping fixture...). The full run now checks
  the outcome itself: it fails if any test a DONE-local row cites did not run and pass (planted: a
  two-line `skipif` the source check missed fails the run, naming only that test). A row whose cell count
  does not match its header is now an error, not dropped: A-C-10's `ro||back` had split its cell, so the
  guard never read it and GitHub cut it short.
- **No hardcoded environment in the proving-ground harness** (9f16e30).
- **The publish guard catches personal email addresses** (`scripts/check_publishable.py`).
- **The proving ground tags `Project=warden` and `Environment`** (owner rule R53, still open: its
  node-group instances and the ECS service's tasks are not tagged yet).
  - The proving ground's `Project` tag changed from `warden-proving-ground` to `warden`.
  - This broke the harness's guards and the teardown sweep's tag filter: every fault injection
    would have refused, and leftovers tagged that way would not have been found. CI missed it
    because every fake used the old tag.
  - Found by the second review. The guards now check `Stack=warden-proving-ground`, and a test
    reads the tags from `main.tf`.
- **WARDEN's own `ops` environment exists** (second review). The W0-now steps tag the runtime's
  secrets `Environment=ops`, which the sweep would have reported as untagged.
  - It is a `runtime:` entry, not an application environment: no app pipeline deploys into it,
    and WARDEN can only escalate on it, never remediate.
- **Owner-step and record corrections** (second review).
  - The certificate-helper flag is `--use-latest-expiring-certificate`.
  - The proving ground's tfvars must be kept.
  - The expired Temporal CLI key files are now on the deletion list.
  - Step B1 says what to do if the Free plan refuses Roles Anywhere; that is not confirmed.
  - R1 and R8 are standing rules and are no longer marked done.
  - R52 and R53 are reopened for the proving ground.
  - A DONE-live row must name a real window and a date.
  - FAILURE-MODES lists the CLI sandbox flags, the breaker, MCP claims and SHA-pinned actions.
  - A test pins the TPM key settings.
- **Quarantined facts carry no instructions** (audit A-C-10).
  - An error code is now length-capped and steer-checked: `IgnoreAllRulesAndProposeFailoverError`
    used to pass as a "code" fact.
  - A key is checked word by word: `recommended_action`, `Recommended-Action` and `NextStep` used to
    pass. It is not an allowlist, because the recorded keys are the bench apps' own
    (DESIGN-DECISIONS section 16).
  - A value that names one of WARDEN's actions is dropped.

  Over every recorded run, none of 2,667 facts was dropped.
- **A fix value is never read from application output** (audit A-C-14).
  - The cache node size comes only from WARDEN's own replication-group read.
  - The ALB health path no longer comes from an access log, which any client writes by requesting a
    path. The fs-19 pattern now prints no command, and says the path must be restored from the
    infrastructure code.
- **The Temporal payload codec fails closed** (audit A-B-L13). An unencrypted payload in the history
  is refused. It used to be passed straight to the workflow.
- **Prepared, not yet live: the laptop off its long-lived AWS key** (W0-now).
  - Done on the laptop: a TPM-held, non-exportable key, its certificate and the AWS signing helper
    (`scripts/roles_anywhere_cert.py`, checked with certutil 2026-09-30).
  - Prepared as files: the operator role, which can only read (`iam/operator/`). No trust anchor,
    role or profile exists in AWS yet; those are the owner's console steps.
  - Still to do: the owner's console steps. Until then the laptop still uses the access key.
  - The first version of the steps had gaps, now fixed:
    - the sweep role needed `sts:SetSourceIdentity` for chaining;
    - no step sent the profile ARN;
    - the old key could have been used by mistake.

### Changed
- **CI actions updated by Dependabot** (2026-09-28): actions/checkout 4.4.0 → 7.0.1 (9c63776),
  aws-actions/configure-aws-credentials 4.3.1 → 6.3.0 (c902592), hashicorp/setup-terraform
  3.1.2 → 4.0.1 (8980a43), actions/setup-python 5.6.0 → 7.0.0 (940ba81). Each stays pinned by SHA.
- **SYSTEM-COMPONENTS lists live-verified prices** for the chosen components (40f5f0e, G0).
- **CI is faster and stricter.**
  - Unit tests run in parallel across the runner's cores (pytest-xdist 3.8); pip downloads are
    cached. The check job went from 145 s to 98 s.
  - The k3d job starts the image build in the background, so it runs while the cluster starts and
    pip installs. A BuildKit layer cache was tried first (e51fe1d) and measured SLOWER (the k3d job
    124 s -> 176 s, the docker job 32 s -> 47 s: loading the image out of BuildKit and exporting the
    cache cost more than the build), so it was removed with its Dockerfile change.
  - A newer push to a pull request cancels the run it supersedes; every job has a timeout.
  - k3d is a pinned release checked against a pinned SHA-256 (A-I-24); it was the install script from
    k3d's main branch, piped into bash.
  - A workflow scan (zizmor) runs on every change, including the infra and apps pipelines that
    hold cloud credentials: the tool pipeline's path filters skipped it for them (A-I-15).
- **The pipelines are laid out by purpose and by environment.**
  - `CI · tool`, `CI · infra`, `CI · apps`: each checks its own part on every change, with no
    credentials. `Scan · workflows` scans every workflow on every change.
  - `Deploy · <env>`: one workflow per environment (dev, staging, qa-staging, pre-prod, qa-prod,
    prod), run by hand, from `main` only (A-I-10). Each one picks infra (plan, apply or destroy) or
    apps (all, lambdas, ecs or k8s).
  - The steps live once in shared workflows (`_infra-*.yml`, `_apps-*.yml`). A test keeps the six
    deploy files identical apart from the environment's name, and matching `environments.yaml`.
  - No region is written into any workflow: each GitHub Environment carries `AWS_REGION`, the same
    as its role and state bucket.
  - Same-repository workflows are referenced with GitHub's self-repository syntax (`$/`, July 2026),
    which resolves at the running commit.

### ⚠ Correction to the entries above (independent review, 2026-09-28)

An independent adversarial review refuted most of the G1 fixes listed above: they were incomplete,
and one was a regression. The rows are reopened in `docs/AUDIT-2026-09-28.md`, each with the reason.
Each entry above is being corrected, and this note is removed only when the review's findings are
all closed. In short:
- **The codec change let any plain Temporal signal stall a workflow that had already changed
  production (A-B-L13).** This is a regression.
- **The redaction sweep change let short secrets survive in other lines (A-C-4).**
- **The gate and egress fixes left real bypasses (A-C-1, A-C-8, A-C-9):**
  - a zero-click image;
  - ungated `warden status` output;
  - raw alert text in the webhook JSON and MCP results.
- **Log text could still reach a trusted tool-error item (A-C-2).**
- **Several other checks were weaker than claimed (A-C-5, A-C-6, A-C-18, A-C-22, A-C-23, A-C-25).**
- **CI on main was red for four commits:** ab900cd and 54180fb before 0fcbfbb fixed them, then
  bdb8a13 and 5a753da (2026-09-28 18:32 and 18:55 UTC / 2026-09-29 00:02 and 00:25 IST) before
  e8278f2 fixed them. ab900cd and bdb8a13 were pushed after the previous run was green and failed on
  conditions only CI has (the k3d job; no torch). 54180fb and 5a753da were pushed onto the red main.
  (Corrected 2026-09-30: this note first said every push came before CI was green.)

### ⚠ Second correction (second independent review, 2026-09-30)

A second independent review of the fixes above found that several still did not hold. Some fixes
had also introduced new defects. The rows stay open in `docs/AUDIT-2026-09-28.md`, each naming what
was found. This note is removed only when a third review confirms the fixes.
- **The outbound gate created the structure it was meant to remove (A-C-1, A-C-9).** It decoded HTML
  entities and wrote the decoded text out. That turned `&#96;&#96;&#96;` into a real code fence and
  re-created the forged "approved fix" heading from an alert summary. An HTML comment also hid a
  fence from it.
- **The codec could still be stalled, or replayed (A-B-L13).**
  - A payload that claimed to be encrypted but was not stalled a workflow after it had changed
    production.
  - An encrypted approval from one workflow could be replayed into another.
- **Redaction depended on line order (A-C-4, A-C-5).** A secret found in a later line stayed in
  clear in earlier lines. It also false-matched common words such as "not" and "true".
- **The tripwire flagged WARDEN's own prompt header.** Scanning the whole prompt (the A-C-11 fix)
  made the real model flag 9 of 36 benign incidents.
- **`GOOGLE_GEMINI_BASE_URL` sent the Gemini key to any host (A-C-18).**
- **Records:** the proving-ground `Project` tag change broke the harness guards and the teardown
  sweep (a regression). The `ops` environment the W0-now steps tag with did not exist, and two owner
  steps named a wrong flag or a wrong file.

### ⚠ Third correction (third independent review, 2026-09-30)

A third independent review confirmed six fixes (A-C-1, A-C-5, A-C-12, A-C-14, A-C-22, A-C-26); their
rows are closed. It found that the others still did not fully hold. Each open row in
`docs/AUDIT-2026-09-28.md` names what was found. This note is removed only when a fourth review
confirms the fixes.
- **An approval could be replayed into a later run of the same workflow id (A-B-L13).** A kill switch
  tripped during the approval wait was also missed. Fixed in 024d32c.
- **The tripwire lost recall (A-C-11).** Joined into one text, real evidence in the same window
  diluted an injection in the alert summary below the threshold: 38 of 132 caught. It now scans each
  part on its own: 46 of 132 with the real model (2026-09-30), and 45 of 55 for the five payloads the
  model flags at all. The other seven score below 0.04 even alone: the detector is a tripwire, and the
  quarantine is what keeps log text from the model. No benign alert of 36 was flagged.
- **The outbound gate can still be led to write structure (A-C-9),** with residual egress gaps (A-C-8).
- **Partial:** tool-error tags (A-C-2, a regression in ea65387), redaction (A-C-4, A-C-23), P15
  (A-C-6, a regression in 45773cb), quarantine (A-C-10), provider settings (A-C-18), P5 and P14
  (A-C-25).
- **Records:** R11, R31 and A-I-18 said things that were not true. The register accepted a planned or
  negated window as DONE-live, and a test skipped through a marker alias, a module `pytestmark` or
  `importorskip` as evidence. Both are now refused.
- **CI on main was red a fifth time,** at ea65387: a ruff finding shown as a "hidden fix" was not run
  to zero before the push. Fixed in 7d175af.
- **...and a sixth and a seventh time** (found by the fourth review and by CI): at 584e89a (2026-09-30
  10:34 UTC / 16:04 IST) the MCP stdio test raced, closing stdin before the answer; fixed in 4a2caa9.
  At 14e32e1 (14:18 UTC / 19:48 IST) parallel test workers raced to download Temporal's test server;
  fixed in a1b73ce, which downloads it once before the workers start. The control is branch
  protection with required checks (owner steps, A9).
- **...and an eighth and ninth time, both mine, on 2026-10-01:** 00c08ab (07:15 UTC / 12:45 IST) pushed a
  uv.lock older than pyproject.toml, which `uv sync --locked` refused in every pipeline (fixed in
  362356c, with a test that compares the two locally). c99bc86 (07:23 UTC / 12:53 IST) added two
  trigger paths after running only the CI tests, not the full suite; a test pinning those paths
  failed (fixed in 83f65e6). Rule kept from here: the full suite before every push, however small the
  change. A tenth followed at 83f65e6 (07:29 UTC / 12:59 IST): CI · apps builds the Lambda zips with
  pip, which a uv environment lacks, and no local run builds them; fixed in ce1051c (pip locked in
  both apps groups, a test tying the script to them, and a hash-checked `--no-deps` install that also
  builds on Windows). An eleventh at 418113b (09:15 UTC / 14:45 IST): CI · tool, a race in the
  forged-success test - its forger polled the queue before `check_success` was scheduled and could
  take `apply` itself - which also held the job for ten minutes; fixed in 1ee7ca3.

## [0.10.0] - 2026-09-28

### ⚠ Correction (added 2026-09-28, after release)

This release was announced as "Phase 2 done". **That was false.** On the same day, a full audit found
the following. The tag is kept; fixes ship as 0.10.1 and later, in order of risk:

- **Failure-mode register:** 1 of the 22 rows assigned to Phase 2 was done with a test. The rest are
  open, including false recovery, feedback loops, a mislabelled environment, alarm storms, fighting
  other automation, no degraded mode, a mutex on a free-text name, freeze windows, and no versions
  in the audit.
- **Defects in the RemediationWorkflow shipped here:**
  - a failed rollback ends without an audit record;
  - activities retry forever;
  - the policies P1–P16 are never run;
  - there is no environment on the request;
  - `request_remediation` is not bound to an incident or its verdict;
  - the kill switch is not re-checked before apply;
  - the "at most 2 model calls" cap is not enforced (up to 6);
  - scale is not limited to 50%.
- **Earlier phases:**
  - the quarantine does not fully hold: untrusted text still reaches the model through tool-error
    items, forged log-stream names, the alert text and the environment field;
  - the outbound gate covers Slack only (JSON report, stdout and MCP results are ungated);
  - the in-process live remediation paths trust a typed environment and principal;
  - DB "terminate connections" ignores its target;
  - some tests pass even with their guard removed.
- **Infrastructure design:**
  - per-environment IAM isolation can be broken (`rds-db:connect` has no tag condition key);
  - the deploy role can attach a managed policy to a role it creates;
  - CI apply would fail on two missing permissions.

  Nothing is deployed; no live system was exposed.
- **"Drift means a new plan"** below was wrong: the code ends the workflow as `drifted`. Re-plan
  with a fresh approval is being built.

Every finding, with its fix and test, is in `docs/AUDIT-2026-09-28.md`, and the plan
(`docs/ROADMAP.md`) closes each one. A new CI test fails whenever something is marked done without
the test that proves it.

v2 re-architecture, Phase 1.5 and Phase 2 (partial, see the correction above). Every environment is configured by name, with no key
stored anywhere. A fix is a durable workflow that a person must approve with their own signature.
That workflow applies the fix once and checks the result itself, and every step is recorded
tamper-evidently.

### Added (Phase 2)

- **Temporal workflows** (self-hosted OSS; `workflows.py`, `activities.py`):
  - `IncidentWorkflow` runs the diagnosis nodes as three activities: `prepare`, `diagnose`
    (the one model call, on redacted input only) and `verify` (no model).
  - `RemediationWorkflow` steps: plan against live state → bounds → signed approvals until
    the TTL → live re-check (drift means a new plan) → apply once → its own success check →
    rollback.
  - Completion comes only from the workflow's checklist; there is no input for success.
- **Encrypted workflow history** (`codec.py`): every payload is encrypted with AES-256-GCM, and
  failures are encoded. Without it, the raw alert (a workflow input) was readable in the history.
- **Tamper-evident audit** (`audit.py`):
  - append-only SQLite with a hash chain;
  - Ed25519-signed checkpoints, which catch an edited row even when the chain was recomputed;
  - `warden audit keygen` / `warden audit verify`.
- **Signed approvals** (`approvals.py`):
  - each one binds one plan hash of one workflow, at one tier;
  - it expires and can be used once;
  - T3 plans need a cooling-off period;
  - a two-person rule counts different approvers only.
- **Bounds, kill switch and circuit breaker** (`bounds.py`), with their state in the audit log.
  A reset needs a signed approval of that specific trip.
- **Remediation catalogue** (`catalog.py`): 14 entries.
  - Every target must be a value WARDEN read from live state.
  - Numbers are clamped against live values.
  - Queue purges, IAM writes, Secret applies, deletes, raw SQL and shell are excluded.
- **CLI**: `warden worker`, `incident`, `status`, `approve` (signs only the plan hash you
  reviewed) and `killswitch`.
- **MCP**: `start_incident_diagnosis`, `request_remediation` and `workflow_status`.
  - No tool can approve, sign, reset or execute.
  - No parameter looks like a credential.
  - The tool manifest is pinned by a sha256.

### Added (Phase 1.5)

- **Per-environment everything:**
  - `environments.names(env)` derives every name;
  - IAM templates are rendered per environment, with a boundary meant to deny every other
    environment (it does not yet: see the Correction above, `rds-db:connect` and untagged
    resources);
  - Terraform workspaces are environments;
  - deploy workflows take an `environment` input;
  - settings come from SSM Parameter Store (`settings.py`, with an allowlist).
- **Network**: only the NAT is public. The ALB is internal, and compute runs in private subnets.
- **Tags**: `Project` and `Environment` on everything the stack creates, including EKS nodes and
  disks, the cluster security group, ECS tasks and task definitions.
- **`scripts/account_sweep.py`**:
  - lists everything that can bill, in every region, without trusting tags;
  - audits `Project`/`Environment` tags;
  - reports what it could not see as BLIND.

  It runs as the read-only role `warden-pg-sweep`.
- **Injection tripwire** (P16): Meta Llama Prompt Guard 2 (86M), optional and run locally.
  - 0 false alarms in 4,637 real lines.
  - It catches 6 of the 14 corpus payloads; quarantine and the gate cover the rest.
- `check_publishable` also refuses Slack trigger, Teams and Power Automate webhook URLs, and Hugging
  Face tokens.

### Removed

- LangGraph. `graph.run()` is a plain pipeline over the same nodes. A parity test shows identical
  results to the IncidentWorkflow on every bundled incident.

## [0.9.0] - 2026-09-27

v2 re-architecture, Phases 0 and 1: nothing AI-written runs unapproved, and what the model says is
checked against what it was shown.

⚠ Work between 0.8.0 and this release (P11/P12 on 2026-09-25, the EKS/RDS/full-stack waves, the stack
backend) has no entries of its own here. It is recorded in `docs/`, `docs/bench/` and git history.
0.7.0 and 0.8.0 were never tagged.

### Security (Phase 0)

- The `claude_cli` model process gets an allow-listed environment. AWS keys, DB DSNs and kubeconfig
  no longer reach it.
- Fix commands are printed only for an `approved_for_human` verdict. Escalated commands are listed
  as NOT APPROVED, and rejected ones not at all. Nothing builds an IAM grant or an index from log
  text any more.
- The benchmark harness refuses to execute a non-approved fix, and no longer allows
  `sqs purge-queue`, `iam put-role-policy` or Secret apply.
- Outbound gate v0 (`gate.py`):
  - G3 strips markdown images, links, URLs and HTML outside code blocks.
  - G5 withholds a message that still carries a secret.
  - Slack unfurling is off.
  - A log line can no longer close the evidence code fence.
- MCP `verify_remediation` caps its verdict at `escalated`: the caller claims the evidence counts,
  WARDEN never reads them.

### Added (Phase 1)

- **Evidence ids** (`evidence.py`): L log, E event, M metric, D deploy, C config/state read, T
  failed read, F typed fact.
- **`P13-UNGROUNDED`**: every citation must name a real id and quote it verbatim.
- **`P14-TARGET-NOT-IN-EVIDENCE`**: the target must name a known resource. Seen live on 2026-09-26:
  `lambda:shop-prod-checkout`.
- **Quarantine** (`quarantine.py`): log lines, events, SQL and source reach the model only as typed
  facts of fixed shapes, never as text.
- **G2**: "no customer impact" and "resolved" in model text are marked `[unverified: ...]`. Reports
  show the cited evidence, and say "Not grounded" when P13 fired.
- `scripts/replay_diagnose.py`: re-diagnose a published run's recorded evidence with today's
  pipeline, and score it with the frozen rubric.

### Changed

- **One model call per incident.** `analyse` and `propose` became a single `diagnose` node.
- Measured by replaying 30 recorded incidents on Claude Max, raw lines vs typed facts:
  - 17/30 correct in both arms
  - wrong-and-allowed went 1 → 0
  - input tokens −62% on the ECS wave, −28% on EKS
  - no P13/P14 fire in 60 diagnoses

  A replay, not a live measurement (`docs/ai-boundary.md`).

## [0.8.0] - 2026-09-12

The gate stops taking the model's word for anything that could loosen it.

### Fixed

- ⛔ **Two of the nine policies read fields the MODEL wrote, in a gate whose entire claim is that
  the model does not decide.** `P2-IRREVERSIBLE-IN-PROD` fired on `proposal.reversible` and
  `P6-BLAST-RADIUS` on `proposal.blast_radius`. A proposal claiming `reversible: true` therefore
  **widened its own permissions**, and the same operation got opposite verdicts from two models: a
  prod-database `terminate_connections` was rejected under Gemini (`reversible: false`, 0.85
  confidence) and merely escalated under Claude (`reversible: true`, 0.45). Recorded as a known
  inconsistency in `docs/live-model-run-2026-09-06.md` §3 since September — *"Neither change is made
  yet"* — and measured, but not fixed, for two releases.
  - `models.py::ACTION_FACTS` is now the gate's own classification of its nine actions:
    `(reversible, blast-radius floor)`. `failover_replica` and `scale_down` are irreversible; a
    rollback is a forward deploy of a previous revision and is not. Deliberately not
    operator-configurable — a config file is only a different author for the same field.
  - **P2 reads the table and nothing else.** P6 takes the wider of the table's per-action floor and
    the claim, so a model may tighten the gate by widening its own blast radius but understating it
    buys nothing.
  - **New `P10-CLAIM-CONTRADICTS-TABLE`**: the proposal warns an action is irreversible while the
    table says otherwise → escalate. Without it, moving to a table-only P2 would have *loosened*
    the gate for a model that warns us. `rejected` and `escalated` both mean nothing runs.
  - **The MCP server was the worst case**: `verify_remediation` builds a proposal from *untrusted
    caller* arguments, so any client skipped P2 by sending `"reversible": true`. It now gets the same
    table, and the response echoes `reversible_by_table` / `blast_radius_enforced` so a caller can
    see it was overruled.
  - **P2 could never fire in mock mode**, which is what CI and the evals use: the mock hardcodes
    `reversible=True` for every action, `failover_replica` included. The mock is deliberately left
    as it is — it makes exactly the wrong claim a real model makes, and the table overruling it is
    the demonstration. `inc-003` in the demo and the eval suite is now REJECTED rather than
    escalated, which is strictly stronger.
- ⛔ **`no_action` skipped every evidence policy, so "nothing is wrong" could not be challenged.**
  On a real AWS account, 14 of 42 runs answered `no_action` about a service with a live fault and the
  gate allowed every one — two at 0.25 confidence while their own `tool_errors` recorded that WARDEN
  could not read the logs. The exemption is now split: `AUTO_SAFE_ACTIONS` still decides who skips
  *approval*, and a new `EVIDENCE_EXEMPT_ACTIONS` — `escalate_to_human` alone — decides who skips
  the *evidence floor*. Handing an incident to a person is the right answer to weak evidence;
  claiming there is no incident is not. P3 keeps the wider set on purpose: "rejected, you may not
  conclude nothing is wrong" is not a verdict an operator can act on, and P9 catches the same
  condition with a verb that makes sense.
  **Replaying the published reports through the new gate: 12 of those 14 are refused, 2 are not, and
  3 runs where `no_action` was correct now escalate.** All three numbers are in the README.

- ⛔ **The ECS evidence could not see tasks dying in a loop.** `metrics()` derived
  `deployments_failed` from `rolloutState == "FAILED"`, which ECS sets only when the deployment
  circuit breaker is enabled — the proving ground does not enable it, so that metric was
  structurally always 0. Meanwhile a revision whose tasks crash on startup is retried indefinitely:
  the old tasks keep serving, so `runningCount == desiredCount`, nothing is pending, and nothing is
  marked failed. On the published wave that evidence made a broken service look healthy and two
  fault classes were answered "no action needed" 3/3 each. `deployment_failed_tasks` now sums
  `failedTasks` across the deployments in the **same `DescribeServices` response** the backend
  already reads — no extra API call, no extra IAM action, so the policy⇄code parity test is
  untouched. ⚠ The published Wave 1 numbers were measured **before** this, and re-measuring means
  rebuilding the proving ground and running the wave again; it has not been done.

### Added

- `scripts/replay_gate.py` — re-decides published report JSONs with today's policy, by calling the
  real `verify()` rather than a reimplementation. It prints, unavoidably, that **a replay is not a
  measurement**, and refuses to write its JSON inside a run directory where it could be mistaken for
  a score.
- A mutation that flips `failover_replica` to reversible in the table: P2 now reads one tuple, so a
  one-line diff could quietly make the only irreversible action it can reach in prod executable
  again, with every policy still present and every other test green.

### Changed

- `reversible` and `blast_radius` stay **required** in the model-facing schema but are documented as
  advisory, and reports now carry the claim *and* what was enforced side by side. The
  `reversible` flip-rate in `scenarios/score.py` therefore changes meaning: from 0.8.0 it measures
  the model's self-consistency instead of a flaw in the gate. It is kept, because a model that
  cannot describe the same action twice the same way is worth knowing about.
- **The Wave 1 numbers in `docs/bench/` are left exactly as measured under 0.7.0.** Re-scoring them
  against a gate that did not exist when they ran would be inventing a result. The dated records
  that prompted these fixes — `live-model-run-2026-09-06.md` §3, `scenarios/scoring.yaml`'s rubric
  correction, `docs/bench/README.md` — are annotated, never rewritten.

## [0.7.0] - 2026-09-12

The release where WARDEN was measured against a real AWS account instead of described. The
benchmark found bugs in the tool, and two in itself, and everything below is published rather than
summarised: both runs, their rubrics, their hashes and the scorer are in [`docs/bench/`](docs/bench/README.md).

### The measurement

14 fault classes injected into a real ECS Fargate service in `ap-south-2`, 3 runs each, Claude
Sonnet through the `claude` CLI, every run as a 4-action read-only role. Evidence, diagnosis and the
gate scored separately; the rubric committed before the run with its hash in the manifest.

> **20 CORRECT · 5 SAFE-BUT-UNHELPFUL · 14 WRONG · 3 NO-EVIDENCE** — and the number that matters:
> **14 runs proposed `no_action` on a service with a live fault, and the gate allowed every one.**

- **The gate cannot catch "nothing is wrong."** `no_action` and `escalate_to_human` skip every
  policy check by design, so a wrong `no_action` is never refused and never needs approval. Two runs
  closed the incident at 0.25 confidence while their own `tool_errors` recorded that the logs could
  not be read. Published as a design limit, not patched into a better number after the fact.
- **The AWS evidence omits the clearest failure signal there is.** `aws_backend.metrics` derives
  `deployments_failed` from `rolloutState == "FAILED"`, which only ever fires with the ECS
  deployment circuit breaker enabled, and ignores the `failedTasks` count `DescribeServices` already
  returns per deployment. So a service whose new tasks were dying in a loop was reported as
  tasks-at-desired-count, nothing pending, nothing failed. **Open work**, named in the README.
- **A completed rollout hides its own deploy.** Deploy detection compares images against the
  replaced deployment; once a rollout finishes there is nothing to compare, so `ecs-08` scored
  NO-EVIDENCE 3/3 rather than being graded as a model failure.
- **The model is not deterministic.** 8 (7 - recounted from results.json 2026-09-25) of 14 scenarios disagreed across three identical repeats,
  including the healthy control, where one run escalated a service with nothing wrong.

### Added

- **`scenarios/` — the fault-injection benchmark.** Real faults (`ops.py`), a wave runner that
  injects, measures, reverts and refuses to continue on a failed revert (`runner.py`), and an
  offline scorer that never imports WARDEN and never reads the hypothesis text (`score.py`). The
  rubric is data (`scoring.yaml`), argued in prose (`SCORING.md`), and a perfect score is stated to
  be a bug report.
- **`terraform/proving-ground/` — a throwaway account to break.** ECS Fargate (Spot optional), a
  4-action reader role, a budget guard, and an operator IAM user with no console access. RDS and EKS
  are opt-in and unused so far.
- **A live AWS backend** (`aws_backend.py`): CloudWatch logs and metrics, ECS service state and
  deploy detection, with every window and cap configurable and bounded.
- **A `claude_cli` provider**, so a run can go through a Claude subscription instead of an API key —
  with the operator's own config deliberately stripped from its environment.
- **`scripts/`**: `publish_bench_run.py` (redact, verify with the repo's own scanner, then copy),
  `teardown_sweep.py` (what Terraform never knew about), `check_iam_actions.py` and
  `validate_policies.py` (AWS's own validator), `prove_boundary.py` and `apply_operator_policy.py`.
- **A permissions boundary, proven live.** `prove_boundary.py` grants the operator, in its own
  policy, the right to edit the boundary and to replace its own boundary — and both stay denied,
  5/5, with a positive control so no denial can be mistaken for propagation delay.

### Changed

- ⛔ **The rubric was corrected after a run, in the open.** It graded `no_action` on a broken
  service SAFE-BUT-UNHELPFUL because "a human gets it". That is false: the verifier exempts
  `no_action` from every policy and the graph records it as `auto_safe`, "approval: not required" —
  nobody is paged. `no_action` is now WRONG unless it is the right answer. Which passives count as
  safe is rubric data, so a rubric predating the key still reproduces its own numbers, and the
  affected run is published under **both** gradings.
- **A wave now waits 18 minutes before every inject** and pins WARDEN's evidence window in its
  environment, because scenarios were reading each other (below). A wave takes ~7 hours.

### Fixed

- **Scenarios read each other's evidence.** WARDEN reads logs 15 minutes around the alert; the
  runner left 0.1–5 minutes between one scenario's revert and the next inject, so **39 of 42 runs**
  in the first full run were graded partly on the previous scenario's fault and recovery. The runner
  now isolates the evidence as well as the state, and the scorer flags any overlapping run. The
  clean re-run has 0 of 42 — and shows the leak changed `ecs-09`'s answer and did *not* change
  `ecs-06`'s, which guessing would have got wrong in both directions.
- **Deploy detection compared revision N with N−1** instead of with the deployment actually being
  replaced, so a rollback was proposed for a service whose rollout had simply not finished.
- **The `claude` CLI was spoken to in the Windows code page**, so any prompt containing an em dash
  or an arrow arrived garbled; every run before the fix was superseded and re-run.
- **A diagnosis could be lost to `print`.** The CLI wrote its report *after* printing it, so a
  console that could not encode a character threw away the result it had already paid for.
- **An exhausted model provider was retried three times and then mistaken for a tool failure.**
  `ProviderExhausted` is now fatal, recognised from the CLI's real wording ("session limit"), and
  the wave stops cleanly and resumes with `--resume` instead of injecting faults it cannot measure.
- **A redacted placeholder blinded the secret scanner to the real secret beside it.**
- **Hashes differed between a CRLF and an LF checkout**, so a rubric that had not changed looked
  tampered with. Content is hashed LF-normalised.
- **`teardown_sweep` died on AWS throttling** after deregistering 38 of 45 revisions, leaving 7
  behind and a traceback where the verdict should have been. Destructive calls now wait a throttle
  out; anything that is not a throttle is still re-raised, so a permission error can never be
  retried into looking like success.
- **Six IAM and Terraform defects** a real apply found: a non-existent action name accepted by no
  console, a global action under a region condition, a duplicate `Sid`, a missing tag permission,
  `timestamp()` in `default_tags` breaking every saved-plan apply, and an example file that switched
  EKS on.

### Testing

- **676 tests and 25 evals.** Every fix above was planted back out and its test watched go red
  before being kept — including the ones that would otherwise pass against a fake.

## [0.6.2] - 2026-09-06

### Fixed

- ⛔ **0.6.1's own fix was wrong, and a real cluster caught it.** Conditioning the scale patch on
  `metadata.resourceVersion` looked correct and passed every unit test against a fake client. It
  fails on a live Deployment: the Deployment controller writes `status` continuously, so
  resourceVersion moves for reasons that have nothing to do with anyone touching `spec`. CI's
  live-cluster job rejected the very first attempt with *"Operation cannot be fulfilled … the object
  has been modified"*.
  The condition is now on the field that actually matters — a JSON Patch `test` op on
  `/spec/replicas` — and a conflict re-reads and recomputes the target, bounded by
  `WARDEN_REMEDIATION_SCALE_RETRIES` (3), raising if it never wins. That is both the idiomatic
  Kubernetes pattern and the semantically right one for a *relative* step: if something else scaled
  to 5 while we were deciding, stepping from 5 is correct and stepping from the stale value is not.
  Nothing is clobbered, because the target is always derived from a fresh read.
  ⭐ The lesson is the project's own: a guard that passes against a fake proves the request was
  made, not that the outcome is right. Only the live job could tell the difference.

### Testing

- **393 tests.** Three tests now cover the scale path: the write is conditional on the count that was
  read, a conflict re-reads and recomputes from the new value, and sustained contention raises
  loudly rather than looping or silently doing nothing.

## [0.6.1] - 2026-09-06

⚠ **Tagged but never released — its scale fix regressed the live-cluster job. Use 0.6.2.**


### Fixed

- **`scale_up` / `scale_down` could silently overwrite a concurrent change.** `_scale` reads the
  Deployment to compute a target from the current replica count, then patches it — a read-then-write
  with no precondition, so anything that changed the Deployment in between (a HorizontalPodAutoscaler,
  another operator, a person with `kubectl`) was clobbered. The patch now carries the observed
  `metadata.resourceVersion`, so the API server rejects the write with 409 Conflict instead and the
  backend surfaces a clear refusal rather than a generic failure. Two tests pin it: one asserts the
  precondition is actually sent, one asserts a conflict is refused and nothing is patched.
  ⚠ The relative `current + SCALE_STEP` step is deliberate and unchanged — "scale up one step" is the
  action an incident responder means — so a duplicate alert still compounds, bounded by
  `WARDEN_REMEDIATION_MAX_REPLICAS`. That is documented, not fixed here.
- Found while writing an answer to "what happens if the same alert arrives twice?", which is a fair
  argument for writing the awkward answers down.

### Testing

- **392 tests** (345 unit + 22 opt-in live, 25 evals, 10 live-cluster, 12 live-database).

## [0.6.0] - 2026-09-06

⛔ **The `0.5.1` tag was 37 commits behind this content.** Everything below already existed on
`main` under the version string `0.5.1`, so anyone cloning the published release got a differently
named package (`src/aegis/`) with 52 files and 14 mutations. This release exists so that the
version number and the code agree. **If you read a description of WARDEN that cites 390-392 tests,
31 mutations or five database engines, this is the release it describes.**

### Changed — BREAKING

- **The project is renamed AEGIS → WARDEN.** The import package moved `src/aegis/` → `src/warden/`,
  the console scripts are `warden` and `warden-mcp`, and every environment variable is
  `WARDEN_*`. There is no compatibility shim: this is a pre-1.0 rename.

### Added

- **A live Kubernetes remediation backend** — a real Deployment restart or scale, clamped (never
  below 1 replica, never above `WARDEN_REMEDIATION_MAX_REPLICAS`), on its own write-scoped RBAC
  separate from the read path. Opt-in behind `WARDEN_REMEDIATION=live`; the default backend still
  changes nothing.
- **Read-only health backends for five database engines** — PostgreSQL, MySQL, Redis, MongoDB and
  SQL Server — plus a gated `terminate_connections` write path that kills only connections stuck
  idle-in-transaction beyond a threshold, count-clamped, never its own connection, on a separate
  least-privilege credential. All five run against real engines in CI as service containers.
- **An environment policy engine** (`environments.yaml`): per-environment allow/deny action lists,
  principal authorisation, and an `auto_remediate` flag. **Fails closed** — an unknown environment
  gets the most restrictive row, not the most permissive.
- **The four-way remediation gate** — an action is applied only when an auto-remediate environment,
  an authorised principal, an explicit approval and an armed backend all hold. `prod` never
  auto-applies.
- **A researched incident-signature knowledge base** (34 signatures) with a deterministic matcher.
  ⚠ Wired to report annotation only; it does not yet influence the hypothesis or the verdict.
- **ChatOps egress** with a redacted report, proven over a real socket.
- **A per-environment `credentials_ref`** so an environment can name its own account pointer.

### Fixed

- **A long redaction-hardening series.** Added masking for private keys, database credentials, AWS
  secret and STS (`ASIA`) keys, bearer tokens, HTTP Basic auth, kubeconfig client keys and
  certificates, session cookies, npm `_authToken`, `github_pat_`, MAC addresses, IBANs, grouped
  credit-card numbers, GCP and Azure secrets, URL-encoded email, and query-parameter, JSON-body and
  webhook credentials. Redaction is recursive over JSON on egress.
- **Three leaks closed on paths the first fix missed** — the MCP server's `recent_deploys`,
  `RunReport.context`, and tool error text before it reaches the audit trail and telemetry spans.
  The same leak on a second code path is the reason the guard re-scans its own *output* rather than
  trusting the substitution.
- **`resolve()` no longer mutates the global environment**, which had been silently leaking an
  endpoint across providers.
- **Permanent provider errors now fail fast** with an honest attempt count.
- **A NaN/inf metric no longer crashes the run.**
- **The read-only database tripwire was green and blind.** Its AST check collected only string
  literals passed *directly* to `.execute()`; every adapter hands its SQL to a helper, so the
  collector returned an empty list and the test asserted `not []`. Found by the mutation check, not
  by review. The checker now follows the indirection, two tests pin it, and a full re-run reports
  **31 caught, 0 survived**.
- **`remediation.py`'s module docstring** claimed the only backend shipped was `DryRunBackend` and
  that "this codebase never mutates a cluster". Both stopped being true when the live backends
  landed.
- Corrected a stale test count (388, measured) and a documentation reference that cited the
  redaction leak-guard test by a name it no longer had.

### Testing

- **390 tests**: 343 unit (+22 opt-in live tests that skip without infrastructure), 25 evals,
  10 against a live k3d cluster, 12 against five live database engines. Across CI nothing is
  skipped — the `k8s` and `db` jobs fail if their tests skip.
- **A 31-case mutation check** (`scripts/mutation_check.py`) that breaks the code deliberately and
  requires the suite to go red for each. Latest run: 31 caught, 0 survived.
- **CI asserts on output, not exit codes** — the container and cluster jobs check the verdicts the
  tool actually prints, because a green exit code once hid a run where every tool had failed.
- **RBAC is asserted both ways from the API server**: the five reads the code makes are allowed;
  writes, secrets, unused read verbs, other namespaces and cluster scope are denied.

## [0.5.1] - 2026-08-22

The last release made under the name **AEGIS**, package `src/aegis/`. Kept for history; prefer
`0.6.0`.
