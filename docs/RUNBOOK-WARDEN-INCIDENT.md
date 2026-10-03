# Runbook: when WARDEN itself is the incident

For incidents WARDEN causes or suffers: a change it applied made things worse, it may be acting on injected text, its
model behaves strangely, its record may have been tampered with, or it is down. Organised on the NIST incident
lifecycle as the Coalition for Secure AI's *AI Incident Response Framework* v1.0 adapts it for AI systems
(coalitionforsecureai.org, OASIS Open; read 2026-10-03). Every `warden` command below is checked against the real
command line by `tests/test_runbook_commands.py`.

Times: give every time in UTC and in the install's display zone (IST here), as WARDEN's own reports do.

## 0. First minute, whatever happened: stop all changes

```
warden killswitch on --reason "WARDEN incident: <one line>"
warden killswitch status
```

The kill switch is checked inside every apply, right before the change; with it on, nothing WARDEN plans is applied,
and only a signed approval resets it. Diagnosis keeps running and keeps reporting: a person decides with it, not
WARDEN. (The cloud deployment adds an AWS deny policy as a second switch that does not depend on WARDEN; G6.)

## 1. Preparation (before any incident)

- The approver keys and passkeys are enrolled, and the break-glass Ed25519 key is passphrase-encrypted.
- The audit's public key is kept apart from the worker, and the S3 anchor bucket (register S12) is configured.
- This runbook and `docs/OWNER-CONSOLE-STEPS.md` are where the on-call engineer can open them without WARDEN.
- What to keep for an investigation: the audit database, the Temporal workflow histories (encrypted; the codec key
  is in Secrets Manager), and the model's recorded prompts and answers (by hash in `llm.call` rows).

## 2. Detection and analysis

Signs that WARDEN is the incident:

| Sign | Where it shows |
|---|---|
| A fix made things worse | the run ended `relapsed`, `rolled_back` or `rollback_failed`; the breaker tripped the kill switch; a GitHub change record (O9) |
| WARDEN may be acting on injected text | policy `P16-SUSPECTED-INJECTION` on a verdict; quoted text steering toward an action in a report |
| The model behaves strangely | many escalations at once (the escalation SLO, N6), the same wrong action repeated, a model change in the `llm.call` rows |
| The record may be tampered with | `warden audit verify` reports a broken chain, a bad signature or a checkpoint that differs from its anchor |
| WARDEN is down | no Slack thread for a firing alarm; no heartbeat (G6); Temporal shows no worker polling |

Check the record first: it is what every other answer rests on.

```
warden audit verify --db <audit.db> --public-key <audit.pub> --anchor-bucket <bucket>
warden audit show <incident-id> --db <audit.db> --public-key <audit.pub>
warden status <workflow-id>
```

`audit verify` recomputes every hash and checks every signature and anchor; `audit show` lists one incident's rows
with their hashes, the same hashes WARDEN's Slack footers cite (S17), so a message claiming to be WARDEN's can be
matched to the record or exposed as forged.

## 3. Containment, eradication and recovery

- **A fix made things worse.** With the kill switch on, put the target back by hand to its recorded snapshot (the
  `remediation.plan` and `remediation.rollback` rows hold what it was). Do not let WARDEN retry.
- **Injected text.** Find the evidence item the tripwire flagged (its id is in the verdict), find its source (a log
  line, an event, a description field), and remove or quarantine it at the source. WARDEN never executed text: a
  closed catalogue and a signed approval stood between it and any change - confirm in the audit that no approval
  was signed for the suspect plan.
- **The model.** Pin the previous qualified model (`data/providers.yaml`), or stop model calls entirely: without a
  model WARDEN escalates every incident on its rules alone (register M19). Re-qualify before using a model again.
- **Tampering.** Stop the worker. Keep the database file as it is (copy it, do not repair it), and compare it with
  the S3 anchors, which cannot be rewritten; rotate the audit key, and anything the attacker could have reached.
- **WARDEN down.** Incidents go to people directly: the alarms page as they did before WARDEN. Start the worker
  again (`warden worker`), and check the clock (`warden worker` refuses to run with a skewed clock, O6).

## 4. After the incident

- Reset the kill switch only with a signed approval, after reading every trip it lists:

```
warden killswitch reset --approver <you> --key <your.pem> --trips <n>
```

- Write down what happened, with times in UTC and the display zone, and the audit hashes that prove it.
- Add the case to the register (`docs/FAILURE-MODES.md`) with a test that fails without its fix, and plant-check it.
- If a policy would have caught it, add it in observe mode first (audit A-P-8), measure it, then enforce it.
