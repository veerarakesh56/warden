# WARDEN AI policy (register CW1)

This is the written policy for how WARDEN, an AI system, may be used, changed and stopped. It applies to every
install. Who does what is in `RACI.md`; how it can go wrong and what holds it is in `IMPACT-ASSESSMENT.md` and the
register (`docs/FAILURE-MODES.md`).

## Purpose and scope

WARDEN diagnoses production incidents and proposes one remediation from a closed catalogue. It is decision support
for on-call engineers. It is not an autonomous operator.

## Principles

1. **A person decides every change.** Nothing WARDEN proposes is applied without a signed approval of that exact
   plan (passkeys, H6). No automatic tier is enabled until a shadow precision's Wilson lower bound reaches 0.90
   (E5); none is enabled today.
2. **The model proposes; rules decide.** A deterministic gate, not the model, decides what happens (policies P0 to
   P33); new policies run in observe mode, recorded but not obeyed, before they are enforced.
3. **Evidence, not assertion.** Claims cite evidence verbatim (B1, B2), numbers are checked against the metrics
   (M2), and untrusted text reaches the model only as typed facts (B4).
4. **Least privilege and a record of everything.** Short-lived, scoped identities; a tamper-evident audit signed by
   a key WARDEN cannot export (S12).
5. **Stop is always available.** The kill switch stops every change (B9), and the runbook for incidents WARDEN
   itself causes (`docs/RUNBOOK-WARDEN-INCIDENT.md`) says what to do.
6. **Say what it cannot do.** Limits are written down, not discovered: an install with a single approver lets one
   person decide a change alone, some checks match English words only (M23), and the calibrated decider does not
   yet beat the base rate.

## Prohibited uses

- Applying a change without a person's signed approval of the exact plan.
- Acting on WARDEN's own components (P22) or outside the environments it is configured for (P18).
- Running a model that has not passed the replay qualification (M20), or a prompt that differs from the qualified
  one (E6).
- Sending logs to a model before redaction, or feeding WARDEN's own output back into its knowledge (N9).

## Change control

Changes to the prompt, the policies, the catalogue, the approval rules or any data file are pinned by hash and
routed to a named reviewer (N8). A prompt change needs a new qualification run (E6). Every applied change leaves a
GitHub change record (O9).

## Review

This policy, the RACI and the impact assessment are reviewed at least once a year and after any incident WARDEN
causes, with the date recorded below.

| Reviewed | By | Notes |
|---|---|---|
| 2026-10-03 | maintainers | first version |
