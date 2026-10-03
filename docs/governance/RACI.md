# Who does what (register H5)

R = responsible (does it), A = accountable (answers for it; exactly one per activity), C = consulted, I = informed.

| Activity | Owner | Approver | On-call engineer | Reviewer | WARDEN |
|---|---|---|---|---|---|
| Diagnose an incident and propose one fix | A | I | C | - | R |
| Decide whether a proposed fix is applied | I | A | R | - | C |
| Apply an approved fix | I | A | C | - | R |
| Roll back a fix that made things worse | I | C | A | - | R |
| Turn the kill switch on | I | C | A | - | - |
| Reset the kill switch (signed) | C | A | R | - | - |
| Change a policy, prompt, catalogue entry or data file | A | - | C | R | - |
| Qualify a model before it is used | A | - | - | R | C |
| Review the incident-signature catalogue (yearly per entry) | A | - | C | R | - |
| Run the quarterly game day without WARDEN | A | - | R | C | - |
| Rotate secrets and keys | A | - | R | - | - |
| Respond to an incident WARDEN itself causes | A | C | R | C | - |
| Read concerns raised about WARDEN | A | - | I | R | - |
| Review this RACI, the AI policy and the impact assessment | A | C | C | R | - |

In the lab one person holds every human role. That is stated, not hidden: one key or one hasty approval decides a
change alone (R50). A team splits the roles; the code already counts approvals from different approvers where the
tier requires it.
