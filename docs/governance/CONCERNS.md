# Raising a concern about WARDEN (audit CW4)

Anyone - an on-call engineer, a user of a service WARDEN watches, a reviewer - can raise a concern about how WARDEN
behaves: a wrong diagnosis, a fix that should not have been proposed, a report that overstated something, a privacy
worry.

## How

- **A concern about behaviour or a report:** open an issue in this repository with the label `warden-concern`. Say
  what happened and when (UTC), and the incident id or audit hash from the message footer (`warden audit show`
  matches it). Do not paste secrets or personal data.
- **A security problem:** follow `SECURITY.md` - never a public issue.
- **About a specific approval:** an approver can also record a signed verdict on the diagnosis and the action,
  which calibration reads (`warden label`, audit A-P-2).

## What happens

The owner (accountable in `RACI.md`) reads every concern within five working days, answers on the issue, and when it
shows a gap, adds a register row with a test that fails without its fix. A concern is never closed without a reply.
