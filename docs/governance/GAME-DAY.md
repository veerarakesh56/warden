# Quarterly game day without WARDEN (register H4)

People who only approve what WARDEN proposes lose the skill of diagnosing without it. Once a quarter the on-call
engineers handle real faults with WARDEN switched off, then compare with what WARDEN would have said.

## When

The first working Monday of each quarter (January, April, July, October). The first is **2027-01-04**, after the
first cloud window; every game day is recorded in the table below.

## How

1. Turn WARDEN's changes off for the day, so nothing it plans can be applied:

```
warden killswitch on --reason "quarterly game day: people diagnose without WARDEN"
warden killswitch status
```

2. Inject three faults from the benchmark catalogue (`scenarios/`) into the proving-ground stack, one at a time: one
   the team has seen, one it has not, and one healthy control.
3. For each fault, the on-call engineer diagnoses and proposes a fix from the dashboards, logs and runbooks alone, and
   writes the time to diagnosis and the fix down.
4. Afterwards, run WARDEN on the same recorded evidence (`warden run`) and compare: who was right, who was faster,
   what each missed.
5. Reset the switch with a signed approval:

```
warden killswitch reset --approver <you> --key <your.pem> --trips <n>
```

## What counts

A game day is passed when the engineers diagnose at least two of the three faults correctly without WARDEN and name
the healthy control as healthy. A miss becomes a training item, not a blame item; a WARDEN miss becomes a register
row.

## Record

| Date | Faults | People right without WARDEN | WARDEN right | Notes |
|---|---|---|---|---|
| 2027-01-04 | planned | - | - | first game day |
