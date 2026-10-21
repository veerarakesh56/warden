# Model cost per month

What WARDEN's model calls cost, from token counts the repository recorded - not from estimates. AWS running costs are
in [SYSTEM-COMPONENTS.md](SYSTEM-COMPONENTS.md); this page is the model tokens only. Written 2026-10-21.

## Tokens per incident: the source

Every live benchmark report records the model's token counts per incident in its `cost` field
(`{"input_tokens", "output_tokens", "usd", "calls"}`), taken from the provider's reported usage
(`src/warden/providers.py`: `resp.usage.input_tokens`, `resp.usage.output_tokens`). The runs used are the three
published live runs, the same 30 incidents that make the golden set (`scripts/qualify_provider.py` `RUNS`); each
incident ran 3 times, 2 model calls each. The model was Claude Sonnet through the `claude` command line
([BENCHMARKS.md](BENCHMARKS.md), "Live runs on a real AWS account").

| Run (source files) | Run date | Reports | Input tokens | Output tokens |
|---|---|---|---|---|
| `tests/fixtures/bench/wave1-2026-09-11T155744Z/reports/*.json` | 2026-09-11 | 42 | 281,286 | 29,826 |
| `tests/fixtures/bench/wave2-2026-09-24T115746Z/reports/*.json` | 2026-09-24 | 30 | 88,087 | 16,328 |
| `tests/fixtures/bench/wave3-2026-09-25T044307Z/reports/*.json` | 2026-09-25 | 18 | 23,103 | 8,245 |
| **All three** | | **90** | **392,476** | **54,399** |

**Per incident: 392,476 / 90 = 4,361 input tokens and 54,399 / 90 = 604 output tokens** (rounded). The earlier run
`wave1-2026-09-11T052533Z` is left out: BENCHMARKS.md marks it invalid as a measurement.

Recompute:

```bash
python -c "import json,glob; r=[json.load(open(f))['cost'] for d in ('wave1-2026-09-11T155744Z','wave2-2026-09-24T115746Z','wave3-2026-09-25T044307Z') for f in glob.glob(f'tests/fixtures/bench/{d}/reports/*.json')]; print(len(r), sum(c['input_tokens'] for c in r), sum(c['output_tokens'] for c in r))"
```

## Prices

From Anthropic's pricing page, <https://platform.claude.com/docs/en/about-claude/pricing>, read 2026-10-21 about 13:55 UTC
(19:25 IST). Base prices, USD per million tokens (MTok); no batch, cache or data-residency changes applied:

| Model | Input | Output | Why it is here |
|---|---|---|---|
| Claude Sonnet 5.5 | $2 / MTok | $10 / MTok | the qualified model (`src/warden/data/providers.yaml` `qualified`; `prices` has the same `[2.0, 10.0]`) |
| Claude Haiku 5.5 (prompts up to 100,000 tokens) | $0.10 / MTok | $0.50 / MTok | the cheaper alternative. **Not qualified**: never measured on the golden set, so WARDEN refuses it today |

The same page also lists Claude Opus 5.5 at $4 / $20 (the model Eldane uses when Sonnet 5.5 diagnosed).

## Monthly cost

Cost = incidents per day x 30 days x tokens per incident x price per MTok / 1,000,000, input and output separately.
The repository records no expected incident volume, so three volumes are shown.

**Per incident**

| Model | Input | Output | Total |
|---|---|---|---|
| Sonnet 5.5 | 4,361 x $2 / 1M = $0.008722 | 604 x $10 / 1M = $0.006040 | **$0.014762** |
| Haiku 5.5 | 4,361 x $0.10 / 1M = $0.000436 | 604 x $0.50 / 1M = $0.000302 | **$0.000738** |

**Per month (30 days)**

| Incidents a day | Incidents a month | Input tokens | Output tokens | Sonnet 5.5 input | Sonnet 5.5 output | **Sonnet 5.5 total** | Haiku 5.5 input | Haiku 5.5 output | **Haiku 5.5 total** |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 30 | 130,830 | 18,120 | $0.26 | $0.18 | **$0.44** | $0.013 | $0.009 | **$0.02** |
| 10 | 300 | 1,308,300 | 181,200 | $2.62 | $1.81 | **$4.43** | $0.131 | $0.091 | **$0.22** |
| 50 | 1,500 | 6,541,500 | 906,000 | $13.08 | $9.06 | **$22.14** | $0.654 | $0.453 | **$1.11** |

Example row (10 a day, Sonnet 5.5): 10 x 30 = 300 incidents; 300 x 4,361 = 1,308,300 input tokens x $2 / 1M = $2.62;
300 x 604 = 181,200 output tokens x $10 / 1M = $1.81; total $4.43.

## Cross-check against measured spend

The qualification and held-out runs recorded their spend, not their tokens (`scripts/qualify_provider.py` writes its
output outside the repository; `providers.yaml` keeps `spent_usd` only):

| Run | Recorded | Per incident |
|---|---|---|
| Sonnet 5.5 qualification, 30 incidents, 2026-10-15 14:56 UTC (20:26 IST) | `spent_usd: 0.4212` | $0.0140 |
| Sonnet 5.5 on the G10 held-out set, 172 cases | $3.15 (providers.yaml comment) | $0.0183 |
| Opus 5.5 on the G10 held-out set, 172 cases | $9.00 (providers.yaml comment) | $0.0523 |

The recorded-token estimate ($0.0148) is within about 5% of the qualification run's measured $0.0140 (the
2026-10-15 code, on the previous prompt).

## What this does not count

- **Eldane** (dev only): two passes per plan on the other model (Opus 5.5 when Sonnet 5.5 diagnosed), plus catch
  trials. No Eldane token counts are recorded in the repository; its calls are capped by `WARDEN_ELDANE_DAILY_CALLS`
  (60 a day, `src/warden/eldane.py`).
- **Investigation rounds and the discussion channel**: up to 2 extra read-and-decide rounds (`INVESTIGATE_ROUNDS`,
  `src/warden/workflows.py`) and up to 20 discussion answers per incident a day (`src/warden/discuss.py`). The recorded
  runs made exactly 2 calls per incident.
- **Prompt growth since September**: the diagnosis prompt now asks for ranked hypotheses with citations, so today's
  prompts are likely longer than the recorded ones. The qualification spend above is the better guide until new
  token counts are recorded.
- **Haiku 5.5's token counts** may differ from Sonnet's for the same text; the table applies Sonnet-measured counts.
- **Caps**: per incident `WARDEN_MAX_USD` (default $0.50, `src/warden/llm.py`); per day `WARDEN_DAILY_MAX_USD` ($10)
  and `WARDEN_DAILY_MAX_TOKENS` (2,000,000) in `src/warden/activities.py`. At 50 incidents a day the table's spend
  ($0.74 a day on Sonnet 5.5) is far below the daily cap.

In production the real figures come from the audit: `warden usage --days 30` prints model calls, tokens and cost per
day ([RUNBOOK.md](RUNBOOK.md#monitoring)).
