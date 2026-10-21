# Model cost per month

What WARDEN's model calls cost per incident and per month. The monthly figures start from **spend measured on the
Claude API**. A second, rougher figure comes from the token counts in the September benchmark reports, which are
**estimates (characters / 3), not counts from the provider**; it is shown only as a cross-check. AWS running costs are
in [SYSTEM-COMPONENTS.md](SYSTEM-COMPONENTS.md); this page is the model calls only. Written 2026-10-21.

## Measured spend per incident

These runs called the Claude API through the `anthropic` SDK. The provider reported each call's tokens
(`src/warden/providers.py`: `resp.usage.input_tokens`, `resp.usage.output_tokens`), and WARDEN priced them
(`src/warden/llm.py` `model_prices()`: `WARDEN_PRICE_IN`/`WARDEN_PRICE_OUT` when set, else the model's row in
`src/warden/data/providers.yaml` `prices`). So `spent_usd` is WARDEN's own accounting of reported tokens at the listed
price, not an Anthropic invoice. The rows do not record whether a price override was set; the figures assume none.

| Run | Recorded | Per incident |
|---|---|---|
| Claude Sonnet 5.5 qualification, the 30 golden-set incidents, 2026-10-15 14:56 UTC (20:26 IST) | `spent_usd: 0.4212` (providers.yaml `qualified`) | **$0.0140** |
| Claude Sonnet 5.5 on the G10 held-out set, 172 cases | $3.15 (providers.yaml comment) | **$0.0183** |
| Claude Opus 5.5 on the G10 held-out set, 172 cases | $9.00 (providers.yaml comment) | $0.0523 |

All three ran on the 2026-10-15 code and an earlier prompt (`d435b59f...`). The prompt pinned today
(`providers.yaml` `prompt.sha`) is longer: it asks for 2-4 ranked hypotheses with citations, uses tagged sections and
worked examples, and names failed fields when it retries. No run on it has been measured yet, so today's cost per
incident is likely somewhat higher than these.

## Prices

From Anthropic's pricing page, <https://platform.claude.com/docs/en/about-claude/pricing>, read 2026-10-21 about
13:55 UTC (19:25 IST). Base prices, USD per million tokens (MTok); no batch, cache or data-residency changes applied:

| Model | Input | Output | Why it is here |
|---|---|---|---|
| Claude Sonnet 5.5 | $2 / MTok | $10 / MTok | the model in `providers.yaml` `qualified` (measured on an earlier prompt, so **not qualified on today's**: [RUNBOOK.md](RUNBOOK.md#known-limitations)); `prices` has the same `[2.0, 10.0]` |
| Claude Haiku 5.5 (prompts up to 100,000 tokens) | $0.10 / MTok | $0.50 / MTok | the cheaper alternative. **Not qualified**: never measured on the golden set, so WARDEN refuses it today |

The same page also lists Claude Opus 5.5 at $4 / $20 (the model Eldane uses when Sonnet 5.5 diagnosed).

If `WARDEN_PRICE_IN` or `WARDEN_PRICE_OUT` is set, WARDEN prices every model at those two values. If only one is set,
the other falls back to the code default ($3 in, $15 out, `src/warden/llm.py`), not the model's own price. WARDEN's
recorded `usd` figures and its per-incident and daily caps then use those prices. This page's figures assume both are
unset.

## Monthly cost

Cost a month = incidents a day x 30 x measured cost per incident. Two measured figures give a range: the qualification
run ($0.0140) and the larger held-out set ($0.0183). Haiku 5.5 costs exactly 1/20 of Sonnet 5.5 for both input and
output, so for the same tokens it costs 1/20 as much ($0.0007 to $0.0009 per incident). Its token counts are not
measured: it might use more or fewer tokens than Sonnet on the same incident. The repository records no expected
incident volume, so three volumes are shown.

| Incidents a day | Incidents a month | **Sonnet 5.5** ($0.0140 - $0.0183 each) | Haiku 5.5 (1/20, not measured) |
|---|---|---|---|
| 1 | 30 | **$0.42 - $0.55** | $0.02 - $0.03 |
| 10 | 300 | **$4.21 - $5.49** | $0.21 - $0.27 |
| 50 | 1,500 | **$21.06 - $27.47** | $1.05 - $1.37 |

Example (10 a day, Sonnet 5.5): 300 x $0.4212 / 30 = $4.21; 300 x $3.15 / 172 = $5.49.

## Cross-check: September token estimates

Every live benchmark report keeps a `cost` field (`{"input_tokens", "output_tokens", "usd", "calls"}`). The three
published live runs, the same 30 incidents that make the golden set (`scripts/qualify_provider.py` `RUNS`; each
incident ran 3 times, 2 model calls each), used the `claude` command line (`WARDEN_PROVIDER=claude_cli`, model alias
`sonnet`, in each run's `manifest.json`). The alias does not say which Sonnet version answered.

**These token counts are estimates, not counts from the provider.** `ClaudeCliProvider` does not read the CLI's usage.
It returns `_estimate_tokens(system + user)` and `_estimate_tokens(text)`, which is characters / 3, a deliberate
over-estimate (`src/warden/providers.py`; the same code at each run's `git_commit`). The reports' `usd` priced those
estimates at the then default $3 / $15.

| Run (source files) | Run date | Reports | Input tokens (est.) | Output tokens (est.) |
|---|---|---|---|---|
| `tests/fixtures/bench/wave1-2026-09-11T155744Z/reports/*.json` | 2026-09-11 | 42 | 281,286 | 29,826 |
| `tests/fixtures/bench/wave2-2026-09-24T115746Z/reports/*.json` | 2026-09-24 | 30 | 88,087 | 16,328 |
| `tests/fixtures/bench/wave3-2026-09-25T044307Z/reports/*.json` | 2026-09-25 | 18 | 23,103 | 8,245 |
| **All three** | | **90** | **392,476** | **54,399** |

That averages about 4,361 input and 604 output tokens per diagnosis run (estimated). At Sonnet 5.5's prices, that is
4,361 x $2 / 1M + 604 x $10 / 1M = **$0.0148 per diagnosis run**. It lands near the measured $0.0140 to $0.0183. Treat that
as a sanity check only: the token counts are estimates from a different provider path, prompt and possibly model. The
earlier run `wave1-2026-09-11T052533Z` is left out because BENCHMARKS.md marks it invalid as a measurement.

Recompute:

```bash
python -c "import json,glob; r=[json.load(open(f))['cost'] for d in ('wave1-2026-09-11T155744Z','wave2-2026-09-24T115746Z','wave3-2026-09-25T044307Z') for f in glob.glob(f'tests/fixtures/bench/{d}/reports/*.json')]; print(len(r), sum(c['input_tokens'] for c in r), sum(c['output_tokens'] for c in r))"
```

## What this does not count

- **Eldane** (dev only): two passes per plan on the other model (Opus 5.5 when Sonnet 5.5 diagnosed), plus catch
  trials. The repository records no Eldane token counts. Its calls are capped by `WARDEN_ELDANE_DAILY_CALLS` (60 a
  day, `src/warden/eldane.py`). The planned Eldane benchmark's cost estimate is in
  [BENCHMARKS.md](BENCHMARKS.md#the-ai-critic-eldane-on-the-g10-held-out-set).
- **Extra diagnosis calls**:
  - up to 2 read-and-decide investigation rounds (`INVESTIGATE_ROUNDS`, `src/warden/workflows.py`);
  - one repair round when an answer fails only checks a better answer could pass (`src/warden/workflows.py`);
  - a retry after an answer that fails validation (`llm.RETRY_FEEDBACK`, `src/warden/llm.py`);
  - up to 20 discussion answers per incident a day (`src/warden/discuss.py`).

  The qualification run's spend includes whatever of these its code made. The September reports made exactly 2 calls
  per incident.
- **Caps**:
  - In the cloud runtime, the llm zone allows **6 model calls and $0.25 per incident**, across rounds
    (`WARDEN_MAX_CALLS=6`, `WARDEN_MAX_USD=0.25`, `terraform/modules/warden-runtime/compute.tf`). This replaces the
    client default of $0.50 (`WARDEN_MAX_USD` in `src/warden/llm.py`), which applies only where nothing sets it, such
    as a laptop.
  - Per day, `WARDEN_DAILY_MAX_USD` and `WARDEN_DAILY_MAX_TOKENS`. They default to $10 and 2,000,000
    (`src/warden/activities.py`) where nothing sets them; a deployment can set its own values in the runtime's environment.
  - At 50 incidents a day, the spend at the measured cost per incident ($0.70 to $0.92 a day on Sonnet 5.5) is far below
    the default daily cap.

In production the real figures come from the audit: `warden usage --days 30` prints model calls, tokens and cost per
day ([RUNBOOK.md](RUNBOOK.md#monitoring)). The cloud audit database is reachable only from inside the runtime's VPC,
like `warden audit verify`.
