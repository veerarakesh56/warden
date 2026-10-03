# Gemini API test with an AI Studio key (requirement R15), 2026-10-03

The owner gave a Google AI Studio key on 2026-10-03, to be deleted after this test. It was passed to each command in
an environment variable and never written to a file or to this repository.

## What was run

- **The key works.** `models.list` answered with 44 models that generate content, among them `gemini-3.8-flash`,
  `gemini-3.7-flash`, `gemini-3.5-flash`, `gemini-3.1-flash-lite`, `gemini-3.1-pro-preview`, `gemini-pro-latest`
  and `gemma-4-31b-it`.
- **The free tier covers only Flash and Flash-Lite.** Pro models have needed a paid tier since 2026-04-01, and Google
  no longer publishes the free tier's per-model limits (sources below, read 2026-10-03).
- **WARDEN's replay qualification** (`scripts/qualify_provider.py`, register M20): the same 30 recorded incidents
  every qualified model was measured on, with a hard $1 cap on each run.

| Model | Incidents | The model answered | Refused with 429 (quota) | Refused with 503 (overloaded) |
|---|---|---|---|---|
| gemini-3.8-flash | 30 | 4 | 23 | 3 |
| gemini-3.7-flash (in parallel) | 30 | 2 | 24 | 4 |
| gemini-3.1-pro-preview (in parallel) | 30 | 0 | 30 | 0 |
| gemini-3.8-flash, 30 s between incidents | 16, then stopped | 1 | 15 | 0 |

## What it shows

- **No Gemini model was measured.** On this key's free tier, WARDEN's 30-incident set could not be run:
  - the per-day quota was gone within the first runs;
  - pacing the calls 30 s apart did not bring it back;
  - Pro is not on the free tier at all.
- **No Gemini model is qualified.** So none may diagnose: the provider check (M20) refuses an unqualified model
  outside qualification. A Gemini measurement needs a key on the paid tier.
- **Cost: nothing.** The free tier billed nothing. At paid Flash prices the answered calls would have cost under
  $0.02.

## What it found in WARDEN

`qualify_provider.py` scored the rows the model never answered:
- in those rows the gate escalated on rules alone (`P0-MODEL-UNAVAILABLE`), and the script counted them as the
  model's answers;
- so Gemini 3.1 Pro, refused 30 of 30 times, came out as "7 correct, 0 errors".

The fix:
- each such row now counts as unanswered;
- one unanswered row fails a qualification, and the script says why ("NOT MEASURED: the model did not answer 30 of
  30 incidents");
- `--pace-s` spaces the incidents for a rate-limited tier.

Tests: `tests/test_qualify_unanswered_r15.py`.

## Sources

- Gemini pricing in 2026 (CloudZero): https://www.cloudzero.com/blog/gemini-pricing/
- Gemini API free tier 2026 (PE Collective): https://pecollective.com/tools/gemini-free-tier-guide/
- Gemini API rate limits, free tier quotas 2026 (TinkerLLM): https://tinkerllm.com/blog/gemini-api-free-tier-limits-rate-quotas/
