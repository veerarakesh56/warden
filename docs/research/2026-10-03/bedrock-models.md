# Bedrock models for WARDEN's evaluation: prices, reach and structured output (2026-10-03)

Read live 2026-10-03 (10:50 UTC / 16:20 IST). One evaluation pass = the 30 recorded incidents, about 6,000 input and
1,000 output tokens each, so one run costs `0.18 x input price + 0.03 x output price` (USD per 1M tokens).

Account state the same day: every Bedrock model shows entitlement AVAILABLE (the Free plan does not block them), but
every tokens-per-minute quota is 0 and a test call returns "Operation not allowed" - an account-level hold that AWS
Support lifts. Nothing below has been called yet.

## Prices seen from ap-south-2 (USD per 1M input / output)

Geo (`in.`, `us.`) and in-region prices are the global price x1.10 for Anthropic, OpenAI and xAI.

| Model | Route | In / Out |
|---|---|---|
| Claude Sonnet 5 | `in.` geo or global | 2.20/11.00 geo; list 2/10 |
| Claude Sonnet 5.5 | global | 2.00/10.00 |
| Claude Fable 5 / 5.1 | global | list 10/50 (no global row on the Bedrock page) |
| Claude Opus 5 | `in.` geo or global | 5.50/27.50 geo; list 5/25 |
| Claude Opus 5.5 | global | 4.00/20.00 |
| Claude Haiku 4.5 | global or `in.` | 1.00/5.00 global; 1.10/5.50 `in.` |
| Claude Sonnet 4.6 | global | 3.00/15.00 |
| GPT-5.4, GPT-5.5 | not reachable from here (Mantle, US regions only) | 2.75/16.50, 5.50/33.00 |
| GPT-5.6 Luna / Sol / Terra | global (Luna, Terra also `in.`) | 0.20/1.20, 4.00/20.00, 2.00/12.00 |
| GPT-6 Astra / Luna / Sol | global (Astra from ap-south-1) | 10/50, 0.10/0.50, 2.00/10.00 |
| GPT-6.1 Sol | global (call from us-east-1) | 2.00/10.00 |
| Grok 4.6 / 4.7 | global | 2.00/6.00 |
| Kimi K3 | global | 3.00/15.00 |

Open-weight, on demand in-region (ap-south-1 price; us-east-1/us-west-2 slightly lower): GLM 5 1.20/3.84, Kimi K2.5
0.72/3.60, DeepSeek V3.2 0.74/2.22, MiniMax M2.5 0.36/1.44, Qwen3 235B 0.26/1.04 (us-west-2), gpt-oss-120b 0.18/0.71,
Mistral Large 3 0.59/1.76. Amazon: Nova 2 Lite 0.30/2.50 global, Nova Pro 0.80/3.20, Nova Premier 2.50/12.50 (`us.`).
Llama 4 Maverick 0.24/0.97 (`us.`). Published standing (Artificial Analysis index, early-2026 versions): GLM 5 50,
Kimi K2.5 47, DeepSeek V3.2 42, MiniMax M2.5 42.

## Structured output and tool use

- Converse works for all of the above except GPT-5.4 and GPT-5.5.
- Forcing one named tool is documented for Anthropic and Amazon Nova only (the reference may be dated: smoke-test).
- Claude Sonnet 5, 5.5, Opus 5, 5.5 and 4.8: structured outputs not supported, so a forced tool call is how
  WARDEN gets typed JSON (BedrockProvider does this). Haiku 4.5 and Sonnet 4.6 support structured outputs.
- GPT-5.6 / 6 / 6.1, Grok 4.7, Kimi K3 and the open-weight models: JSON-schema output supported; WARDEN asks for
  JSON in the prompt and validates it, as for every provider.
- Fable 5.1's card warns of blocking classifiers for dual-use cybersecurity content and materially higher refusal
  rates - relevant to incident response, and measured by the evaluation rather than assumed.

## The evaluation list (one pass about $11 at list; budget $15-18 for tokenizer and reasoning overhead)

| # | Model / route | $ per run |
|---|---|---|
| 1 | Claude Sonnet 5 `in.` (the production choice, D12) | 0.73 |
| 2 | Claude Sonnet 5.5 global | 0.66 |
| 3 | Claude Opus 5.5 global | 1.32 |
| 4 | Claude Fable 5.1 global | 3.30 |
| 5 | Claude Haiku 4.5 global | 0.33 |
| 6 | GPT-6 Sol global | 0.66 |
| 7 | GPT-6.1 Sol global | 0.66 |
| 8 | GPT-5.6 Terra `in.` | 0.79 |
| 9 | GPT-6 Luna global | 0.03 |
| 10 | Grok 4.7 global | 0.54 |
| 11 | Kimi K3 global | 0.99 |
| 12 | GLM 5 (ap-south-1) | 0.33 |
| 13 | Kimi K2.5 (ap-south-1) | 0.24 |
| 14 | DeepSeek V3.2 (ap-south-1) | 0.20 |
| 15 | Amazon Nova 2 Lite global | 0.13 |

Each run is capped by `scripts/qualify_provider.py --budget-usd`; the whole evaluation stays within USD 40 of the
account's free credits, and a Free-plan account cannot be billed beyond its credits.

## Sources (all read 2026-10-03)

- https://aws.amazon.com/bedrock/pricing/ (and its price feeds on b0.p.awsstatic.com, published 2026-09-30 and
  2026-10-03)
- https://docs.aws.amazon.com/bedrock/latest/userguide/ model cards (`model-card-<model>.html`) for each model above
- https://platform.claude.com/docs/en/about-claude/pricing
- https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ToolChoice.html
- https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html
- https://artificialanalysis.ai/articles/glm-5-everything-you-need-to-know ;
  https://artificialanalysis.ai/articles/kimi-k2-5-everything-you-need-to-know ;
  https://artificialanalysis.ai/models/comparisons/minimax-m2-5-vs-gpt-oss-120b
