# Compliance crosswalk (audit A-P-9)

What in WARDEN answers each part of four frameworks, by register row (`docs/FAILURE-MODES.md`,
`docs/AUDIT-2026-09-28.md`), and where it does not. Read live 2026-10-03; every row id here is held to the registers
by `tests/test_compliance_crosswalk.py`. **Not legal advice.** An open row is named as open.

## NIST AI RMF 1.0 (AI 100-1) and the Generative AI Profile (AI 600-1)

AI RMF 1.0 (January 2023) is the current version; NIST states it is being revised under the White House AI Action
Plan (no draft yet), and on 2026-04-07 published a concept note for a profile on trustworthy AI in critical
infrastructure.

| Function / category | WARDEN | Open |
|---|---|---|
| GOVERN 1 policies and practices | the registers and their test; CODEOWNERS and pinned hashes (N8) | CW1 (a written AI policy) |
| GOVERN 2 accountability | single approver stated in every change record (R50) | H5, CW1 |
| GOVERN 4 a culture of communicating risk | the register's honesty rules; N11 | H4 |
| GOVERN 5 engaging relevant AI actors | change records in GitHub (O9) | CW4 (a channel to raise concerns) |
| GOVERN 6 third-party and supply chain | B14, M15, M20, A-P-7 | S9 |
| MAP 1-4 context, categorisation, capabilities, component risk | environments and S6; the closed catalogue and tiers; the replay benchmark and N6; M20 | S11 |
| MAP 5 impacts on people and organisations | - | CW2 (an impact assessment) |
| MEASURE 1-2 metrics and trustworthy characteristics | N6, H1, B1, B2, B3, M20, N5 | E5, E6, M2 |
| MEASURE 3-4 tracking over time, feedback on measurement | E7, M15, N11, signed approver labels (A-P-2) | N5b, E2 |
| MANAGE 1-2 prioritise, and disengage the system | the registers' groups; kill switch (B9), breaker (B12), rules-only mode (M19), observe mode (A-P-8) | - |
| MANAGE 3 third-party risk | M20 | S9 |
| MANAGE 4 response, recovery, monitoring | audit (B8, S12), change records (O9), the WARDEN-incident runbook (A-P-6) | C13, O4 |

AI 600-1's twelve generative-AI risks: confabulation - B1, B2, B3, N1 (open: M2); data privacy - redaction, S2, B6
(open: S11); harmful bias and homogenisation - N3 (open: M23); human-AI configuration - H1, H10, N4 (open: H6, H4);
information integrity - N1, S17; information security - B4, B5, B6, B11, S5 (open: N10, S15); value chain and
component integration - B14, M15, M20 (open: S9); environmental impacts - open, CW3 (cost is capped by M18, energy is
not measured). CBRN, violent or hateful content, intellectual property and obscene content: not applicable - the
model picks from a closed catalogue and generates nothing for the public.

## ISO/IEC 42001:2023, Annex A

Edition 1 is current (under review in SC 42; no amendment published). The A.x headings could not be read from iso.org
(it refused automated reads); the controls under them are taken from NIST's AI RMF to ISO/IEC 42001 crosswalk.

| Control area | WARDEN | Open |
|---|---|---|
| A.2 Policies related to AI | - | CW1 |
| A.3 Internal organisation (incl. reporting of concerns) | - | H5, CW4 |
| A.4 Resources for AI systems | docs/SYSTEM-COMPONENTS.md, A-P-7 | - |
| A.5 Assessing impacts of AI systems | - | CW2 |
| A.6 AI system life cycle (verification, monitoring, event logs) | S12, B8, E7, O5, M20 | E6, C22 |
| A.7 Data for AI systems (provenance) | N9, M11 | E2 |
| A.8 Information for interested parties (incident communication) | reports, O9, S17 | - |
| A.9 Use of AI systems (intended use) | closed catalogue, signed approvals, B10, N7 | - |
| A.10 Third-party relationships | M20 | S9, S11 |

## OWASP Top 10 for Agentic Applications 2026 (released 2025-12-09)

ASI01 agent goal hijack - B4, M10, M11, N3. ASI02 tool misuse - B10, B13, C4, C10, N7. ASI03 identity and privilege
abuse - S6, B5 (open: H6). ASI04 agentic supply chain - B14, N8 (open: S9). ASI05 unexpected code execution - B5,
B6, B11. ASI06 memory and context poisoning - N9 (open: C22). ASI07 insecure inter-agent communication - one model
call, no second agent (open: S15). ASI08 cascading failures - B9, B12, C1, C2, C21 (open: C8). ASI09 human-agent trust
exploitation - H1, H10, N4 (open: H6). ASI10 rogue agents - B9, B10, N7, N11. The same mapping drives the register's
research coverage (R45).

## EU AI Act (Regulation (EU) 2024/1689), Articles 9-15

| Article | WARDEN | Open |
|---|---|---|
| 9 Risk management system | the registers and their test | CW2 (impacts on rights) |
| 10 Data and data governance | N9, redaction | E2 |
| 11 Technical documentation | README and docs | CW5 (Annex IV form, instructions for use) |
| 12 Record-keeping | S12, B8, E7, M15, O3 | - |
| 13 Transparency to deployers | README limits, reports, N1 | CW5 |
| 14 Human oversight | signed approvals (R50), kill switch (B9), N4, H1, H10 | H6, H4 |
| 15 Accuracy, robustness, cybersecurity | B1, B2, B3, B4, B6, B12, M19, M20, S5 | E6, S9, N10 |

**Dates.** The Digital Omnibus (Regulation (EU) 2026/1744 of 8 July 2026, published 2026-07-24) moved the high-risk
obligations: Annex III systems from **2 December 2027**, Annex I systems from **2 August 2028**.

**Is WARDEN high-risk?** Annex III point 2 covers safety components in the management and operation of critical
digital infrastructure; recital 55 excludes components used solely for cybersecurity, and the Omnibus's new
Article 6(1a) excludes non-safety automation and efficiency uses while 6(1b) brings in any system whose failure could
endanger health and safety. For a typical company WARDEN is very likely not high-risk. At an operator of critical
digital infrastructure (cloud, data centre, DNS) or of energy or water systems it could be argued in, because it
remediates production; there an Article 6(3) self-assessment should be written down. Signed human approval of every
change supports a no-material-influence argument, but does not settle it.

## Sources (read 2026-10-03)

- https://www.nist.gov/itl/ai-risk-management-framework ; https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf ;
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- https://airc.nist.gov/docs/NIST_AI_RMF_to_ISO_IEC_42001_Crosswalk.pdf
- https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R1689 ;
  https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202601744 ;
  https://www.europarl.europa.eu/legislative-train/package-digital-package/file-digital-omnibus-on-ai
