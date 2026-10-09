# Governed Agentic AI for SOC Alert Triage

Group 2, Div B. MBA (ITBM), Symbiosis Centre for Information Technology, Pune.
Agentic AI Digital Transformation Hackathon, Cybersecurity Challenge.

A proof-of-concept in which an orchestrated set of AI agents triages security-operations-centre alerts, **recommends** a response, and hands every decision to a human analyst. No code path executes a response action.

**All data is synthetic.** No real credentials, customer data or personal data are included.

## What it does

An alert goes through: input guardrail -> correlation agent -> threat-intelligence agent -> asset-context agent -> risk and prioritisation agent -> policy guardrail -> routing (escalate / analyst review / proposed auto-close) -> incident summary -> mandatory human approve / override / reject -> hash-chained audit log.

Each step is classified A (autonomous), H (human-in-the-loop) or E (escalation). See `diagrams/`.

| File | Purpose |
|---|---|
| `app.py` | Streamlit interface (analyst view, human review, audit log) |
| `api.py` | Flask tool API called by the n8n workflow (port 5001) |
| `core.py` | Agents, guardrails, policy rules, audit log |
| `benchmark.py` | Runs the same alerts through each model and writes the results |
| `n8n/soc_triage_workflow.json` | The n8n workflow (import into n8n) |
| `models.json` | The three open-weight models and the rule-based baseline |
| `data/` | Synthetic alerts, assets and threat intelligence |
| `results/` | Benchmark output of the valid run (run 2) and the per-item hallucination and explanation scores (`final_scores.csv`) |
| `diagrams/`, `screenshots/` | AS-IS, TO-BE and architecture diagrams, and screenshots of the running system |

## Models compared

Hosted open-weight models through OpenRouter, same prompt, same evidence, same JSON schema, temperature 0:
Qwen2.5 72B Instruct, Llama 3.3 70B Instruct, Mistral Small 3.1 24B Instruct, plus a rule-based baseline. Results are in `results/benchmark_summary.csv`.

## Run it (Windows PowerShell)

Requires Python 3.9 or newer and, for the workflow, Node.js.

```powershell
pip install -r requirements.txt
$env:OPENROUTER_API_KEY="your-key-here"     # never commit a key
streamlit run app.py                         # window 1: http://localhost:8501
```

The app works on its own. To run through n8n as well:

```powershell
python api.py                                # window 2: tool API on 127.0.0.1:5001
npx n8n                                      # window 3: n8n on http://localhost:5678
```

In n8n: import `n8n/soc_triage_workflow.json`, click Publish, then switch on "Trigger via n8n workflow" in the app. If n8n is down or returns something invalid, the app falls back to the API pipeline and then to the in-process pipeline.

Without an API key, `LLM_MODE=mock` runs the rule-based engine only.

## Benchmark

```powershell
python benchmark.py qwen llama mistral baseline
```

Writes `results/benchmark_results.csv` and `results/benchmark_summary.csv`. Hallucination and explanation quality are scored (1 to 5) from the `reasoning` column; the scores in `results/final_scores.csv` were assigned by an AI assistant in two claim-by-claim passes, not by independent human raters.

## Governance controls (mapped to NIST AI RMF 1.0 and the GenAI Profile, with ISO/IEC 27001:2022 cross-references in the report)

- Input guardrail: prompt-injection patterns are flagged and redacted; ground-truth and label fields are removed before any model sees an alert (`core.input_guardrail`).
- Output guardrail: JSON schema and enum validation, with fallback to the rule-based engine (`core.validate_output`).
- Policy guardrail: deterministic; it can only move a decision toward more caution (`core.enforce_policy`).
- Human oversight: every outcome needs an analyst decision in the interface.
- Audit: SHA-256 hash-chained log of alert receipt, guardrail result, risk decision and human decision (`core.audit`).

## Limitations

Nine synthetic benchmark alerts and single runs per model, so the comparison is indicative, not statistically conclusive. There is no SOC-specific expert validation: the one expert interview covered a related fraud-investigation workflow. See the report for details.
