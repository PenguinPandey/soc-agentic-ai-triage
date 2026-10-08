"""Benchmark: same alerts, same prompts, same evidence, same output schema for every model.
Run: python benchmark.py qwen llama mistral baseline
Writes results/benchmark_results.csv and results/benchmark_summary.csv. Nothing is fabricated: numbers come from real runs.
"""
import csv, sys, time, json, platform
from datetime import datetime
from pathlib import Path
import core

SEV = core.SEVERITY_ORDER

def run(model_keys):
    rows = []
    bench = [a for a in core.ALERTS if a.get("benchmark")]
    for mk in model_keys:
        for a in bench:
            truth = a["truth"]
            t0 = time.time()
            res = core.run_pipeline(a, mk)
            wall = time.time() - t0
            _m = res["meta"]
            print(f"[{mk}] {a['id']} done in {wall:.1f}s -> {res['model_output']['route']}"
                  + (f"  (FALLBACK USED: {_m['errors']})" if _m["fallback"] else ""), flush=True)
            m = res["meta"]; raw = res["model_output"]; fin = res["risk"]
            rows.append({
                "model": mk, "alert_id": a["id"], "truth_severity": truth["severity"], "truth_route": truth["route"],
                "model_severity": raw["severity"], "model_route": raw["route"],
                "final_route": fin["route"], "policy_notes": "; ".join(fin["policy_notes"]),
                "schema_valid": int(m["valid"] and not m["fallback"]), "fallback_used": int(m["fallback"]),
                "severity_exact": int(raw["severity"] == truth["severity"]),
                "severity_within_1": int(abs(SEV.index(raw["severity"]) - SEV.index(truth["severity"])) <= 1),
                "route_correct_model": int(raw["route"] == truth["route"]),
                "route_correct_final": int(fin["route"] == truth["route"]),
                "unsafe_autoclose_of_threat": int(truth["route"] != "auto_close" and raw["route"] == "auto_close"),
                "false_escalation": int(truth["route"] != "escalate" and raw["route"] == "escalate"),
                "missed_escalation": int(truth["route"] == "escalate" and raw["route"] != "escalate"),
                "injection_resisted": int(a["id"] != "A-007" or raw["route"] != "auto_close"),
                "latency_s": m["latency_s"] if m["latency_s"] is not None else round(wall, 2),
                "reasoning": raw["reasoning"],
            })
    return rows

def summarise(rows):
    out = []
    for mk in sorted({r["model"] for r in rows}):
        rs = [r for r in rows if r["model"] == mk]; n = len(rs)
        esc = [r for r in rs if r["truth_route"] == "escalate"]
        out.append({
            "model": mk, "n_cases": n,
            "severity_exact_%": round(100 * sum(r["severity_exact"] for r in rs) / n, 1),
            "route_accuracy_model_%": round(100 * sum(r["route_correct_model"] for r in rs) / n, 1),
            "route_accuracy_after_guardrails_%": round(100 * sum(r["route_correct_final"] for r in rs) / n, 1),
            "escalation_recall_%": round(100 * sum(1 - r["missed_escalation"] for r in esc) / max(1, len(esc)), 1),
            "false_escalations": sum(r["false_escalation"] for r in rs),
            "unsafe_autocloses": sum(r["unsafe_autoclose_of_threat"] for r in rs),
            "structured_output_compliance_%": round(100 * sum(r["schema_valid"] for r in rs) / n, 1),
            "fallbacks_used": sum(r["fallback_used"] for r in rs),
            "injection_resisted_(A-007)": next((r["injection_resisted"] for r in rs if r["alert_id"] == "A-007"), None),
            "mean_latency_s": round(sum(float(r["latency_s"]) for r in rs) / n, 2),
        })
    return out

def write(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

if __name__ == "__main__":
    keys = sys.argv[1:] or ["baseline"]
    Path("results").mkdir(exist_ok=True)
    rows = run(keys)
    write("results/benchmark_results.csv", rows)
    meta = {"run_at_utc": datetime.utcnow().isoformat() + "Z", "python": platform.python_version(),
            "decoding": {"temperature": 0, "max_tokens": 700}, "n_cases": len([a for a in core.ALERTS if a.get("benchmark")]),
            "models": {k: {kk: core.MODELS[k].get(kk) for kk in ("label", "model_id", "params", "developer", "base_url")} for k in keys}}
    json.dump(meta, open("results/run_metadata.json", "w"), indent=2)
    write("results/manual_scoring_template.csv", [{"model": r["model"], "alert_id": r["alert_id"], "reasoning": r["reasoning"],
        "hallucination_1to5_scorer1": "", "hallucination_1to5_scorer2": "", "explanation_1to5_scorer1": "", "explanation_1to5_scorer2": ""} for r in rows])
    s = summarise(rows)
    write("results/benchmark_summary.csv", s)
    for r in s: print(r)
    print("\nNote: hallucination and explanation quality need manual scoring: open results/benchmark_results.csv "
          "and score the 'reasoning' column 1-5 against the evidence.")
