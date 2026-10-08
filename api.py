"""Tool/agent API called by the n8n workflow. Run: python api.py  (port 5001)"""
import os
from flask import Flask, request, jsonify
import core

app = Flask(__name__)

def _alert():
    body = request.get_json(force=True)
    if "alert" in body:
        return body["alert"], body
    return body, body

@app.get("/health")
def health():
    return {"status": "ok", "mode": os.getenv("LLM_MODE", "live")}

@app.post("/guardrail")
def guardrail():
    a, _ = _alert()
    g = core.input_guardrail(a)
    core.audit("input_guardrail", a["id"], {"injection": g["injection_detected"]})
    return jsonify(g)

@app.post("/correlate")
def correlate():
    a, _ = _alert(); return jsonify(core.correlate(a))

@app.post("/threat")
def threat():
    a, _ = _alert(); return jsonify(core.threat_lookup(a))

@app.post("/asset")
def asset():
    a, _ = _alert(); return jsonify(core.asset_lookup(a))

@app.post("/risk")
def risk():
    _, body = _alert()
    model = body.get("model", "baseline")
    ev = body["evidence"]
    r = core.risk_agent(model, ev)
    final = core.enforce_policy(r["result"], ev)
    core.audit("risk_decision", ev["alert"]["id"], {"model": model, "route": final["route"], "notes": final["policy_notes"]})
    return jsonify({"risk": final, "meta": r["meta"]})

@app.post("/summary")
def summary():
    body = request.get_json(force=True)
    return jsonify(core.summary_agent(body.get("model", "baseline"), body["evidence"], body["risk"]))

@app.post("/human-decision")
def human():
    b = request.get_json(force=True)
    rec = core.record_human_decision(b["alert_id"], b["analyst"], b["decision"], b.get("comment", ""), b.get("proposed_route", ""))
    return jsonify(rec)

@app.post("/pipeline")
def pipeline():
    """Single-call run, used as the UI fallback when n8n is unreachable."""
    a, body = _alert()
    return jsonify(core.run_pipeline(a, body.get("model", "baseline")))

if __name__ == "__main__":
    app.run(port=5001)
