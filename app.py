"""Streamlit UI. Run: streamlit run app.py"""
import json, os
import requests
import streamlit as st
import core

N8N_URL = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/soc-triage")
API_URL = os.getenv("API_URL", "http://localhost:5001")

st.set_page_config(page_title="Governed SOC Triage", layout="wide")
st.title("Governed Agentic AI: SOC Alert Triage")
st.caption("Synthetic data only. AI recommends; a human approves every response action.")

with st.sidebar:
    st.header("Run settings")
    model = st.selectbox("Model", list(core.MODELS.keys()), format_func=lambda k: core.MODELS[k]["label"])
    analyst = st.text_input("Analyst name", "analyst1")
    use_n8n = st.toggle("Trigger via n8n workflow", True)
    st.caption(f"n8n: {N8N_URL}")

labels = {a["id"]: f'{a["id"]} - {a["label"]}' for a in core.ALERTS}
choice = st.selectbox("Select a synthetic alert", list(labels), format_func=lambda k: labels[k])
alert = next(a for a in core.ALERTS if a["id"] == choice)
safe_view = {k: v for k, v in alert.items() if k != "truth"}
st.subheader("Incoming alert")
st.json(safe_view, expanded=False)

if st.button("Run triage", type="primary"):
    result, via = None, ""
    if use_n8n:
        try:
            r = requests.post(N8N_URL, json={"alert": safe_view, "model": model}, timeout=120)
            r.raise_for_status()
            payload = r.json()
            if not (isinstance(payload, dict) and "risk" in payload and "summary" in payload):
                raise ValueError("unexpected n8n response: " + str(payload)[:300])
            result, via = payload, "n8n workflow"
        except Exception as e:
            st.warning(f"n8n workflow did not return a valid result ({str(e)[:400]}). Exception handling: using direct API pipeline.")
    if result is None:
        try:
            result = requests.post(f"{API_URL}/pipeline", json={"alert": safe_view, "model": model}, timeout=120).json()
            via = "API pipeline"
        except Exception:
            result = core.run_pipeline(alert, model); via = "in-process pipeline"
    st.session_state["result"] = result
    st.session_state["via"] = via
    st.session_state.pop("decided", None)

res = st.session_state.get("result")
if res and res["alert_id"] == choice:
    risk, summ, meta = res["risk"], res["summary"], res["meta"]
    st.success(f"Executed via: {st.session_state['via']}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Severity", risk["severity"].upper())
    c2.metric("Risk score", risk["risk_score"])
    c3.metric("Proposed route", risk["route"])
    c4.metric("Confidence", risk["confidence"])
    if res["evidence"]["guardrail"]["injection_detected"]:
        st.error("Prompt-injection pattern detected in alert text. Instruction was redacted; auto-close blocked.")
    if meta.get("fallback"):
        st.warning(f"Model output unusable, rule-based fallback used. Reason: {meta['errors']}")
    for n in risk.get("policy_notes", []):
        st.info("Policy guardrail: " + n)
    st.subheader(summ["headline"])
    st.write(summ["summary"])
    colA, colB = st.columns(2)
    colA.markdown("**Evidence**\n\n" + "\n".join("- " + str(e) for e in summ["evidence"]))
    colB.markdown("**Next steps**\n\n" + "\n".join("- " + str(e) for e in summ["next_steps"]))
    with st.expander("Agent evidence (correlation, threat intel, asset context)"):
        st.json(res["evidence"])
    st.divider()
    st.subheader("Human review (required)")
    if risk["route"] == "escalate":
        st.error("ESCALATION: notify incident response lead. Containment actions need explicit approval below.")
    comment = st.text_area("Analyst comment")
    b1, b2, b3 = st.columns(3)
    decision = None
    if b1.button("Approve recommendation"): decision = "approved"
    if b2.button("Override / change route"): decision = "overridden"
    if b3.button("Reject, need more info"): decision = "rejected"
    if decision:
        rec = core.record_human_decision(res["alert_id"], analyst, decision, comment, risk["route"])
        st.session_state["decided"] = rec
    if st.session_state.get("decided"):
        st.success("Decision recorded in the tamper-evident audit log.")
        st.json(st.session_state["decided"], expanded=False)

with st.expander("Audit log (last 15 entries)"):
    if core.AUDIT_LOG.exists():
        lines = core.AUDIT_LOG.read_text().strip().splitlines()[-15:]
        st.json([json.loads(l) for l in lines])
    else:
        st.write("No entries yet.")
