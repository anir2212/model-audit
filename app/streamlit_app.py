"""Local, read-only browser for measured ModelAudit evidence."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from audit.registry import load_plan  # noqa: E402
from audit.review import confirmation_scope, current_findings, reevaluate, trace, verify_digest  # noqa: E402

AUDIT = Path(os.environ.get("MODELAUDIT_AUDIT_DIR", ROOT / "runs/audit"))
PLAN = Path(os.environ.get("MODELAUDIT_PLAN", ROOT / "configs/audit_plan.yaml"))

st.set_page_config(page_title="ModelAudit local console", layout="wide")
st.title("ModelAudit")
st.caption("Local UCI credit-model research audit · no lending use or regulatory compliance claim")
files = sorted(path for path in AUDIT.glob("*.json") if path.stem.startswith(("taiwan_", "german_"))
               and "tests" in json.loads(path.read_text()))
if not files:
    st.error("Run `make audit` to generate evidence first.")
    st.stop()
name = st.selectbox("Audit bundle", [file.stem for file in files])
source = next(file for file in files if file.stem == name)
bundle = json.loads(source.read_text())
if not verify_digest(bundle):
    st.error(f"Evidence hash mismatch for {source.name}: the file changed after the audit wrote it. "
             "Regenerate it with `make audit` before reviewing.")
    st.stop()
plan = load_plan(PLAN)
drift = [row for row in reevaluate(bundle, plan) if row["stale"]]
live_findings = current_findings(bundle, plan)
scope = confirmation_scope(bundle)

left, middle, right = st.columns(3)
left.metric("Test cohort rows", bundle["test_cohort_rows"])
middle.metric("Registered tests", len(bundle["tests"]))
right.metric("Findings", len(bundle["findings"]))
st.caption(f"Evidence SHA-256: {bundle['sha256']} (recomputed and matched)")
st.info(bundle["provenance"]["split_warning"])
if drift:
    st.warning(f"The audit plan at {PLAN.name} differs from the one used for this bundle. "
               f"{len(drift)} test status(es) are stale: "
               + "; ".join(f"{row['test_id']} {row['stored_status']} → {row['current_status']} "
                           f"({row['reason']})" for row in drift)
               + ". Rerun `make audit` before relying on a status.")

findings, tests, charts, provenance = st.tabs(["Findings", "Tests", "Calibration and fairness", "Provenance"])
with findings:
    st.warning(f"Confirmation limit: {scope['label']}")
    if live_findings:
        columns = ["finding_id", "stored_status", "current_status", "metric", "observed",
                   "confirmation", "confirmation_value", "reason"]
        st.dataframe(pd.DataFrame(live_findings)[columns], width="stretch", hide_index=True)
        chosen = st.selectbox("Trace a finding to its evidence",
                              [finding["finding_id"] for finding in live_findings])
        finding = next(item for item in live_findings if item["finding_id"] == chosen)
        source_ref = trace(bundle, finding, f"runs/audit/{source.name}",
                           f"runs/workpapers/{name}.html")
        st.markdown(
            f"**{source_ref['finding_id']}** · `{source_ref['metric']}` observed "
            f"{source_ref['observed']} on {source_ref['test_cohort_rows']} test rows\n\n"
            f"Status: stored **{source_ref['stored_status']}**, under current plan "
            f"**{source_ref['current_status']}**\n\n"
            f"Confirmation: **{source_ref['confirmation']}** ({source_ref['confirmation_value']}) "
            f"on {source_ref['confirmation_source']}\n\n"
            f"Evidence: `{source_ref['evidence_file']}` → `{source_ref['evidence_key']}` · "
            f"workpaper section `{source_ref['workpaper']}`")
        with st.expander("Registered threshold and full measured values"):
            st.json(source_ref["threshold"])
            st.json(bundle["tests"][finding["test_id"]]["values"])
    else:
        st.success("No local review thresholds were crossed.")
    st.caption("A finding is a review flag under local thresholds; confirmation is cohort-specific.")
with tests:
    test_id = st.selectbox("Test ID", list(bundle["tests"]))
    test = bundle["tests"][test_id]
    status_row = next(row for row in reevaluate(bundle, plan) if row["test_id"] == test_id)
    st.write(f"Stored status: {test['status']} · under current plan: {status_row['current_status']}")
    st.json(test["threshold"])
    st.json(test["values"])
with charts:
    reliability = bundle["tests"]["CAL-ECE-01"]["values"]["reliability_bins"]
    st.line_chart(pd.DataFrame(reliability).set_index("predicted_rate")[["observed_rate"]])
    fair = bundle["tests"]["FAIR-SEX-01"]["values"]
    st.caption(f"Approval threshold: {fair['threshold']}; metric direction depends on group and label definition.")
    st.dataframe(pd.DataFrame.from_dict(fair["groups"], orient="index"), width="stretch")
    tradeoff = bundle["tests"]["FAIR-TRADEOFF"]["values"]["thresholds"]
    st.dataframe(pd.DataFrame([{k: row[k] for k in
                               ("threshold", "overall_approval_rate", "approved_observed_default_rate",
                                "equalized_odds_difference", "demographic_parity_difference")}
                              for row in tradeoff]), width="stretch")
with provenance:
    st.json(bundle["provenance"])
    st.write(bundle["scope"])
    st.write(f"Audit plan: {bundle['audit_plan']}")
    st.write(f"Confirmation source: {bundle['confirmation_source']}")
    st.write(f"Confirmation limit: {scope['label']}")
    st.write(f"Workpaper: runs/workpapers/{name}.html and .pdf")
