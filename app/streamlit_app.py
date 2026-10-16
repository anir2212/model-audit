"""Local, read-only browser for measured ModelAudit evidence."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "runs/audit"

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

left, middle, right = st.columns(3)
left.metric("Test cohort rows", bundle["test_cohort_rows"])
middle.metric("Registered tests", len(bundle["tests"]))
right.metric("Findings", len(bundle["findings"]))
st.caption(f"Evidence SHA-256: {bundle['sha256']}")
st.info(bundle["provenance"]["split_warning"])

findings, tests, charts, provenance = st.tabs(["Findings", "Tests", "Calibration and fairness", "Provenance"])
with findings:
    if bundle["findings"]:
        st.dataframe(pd.DataFrame(bundle["findings"]), width="stretch")
    else:
        st.success("No local review thresholds were crossed.")
    st.caption("A finding is a review flag under local thresholds; confirmation is cohort-specific.")
with tests:
    test_id = st.selectbox("Test ID", list(bundle["tests"]))
    test = bundle["tests"][test_id]
    st.write(test["status"])
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
    st.write(f"Workpaper: runs/workpapers/{name}.html and .pdf")
