"""Local, read-only browser for measured ModelAudit evidence, file rechecks and sign-offs."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from audit import paths  # noqa: E402
from audit.integrity import sha256_file, source_archive_check, workpaper_checks  # noqa: E402
from audit.registry import load_plan  # noqa: E402
from audit.review import confirmation_scope, current_findings, reevaluate, trace, verify_digest  # noqa: E402
from audit.signoff import assess, read_log  # noqa: E402

WHERE = paths.resolve()
AUDIT, PLAN = WHERE["audit"], WHERE["plan"]

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
# Rechecked on every page load, not cached: the point is the state of the files right now.
source_check = source_archive_check(bundle, WHERE["raw"])
paper_checks = workpaper_checks(WHERE["workpapers"], name)
workpaper = {row["label"].split()[-1].lower(): row["actual"] for row in paper_checks}
records, chain_break, chain_problem = read_log(WHERE["signoff_log"])
signoffs = assess(records, chain_break, name, bundle["sha256"], workpaper, sha256_file(PLAN),
                  source_check["actual"])

left, middle, right = st.columns(3)
left.metric("Test cohort rows", bundle["test_cohort_rows"])
middle.metric("Registered tests", len(bundle["tests"]))
right.metric("Findings", len(bundle["findings"]))
st.caption(f"Evidence SHA-256: {bundle['sha256']} (recomputed and matched)")
st.info(bundle["provenance"]["split_warning"])
archive = Path(source_check["path"]).name
if source_check["status"] == "match":
    st.success(f"Source archive recheck: {archive} was hashed now and matches the bundle's recorded "
               "SHA-256.")
elif source_check["status"] == "missing":
    st.warning(f"Source archive missing: {archive} is not in {WHERE['raw']}, so it cannot be "
               "rechecked. Run `make data` to fetch and verify it.")
else:
    st.error(f"Source archive mismatch: {archive} now hashes to {source_check['actual'][:16]}…, but the "
             f"bundle recorded {str(source_check['expected'])[:16]}…. These results may not describe "
             "the file on disk.")
if not source_check["recorded_equals_pin"]:
    st.error("The bundle's recorded source hash differs from the pinned hash in data/fetch.py.")
if chain_problem:
    st.error(f"Sign-off log integrity failure: {chain_problem}. Affected records are flagged in the Integrity and sign-off tab.")
if signoffs["effective"]:
    current = signoffs["effective"]
    st.info(f"Current sign-off: {current['decision']} by {current['owner']} ({current['role']}) "
            f"on {current['date']}." + (f" Note: {current['notes']}." if current["notes"] else ""))
elif signoffs["rows"]:
    st.warning("No sign-off matches this bundle, workpaper and source archive as they are now; earlier sign-offs "
               "are stale. See the Integrity and sign-off tab.")
else:
    st.info("Sign-off: none recorded for this bundle.")
if drift:
    st.warning(f"The audit plan at {PLAN.name} differs from the one used for this bundle. "
               f"{len(drift)} test status(es) are stale: "
               + "; ".join(f"{row['test_id']} {row['stored_status']} → {row['current_status']} "
                           f"({row['reason']})" for row in drift)
               + ". Rerun `make audit` before relying on a status.")

findings, tests, charts, provenance, review = st.tabs(
    ["Findings", "Tests", "Calibration and fairness", "Provenance", "Integrity and sign-off"])
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
with review:
    st.subheader("Files rechecked when this page loaded")
    checks = [{"label": "evidence bundle (canonical digest)", "path": str(source),
               "status": "match", "expected": bundle["sha256"], "actual": bundle["sha256"],
               "detail": "recomputed digest equals the stored digest"}, source_check]
    reference = signoffs["effective"] or next(
        (row for row in signoffs["rows"] if row.get("bundle") == name), None)
    for row in paper_checks:
        row = dict(row)
        if row["status"] == "unrecorded" and reference:
            row["expected"] = (reference.get("workpaper_sha256") or {}).get(row["label"].split()[-1].lower())
            row["status"] = "match" if row["expected"] == row["actual"] else "mismatch"
            row["detail"] = f"compared with sign-off #{reference['sequence']} for this bundle"
        elif row["status"] == "unrecorded":
            row["detail"] = "no sign-off yet, so there is no recorded workpaper hash to compare"
        checks.append(row)
    st.dataframe(pd.DataFrame(checks)[["label", "status", "path", "expected", "actual", "detail"]],
                 width="stretch", hide_index=True)
    st.markdown(f"To sign, quote bundle SHA-256 `{bundle['sha256']}` and workpaper HTML SHA-256 "
                f"`{workpaper.get('html')}`.")
    st.subheader("Reviewer sign-offs")
    st.caption(f"Append-only log outside the hashed bundle: {WHERE['signoff_log']}. "
               "Records are added with `python -m audit.signoff sign`; this page does not write them.")
    if signoffs["rows"]:
        table = pd.DataFrame(signoffs["rows"]).reindex(columns=[
            "sequence", "status", "decision", "owner", "role", "date", "conditions", "reason",
            "notes", "bundle_sha256"])
        table["conditions"] = table["conditions"].map(lambda c: "; ".join(c) if isinstance(c, list) else "")
        st.dataframe(table, width="stretch", hide_index=True)
        stale = [row for row in signoffs["rows"] if row["status"] != "current"]
        if stale:
            st.warning(f"{len(stale)} sign-off(s) do not apply to this bundle as it is now: "
                       + "; ".join(f"record {row['line_index'] + 1} {row['status']}" for row in stale))
    else:
        st.write("No sign-off has been recorded for this bundle. The decision is open.")
