"""Sign-off log tests. Every record here is an EXAMPLE written to a temporary folder."""
import json
from pathlib import Path

import pytest

from audit.signoff import GENESIS, SignoffRefused, append_signoff, assess, main, read_log
from conftest import EXAMPLE_OWNER, TODAY, redigest

ROOT = Path(__file__).resolve().parents[1]


def _append(case, request=None, bundle=None, plan=None, workpaper=None, source=None):
    return append_signoff(case.log, request or case.request(), bundle or case.bundle,
                          plan or case.plan, case.plan_sha, workpaper or case.workpaper(),
                          source or case.source_match, today=TODAY)


def _refused(case, **kwargs):
    with pytest.raises(SignoffRefused) as error:
        _append(case, **kwargs)
    assert not case.log.exists()
    return " ".join(error.value.reasons)


def test_valid_example_signoff_is_appended_and_current(signoff_case):
    record = _append(signoff_case)
    assert record["sequence"] == 1 and record["prev_record_sha256"] == GENESIS
    assert record["bundle_sha256"] == signoff_case.bundle["sha256"]
    assert record["workpaper_sha256"] == signoff_case.workpaper()
    assert record["owner"] == EXAMPLE_OWNER and record["decision"] == "approve_with_conditions"
    records, chain_break, problem = read_log(signoff_case.log)
    assert records == [record] and chain_break is None and not problem
    result = assess(records, chain_break, "german_xgb", signoff_case.bundle["sha256"],
                    signoff_case.workpaper(), signoff_case.plan_sha)
    assert result["effective"]["sequence"] == 1 and result["rows"][0]["status"] == "current"
    # The hashed bundle itself is untouched by signing.
    assert json.loads((signoff_case.audit / "german_xgb.json").read_text()) == signoff_case.bundle


def test_log_is_append_only_and_chained(signoff_case):
    first = _append(signoff_case)
    before = signoff_case.log.read_bytes()
    second = _append(signoff_case, request=signoff_case.request(decision="reject", conditions=[]))
    assert signoff_case.log.read_bytes().startswith(before)
    assert second["sequence"] == 2 and second["prev_record_sha256"] == first["record_sha256"]
    result = assess(read_log(signoff_case.log)[0], None, "german_xgb", signoff_case.bundle["sha256"],
                    signoff_case.workpaper(), signoff_case.plan_sha)
    assert result["effective"]["decision"] == "reject"
    assert [row["sequence"] for row in result["rows"]] == [2, 1]


def test_stale_quoted_bundle_hash_is_refused(signoff_case):
    reasons = _refused(signoff_case, request=signoff_case.request(bundle_sha256="0" * 64))
    assert "not the current bundle hash" in reasons


def test_changed_bundle_is_refused(signoff_case):
    edited = dict(signoff_case.bundle, scope="edited after the audit")
    assert "digest does not verify" in _refused(signoff_case, bundle=edited)


def test_wrong_or_missing_workpaper_is_refused(signoff_case):
    assert "workpaper HTML hash" in _refused(signoff_case,
                                             request=signoff_case.request(workpaper_sha256="f" * 64))
    assert "missing" in _refused(signoff_case, workpaper={"html": None, "pdf": None})


def test_stale_plan_is_refused(signoff_case):
    plan = {"thresholds": dict(signoff_case.plan["thresholds"],
                               **{"CAL-ECE-01": {"metric": "ece", "warn_above": 0.5, "fail_above": 0.6}})}
    assert "stale under the current plan: CAL-ECE-01" in _refused(signoff_case, plan=plan)


@pytest.mark.parametrize("status", ["mismatch", "missing"])
def test_source_archive_problem_is_refused(signoff_case, status):
    assert f"source archive recheck is {status}" in _refused(
        signoff_case, source={"status": status, "actual": None})


@pytest.mark.parametrize("changes, message", [
    ({"decision": "approved"}, "decision must be one of"),
    ({"conditions": []}, "needs at least one condition"),
    ({"decision": "approve"}, "only recorded with approve_with_conditions"),
    ({"owner": "  "}, "owner is required"),
    ({"role": ""}, "role is required"),
    ({"date": "23/10/2026"}, "ISO date"),
    ({"date": "2026-10-24"}, "in the future"),
    ({"bundle": "german_scorecard"}, "bundle name does not match"),
])
def test_request_fields_are_validated(signoff_case, changes, message):
    assert message in _refused(signoff_case, request=signoff_case.request(**changes))


def test_signoff_becomes_stale_when_bundle_or_workpaper_changes(signoff_case):
    _append(signoff_case)
    records, chain_break, _ = read_log(signoff_case.log)
    rerun = redigest(dict(signoff_case.bundle, scope="regenerated bundle"))
    stale = assess(records, chain_break, "german_xgb", rerun["sha256"], signoff_case.workpaper(),
                   signoff_case.plan_sha)
    assert stale["effective"] is None and stale["rows"][0]["status"] == "stale_bundle"
    changed_paper = dict(signoff_case.workpaper(), html="e" * 64)
    stale = assess(records, chain_break, "german_xgb", signoff_case.bundle["sha256"], changed_paper,
                   signoff_case.plan_sha)
    assert stale["rows"][0]["status"] == "stale_workpaper"
    noted = assess(records, chain_break, "german_xgb", signoff_case.bundle["sha256"],
                   signoff_case.workpaper(), "d" * 64)
    assert noted["rows"][0]["status"] == "current" and "plan file changed" in noted["rows"][0]["notes"]
    replaced = assess(records, chain_break, "german_xgb", signoff_case.bundle["sha256"],
                      signoff_case.workpaper(), signoff_case.plan_sha, "c" * 64)
    assert replaced["rows"][0]["status"] == "stale_source" and replaced["effective"] is None
    unchecked = assess(records, chain_break, "german_xgb", signoff_case.bundle["sha256"],
                       signoff_case.workpaper(), signoff_case.plan_sha, None)
    assert unchecked["rows"][0]["status"] == "current" and "not rechecked" in unchecked["rows"][0]["notes"]
    same = assess(records, chain_break, "german_xgb", signoff_case.bundle["sha256"],
                  signoff_case.workpaper(), signoff_case.plan_sha, signoff_case.source_match["actual"])
    assert same["rows"][0]["status"] == "current" and not same["rows"][0]["notes"]
    other = assess(records, chain_break, "taiwan_xgb", "x", {}, signoff_case.plan_sha)
    assert other == {"rows": [], "effective": None, "chain_ok": True}


@pytest.mark.parametrize("damage", ["edit", "delete_first", "garbage"])
def test_damaged_log_is_flagged_and_blocks_appending(signoff_case, damage):
    _append(signoff_case)
    _append(signoff_case, request=signoff_case.request(decision="reject", conditions=[]))
    lines = signoff_case.log.read_text().splitlines()
    if damage == "edit":
        first = json.loads(lines[0])
        first["decision"] = "approve"
        first["conditions"] = []
        lines[0] = json.dumps(first, sort_keys=True)
    elif damage == "delete_first":
        lines = lines[1:]
    else:
        lines.insert(1, "{not json")
    signoff_case.log.write_text("\n".join(lines) + "\n")
    records, chain_break, problem = read_log(signoff_case.log)
    assert chain_break is not None and problem
    result = assess(records, chain_break, "german_xgb", signoff_case.bundle["sha256"],
                    signoff_case.workpaper(), signoff_case.plan_sha)
    assert not result["chain_ok"] and "log_integrity_failed" in {r["status"] for r in result["rows"]}
    if damage != "garbage":
        assert result["effective"] is None
    with pytest.raises(SignoffRefused, match="chain check"):
        _append(signoff_case)


def test_command_line_refuses_stale_hash_and_records_valid_example(signoff_case, monkeypatch, capsys):
    monkeypatch.setenv("MODELAUDIT_AUDIT_DIR", str(signoff_case.audit))
    monkeypatch.setenv("MODELAUDIT_WORKPAPER_DIR", str(signoff_case.workpapers))
    monkeypatch.setenv("MODELAUDIT_SIGNOFF_LOG", str(signoff_case.log))
    monkeypatch.setattr("audit.signoff.source_archive_check", lambda bundle, raw: signoff_case.source_match)
    base = ["sign", "--bundle", "german_xgb", "--workpaper-sha256", signoff_case.workpaper()["html"],
            "--owner", EXAMPLE_OWNER, "--role", "Example validator (test only)",
            "--decision", "reject", "--date", "2026-10-01"]
    assert main(base + ["--bundle-sha256", "0" * 64]) == 2 and not signoff_case.log.exists()
    assert main(base + ["--bundle-sha256", signoff_case.bundle["sha256"]]) == 0
    assert main(["show", "--bundle", "german_xgb"]) == 0
    assert "effective: reject" in capsys.readouterr().out


def test_repository_ships_only_an_empty_template():
    template = json.loads((ROOT / "reviews/signoff_template.json").read_text())
    assert template["owner"] == "" and template["decision"] == "" and template["date"] == ""
    assert template["sequence"] is None and template["conditions"] == []
    assert "/reviews/signoffs.jsonl" in (ROOT / ".gitignore").read_text().splitlines()
