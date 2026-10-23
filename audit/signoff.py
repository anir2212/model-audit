"""Append-only reviewer sign-off log, kept outside the hashed evidence bundles.

A sign-off names who reviewed which exact bundle and workpaper, in what role, and what they
decided. It is stored as JSON Lines in `reviews/signoffs.jsonl` (ignored by Git; override
with `MODELAUDIT_SIGNOFF_LOG`). The bundle is never edited, so its SHA-256 stays valid.

Rules:
- A sign-off is refused unless the reviewer quotes the bundle's current SHA-256 and the
  current workpaper HTML SHA-256, the bundle digest verifies, no status is stale under the
  current plan, and the source archive rechecks as a match.
- Records are only appended. Each one carries the SHA-256 of the previous record, so an
  edited, reordered or deleted earlier line breaks the chain and is flagged on view.
  The chain is not a signature: someone with write access can rewrite the whole file, and
  removing the newest lines is not detectable without a copy kept elsewhere.
- When a bundle or workpaper later changes, its earlier sign-offs are shown as stale.

Usage:
  python -m audit.signoff show [--bundle german_xgb]
  python -m audit.signoff sign --bundle german_xgb --bundle-sha256 <hex> \
      --workpaper-sha256 <hex> --owner "Name" --role "Model validator" \
      --decision approve_with_conditions --condition "..." --date 2026-10-23
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from audit import paths
from audit.integrity import sha256_file, source_archive_check, workpaper_version
from audit.registry import load_plan
from audit.review import reevaluate, verify_digest

SCHEMA = "modelaudit-signoff/1"
DECISIONS = ("approve", "approve_with_conditions", "reject")
GENESIS = "0" * 64


class SignoffRefused(ValueError):
    def __init__(self, reasons: list[str]):
        super().__init__("sign-off refused: " + "; ".join(reasons))
        self.reasons = reasons


def _record_hash(record: dict) -> str:
    body = {key: value for key, value in record.items() if key != "record_sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_log(log_path: Path) -> tuple[list[dict], int | None, str]:
    """Return (records, index of the first record that fails the chain or None, problem text).

    Every line is returned, including those after a break, so the console can flag them all.
    An unparseable line becomes a placeholder record.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return [], None, ""
    records, previous, chain_break, problem = [], GENESIS, None, ""
    for number, line in enumerate(log_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            record = None
        index = len(records)
        records.append(record if isinstance(record, dict) else {"unparsed_line": number})
        if chain_break is not None:
            continue
        if not isinstance(record, dict):
            issue = f"line {number} is not a JSON object"
        elif record.get("schema") != SCHEMA:
            issue = f"line {number} is not a {SCHEMA} record"
        elif record.get("sequence") != index + 1:
            issue = f"line {number} has sequence {record.get('sequence')}, expected {index + 1}"
        elif record.get("prev_record_sha256") != previous:
            issue = f"line {number} does not chain to the previous record"
        elif record.get("record_sha256") != _record_hash(record):
            issue = f"line {number} was edited after it was written"
        else:
            previous = record["record_sha256"]
            continue
        chain_break, problem = index, issue
    return records, chain_break, problem


def _parse_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def blockers(request: dict, bundle: dict, plan: dict, workpaper: dict, source_check: dict,
             chain_break: int | None, today: dt.date) -> list[str]:
    """Every reason this sign-off request must be refused; empty means it may be recorded."""
    reasons = []
    for field in ("owner", "role"):
        if not str(request.get(field) or "").strip():
            reasons.append(f"{field} is required")
    decision = request.get("decision")
    conditions = [c.strip() for c in request.get("conditions") or [] if c and c.strip()]
    if decision not in DECISIONS:
        reasons.append(f"decision must be one of {', '.join(DECISIONS)}")
    elif decision == "approve_with_conditions" and not conditions:
        reasons.append("approve_with_conditions needs at least one condition")
    elif decision != "approve_with_conditions" and conditions:
        reasons.append(f"conditions are only recorded with approve_with_conditions, not {decision}")
    date = _parse_date(request.get("date"))
    if date is None:
        reasons.append("date must be an ISO date such as 2026-10-23")
    elif date > today:
        reasons.append(f"date {date} is in the future")
    if request.get("bundle") != f"{bundle.get('dataset')}_{bundle.get('model')}":
        reasons.append("bundle name does not match the bundle file")
    if not verify_digest(bundle):
        reasons.append("bundle digest does not verify; the evidence file was changed")
    elif request.get("bundle_sha256") != bundle["sha256"]:
        reasons.append("quoted bundle SHA-256 is not the current bundle hash (stale or wrong bundle)")
    if workpaper.get("html") is None or workpaper.get("pdf") is None:
        reasons.append("workpaper HTML or PDF is missing")
    elif request.get("workpaper_sha256") != workpaper["html"]:
        reasons.append("quoted workpaper SHA-256 is not the current workpaper HTML hash")
    stale = [row["test_id"] for row in reevaluate(bundle, plan) if row["stale"]]
    if stale:
        reasons.append("statuses are stale under the current plan: " + ", ".join(stale))
    if source_check["status"] != "match":
        reasons.append(f"source archive recheck is {source_check['status']}")
    if chain_break is not None:
        reasons.append("existing sign-off log fails its chain check; repair it before appending")
    return reasons


def append_signoff(log_path: Path, request: dict, bundle: dict, plan: dict, plan_sha256: str,
                   workpaper: dict, source_check: dict, today: dt.date | None = None,
                   now: dt.datetime | None = None) -> dict:
    """Validate and append one record. Raises `SignoffRefused` without writing anything."""
    today = today or dt.date.today()
    now = now or dt.datetime.now(dt.timezone.utc)
    log_path = Path(log_path)
    records, chain_break, _ = read_log(log_path)
    reasons = blockers(request, bundle, plan, workpaper, source_check, chain_break, today)
    if reasons:
        raise SignoffRefused(reasons)
    record = {
        "schema": SCHEMA, "sequence": len(records) + 1, "bundle": request["bundle"],
        "bundle_sha256": bundle["sha256"],
        "workpaper_sha256": {"html": workpaper["html"], "pdf": workpaper["pdf"]},
        "audit_plan_sha256": plan_sha256, "source_archive_sha256": source_check["actual"],
        "owner": request["owner"].strip(), "role": request["role"].strip(),
        "decision": request["decision"],
        "conditions": [c.strip() for c in request.get("conditions") or [] if c and c.strip()],
        "date": request["date"], "recorded_at": now.isoformat(timespec="seconds"),
        "prev_record_sha256": records[-1]["record_sha256"] if records else GENESIS,
    }
    record["record_sha256"] = _record_hash(record)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def assess(records: list[dict], chain_break: int | None, bundle_name: str, bundle_sha256: str,
           workpaper: dict, plan_sha256: str, source_sha256: str | None = None) -> dict:
    """Status of every sign-off for one bundle, newest first, and the effective decision.

    `source_sha256` is the source archive hash recomputed now (None when the file is missing,
    which is noted but does not by itself make a sign-off stale).
    """
    rows = []
    for index, record in enumerate(records):
        if record.get("bundle") != bundle_name and (chain_break is None or index < chain_break):
            continue
        if chain_break is not None and index >= chain_break:
            status, reason = "log_integrity_failed", "this or an earlier log line fails the chain check"
        elif record.get("bundle_sha256") != bundle_sha256:
            status, reason = "stale_bundle", "signed a different bundle hash than the one shown"
        elif record.get("workpaper_sha256", {}) != {"html": workpaper.get("html"), "pdf": workpaper.get("pdf")}:
            status, reason = "stale_workpaper", "the workpaper changed after this sign-off"
        elif source_sha256 is not None and record.get("source_archive_sha256") != source_sha256:
            status, reason = "stale_source", "the source archive on disk differs from the one signed"
        else:
            status, reason = "current", ""
        notes = []
        if status == "current" and record.get("audit_plan_sha256") != plan_sha256:
            notes.append("audit plan file changed since sign-off; check the stale-status banner")
        if status == "current" and source_sha256 is None:
            notes.append("source archive missing, so it was not rechecked against this sign-off")
        row = {key: record.get(key) for key in ("sequence", "bundle", "owner", "role", "decision",
                                                "conditions", "date", "recorded_at",
                                                "bundle_sha256", "workpaper_sha256")}
        row.update({"line_index": index, "status": status, "reason": reason, "notes": "; ".join(notes)})
        rows.append(row)
    rows.sort(key=lambda row: row["line_index"], reverse=True)
    effective = next((row for row in rows if row["status"] == "current"), None)
    return {"rows": rows, "effective": effective, "chain_ok": chain_break is None}


def _context(name: str):
    where = paths.resolve()
    bundle = json.loads((where["audit"] / f"{name}.json").read_text())
    plan = load_plan(where["plan"])
    return (where, bundle, plan, sha256_file(where["plan"]),
            workpaper_version(where["workpapers"], name), source_archive_check(bundle, where["raw"]))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show", help="list sign-offs and their status")
    show.add_argument("--bundle")
    sign = commands.add_parser("sign", help="append one sign-off record")
    sign.add_argument("--bundle", required=True)
    sign.add_argument("--bundle-sha256", required=True)
    sign.add_argument("--workpaper-sha256", required=True)
    sign.add_argument("--owner", required=True)
    sign.add_argument("--role", required=True)
    sign.add_argument("--decision", required=True, choices=DECISIONS)
    sign.add_argument("--condition", action="append", default=[])
    sign.add_argument("--date", required=True)
    args = parser.parse_args(argv)
    log_path = paths.resolve()["signoff_log"]
    if args.command == "show":
        records, chain_break, problem = read_log(log_path)
        if problem:
            print(f"Chain check failed: {problem}")
        names = [args.bundle] if args.bundle else sorted({r["bundle"] for r in records if r.get("bundle")})
        if not names:
            print(f"No sign-offs recorded in {log_path}.")
        for name in names:
            _, bundle, _, plan_sha, workpaper, source_check = _context(name)
            result = assess(records, chain_break, name, bundle["sha256"], workpaper, plan_sha,
                            source_check["actual"])
            print(name, "effective:", result["effective"]["decision"] if result["effective"] else "none")
            for row in result["rows"]:
                print(" ", json.dumps(row, sort_keys=True))
        return 0
    _, bundle, plan, plan_sha, workpaper, source_check = _context(args.bundle)
    request = {"bundle": args.bundle, "bundle_sha256": args.bundle_sha256,
               "workpaper_sha256": args.workpaper_sha256, "owner": args.owner, "role": args.role,
               "decision": args.decision, "conditions": args.condition, "date": args.date}
    try:
        record = append_signoff(log_path, request, bundle, plan, plan_sha, workpaper, source_check)
    except SignoffRefused as refused:
        print(refused, file=sys.stderr)
        return 2
    print(f"Recorded sign-off {record['sequence']} in {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
