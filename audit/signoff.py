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
- An optional separately controlled head anchor can detect removal of newest lines or a
  consistently rewritten log. It does not authenticate the reviewer or protect itself.
- A record may carry an optional Ed25519 signature (see `audit/reviewer_signature.py`). The
  signature covers the chain link, and the record hash covers the signature, so a signature
  cannot be moved and cannot be removed from an earlier record without breaking later ones.
  It proves a key holder signed; it does not prove who holds the key. Without a signature the
  owner is unverified typed text. `MODELAUDIT_REQUIRE_SIGNATURE=1` withholds the effective
  decision unless the newest applicable record has a valid signature.

Usage:
  python -m audit.signoff show [--bundle german_xgb]
  python -m audit.signoff anchor [--output /separately/controlled/anchor.json]
  python -m audit.signoff keygen --private-key /outside/the/repo/reviewer.pem
  python -m audit.signoff key-add --key-id reviewer-2026 --public-key <base64> \
      --owner "Name" --role "Model validator"
  python -m audit.signoff key-revoke --key-id reviewer-2026 --date 2026-11-06
  python -m audit.signoff keys
  python -m audit.signoff sign --bundle german_xgb --bundle-sha256 <hex> \
      --workpaper-sha256 <hex> --owner "Name" --role "Model validator" \
      --decision approve_with_conditions --condition "..." --date 2026-10-23 \
      [--key-id reviewer-2026 --private-key /outside/the/repo/reviewer.pem]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

from audit import paths
from audit.integrity import sha256_file, source_archive_check, workpaper_version
from audit.registry import load_plan
from audit.review import reevaluate, verify_digest
from audit.reviewer_signature import (VALID, KeyFileRefused, add_key, fingerprint, generate_key_file,
                                      load_allowlist, load_private_key, public_key_text, revoke_key,
                                      sign_record, signer_problems, verify_record)

SCHEMA = "modelaudit-signoff/1"
DECISIONS = ("approve", "approve_with_conditions", "reject")
GENESIS = "0" * 64
ANCHOR_SCHEMA = "modelaudit-signoff-anchor/1"
ANCHOR_FAILURES = {"missing", "invalid", "truncated", "mismatch", "log_integrity_failed"}


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


def anchor_snapshot(records: list[dict], chain_break: int | None) -> dict:
    """Head of a valid nonempty log, to keep in a separately controlled location."""
    if chain_break is not None or not records:
        raise ValueError("a sign-off anchor needs a nonempty log with an intact chain")
    return {"schema": ANCHOR_SCHEMA, "record_count": len(records),
            "head_record_sha256": records[-1]["record_sha256"]}


def check_anchor(records: list[dict], chain_break: int | None,
                 anchor_path: Path | None) -> dict:
    """Check an externally kept head against the current log, including truncation."""
    if anchor_path is None:
        return {"status": "unconfigured", "detail": "no separate anchor configured"}
    path = Path(anchor_path)
    if not path.is_file():
        return {"status": "missing", "detail": "configured anchor file is missing"}
    try:
        anchor = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"status": "invalid", "detail": "anchor is not readable JSON"}
    if (not isinstance(anchor, dict) or anchor.get("schema") != ANCHOR_SCHEMA
            or type(anchor.get("record_count")) is not int or anchor["record_count"] < 1
            or not isinstance(anchor.get("head_record_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", anchor["head_record_sha256"]) is None):
        return {"status": "invalid", "detail": "anchor schema, count or hash is invalid"}
    count = anchor["record_count"]
    if chain_break is not None:
        return {"status": "log_integrity_failed", "detail": "sign-off log chain is broken",
                "anchored_records": count}
    if len(records) < count:
        return {"status": "truncated", "detail": "sign-off log has fewer records than the anchor",
                "anchored_records": count, "observed_records": len(records)}
    if records[count - 1]["record_sha256"] != anchor["head_record_sha256"]:
        return {"status": "mismatch", "detail": "anchored log head differs from the current chain",
                "anchored_records": count, "observed_records": len(records)}
    if len(records) > count:
        return {"status": "behind", "detail": "newer sign-offs are not covered by this anchor",
                "anchored_records": count, "observed_records": len(records)}
    return {"status": "match", "detail": "anchored log head matches",
            "anchored_records": count, "observed_records": len(records)}


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
                   now: dt.datetime | None = None, signer: dict | None = None) -> dict:
    """Validate and append one record. Raises `SignoffRefused` without writing anything.

    `signer` is optional: `key_id`, `private_key` and `allowlist`. With it, the record is signed
    after its chain link is set and before it is hashed.
    """
    today = today or dt.date.today()
    now = now or dt.datetime.now(dt.timezone.utc)
    log_path = Path(log_path)
    records, chain_break, _ = read_log(log_path)
    reasons = blockers(request, bundle, plan, workpaper, source_check, chain_break, today)
    if signer and not reasons:
        reasons = signer_problems(request["owner"].strip(), request["role"].strip(), signer["key_id"],
                                  signer["private_key"], signer["allowlist"])
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
    if signer:
        record = sign_record(record, signer["key_id"], signer["private_key"])
        checked = verify_record(record, signer["allowlist"])
        if checked["status"] != VALID:
            raise SignoffRefused([f"new signature did not verify: {checked['detail']}"])
    record["record_sha256"] = _record_hash(record)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def assess(records: list[dict], chain_break: int | None, bundle_name: str, bundle_sha256: str,
           workpaper: dict, plan_sha256: str, source_sha256: str | None = None,
           allowlist: dict | None = None) -> dict:
    """Status of every sign-off for one bundle, newest first, and the effective decision.

    `source_sha256` is the source archive hash recomputed now (None when the file is missing,
    which is noted but does not by itself make a sign-off stale). `status` says whether a record
    still applies to these files; `signature_status` separately says what its signature proves
    under `allowlist`. Signature status does not change `effective`; see `withheld_reason`.
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
        signature = verify_record(record, allowlist)
        row.update({"line_index": index, "status": status, "reason": reason, "notes": "; ".join(notes),
                    "signature_status": signature["status"], "signature_key_id": signature["key_id"],
                    "signature_detail": signature["detail"]})
        rows.append(row)
    rows.sort(key=lambda row: row["line_index"], reverse=True)
    effective = next((row for row in rows if row["status"] == "current"), None)
    return {"rows": rows, "effective": effective, "chain_ok": chain_break is None}


def withheld_reason(result: dict, anchored: dict, require_signature: bool) -> str | None:
    """Why the effective decision must not be shown, or None.

    With signatures required, the newest applicable record decides. There is no fallback to an
    older signed record, because that could revive a decision a newer record replaced.
    """
    if anchored["status"] in ANCHOR_FAILURES:
        return "the configured anchor does not verify"
    if require_signature:
        effective = result["effective"]
        if not result["chain_ok"]:
            return "signatures are required and the log chain is broken"
        if effective and effective["signature_status"] != VALID:
            return (f"signatures are required and record {effective['sequence']} is "
                    f"{effective['signature_status']}")
    return None


def _context(name: str):
    where = paths.resolve()
    bundle = json.loads((where["audit"] / f"{name}.json").read_text())
    plan = load_plan(where["plan"])
    return (where, bundle, plan, sha256_file(where["plan"]),
            workpaper_version(where["workpapers"], name), source_archive_check(bundle, where["raw"]))


def _key_command(args, allowlist_path: Path) -> int:
    try:
        if args.command == "keygen":
            public = public_key_text(generate_key_file(args.private_key, paths.ROOT))
            print(f"Wrote private key to {args.private_key} (owner read/write only). It is not "
                  "passphrase-protected, so protect that file and never share or commit it.")
            print(f"Public key: {public}")
            print(f"Fingerprint (SHA-256): {fingerprint(public)}")
            print("List it with: python -m audit.signoff key-add --key-id <id> "
                  f'--public-key {public} --owner "Name" --role "Role"')
        elif args.command == "key-add":
            entry = add_key(allowlist_path, args.key_id, args.public_key, args.owner, args.role)
            print(f"Listed key {args.key_id} for {entry['name']} ({entry['role']}) in {allowlist_path}. "
                  f"Fingerprint: {fingerprint(args.public_key)}. Listing does not verify who holds the key.")
        elif args.command == "key-revoke":
            revoke_key(allowlist_path, args.key_id, args.date)
            print(f"Revoked key {args.key_id} on {args.date}; all its signatures now report revoked_key.")
        else:
            allowlist = load_allowlist(allowlist_path)
            print(f"Reviewer keys: {allowlist['status']} — {allowlist['detail']}")
            for key_id, entry in sorted(allowlist["keys"].items()):
                state = f"revoked {entry['revoked_on']}" if entry["revoked_on"] else "active"
                print(f"  {key_id}: {entry['name']} ({entry['role']}) {state} "
                      f"fingerprint {fingerprint(entry['public_key'])}")
    except KeyFileRefused as refused:
        print(f"refused: {refused}", file=sys.stderr)
        return 2
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show", help="list sign-offs and their status")
    show.add_argument("--bundle")
    anchor = commands.add_parser("anchor", help="export the current log head for separate storage")
    anchor.add_argument("--output", type=Path, help="create this new file; refuse to overwrite it")
    sign = commands.add_parser("sign", help="append one sign-off record")
    sign.add_argument("--bundle", required=True)
    sign.add_argument("--bundle-sha256", required=True)
    sign.add_argument("--workpaper-sha256", required=True)
    sign.add_argument("--owner", required=True)
    sign.add_argument("--role", required=True)
    sign.add_argument("--decision", required=True, choices=DECISIONS)
    sign.add_argument("--condition", action="append", default=[])
    sign.add_argument("--date", required=True)
    sign.add_argument("--key-id", help="allowlisted key ID; use with --private-key to sign the record")
    sign.add_argument("--private-key", type=Path, help="owner-only private-key file outside the repository")
    keygen = commands.add_parser("keygen", help="create a private-key file outside the repository")
    keygen.add_argument("--private-key", type=Path, required=True)
    key_add = commands.add_parser("key-add", help="list a reviewer public key in the allowlist")
    key_add.add_argument("--key-id", required=True)
    key_add.add_argument("--public-key", required=True, help="Base64 printed by keygen")
    key_add.add_argument("--owner", required=True)
    key_add.add_argument("--role", required=True)
    key_revoke = commands.add_parser("key-revoke", help="mark a listed key revoked")
    key_revoke.add_argument("--key-id", required=True)
    key_revoke.add_argument("--date", required=True)
    commands.add_parser("keys", help="list the reviewer key allowlist")
    args = parser.parse_args(argv)
    where = paths.resolve()
    log_path = where["signoff_log"]
    if args.command in {"keygen", "key-add", "key-revoke", "keys"}:
        return _key_command(args, where["reviewer_keys"])
    if args.command == "anchor":
        records, chain_break, _ = read_log(log_path)
        try:
            snapshot = anchor_snapshot(records, chain_break)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
        payload = json.dumps(snapshot, indent=2) + "\n"
        if args.output:
            try:
                with args.output.open("x") as handle:
                    handle.write(payload)
            except OSError as exc:
                print(f"anchor not written: {exc}", file=sys.stderr)
                return 2
            print(f"Wrote anchor to {args.output}; keep it in a separately controlled, append-only location.")
        else:
            print(payload, end="")
        return 0
    if args.command == "show":
        records, chain_break, problem = read_log(log_path)
        if problem:
            print(f"Chain check failed: {problem}")
        anchored = check_anchor(records, chain_break, where.get("signoff_anchor"))
        print(f"Anchor: {anchored['status']} — {anchored['detail']}")
        allowlist = load_allowlist(where["reviewer_keys"])
        required = paths.require_signature()
        print(f"Reviewer keys: {allowlist['status']} — {allowlist['detail']}")
        print(f"Signatures: {'required' if required else 'optional'}. A valid signature proves a key "
              "holder signed, not who holds the key or how carefully they reviewed.")
        names = [args.bundle] if args.bundle else sorted({r["bundle"] for r in records if r.get("bundle")})
        if not names:
            print(f"No sign-offs recorded in {log_path}.")
        for name in names:
            _, bundle, _, plan_sha, workpaper, source_check = _context(name)
            result = assess(records, chain_break, name, bundle["sha256"], workpaper, plan_sha,
                            source_check["actual"], allowlist)
            withheld = withheld_reason(result, anchored, required)
            if withheld:
                print(name, f"effective: withheld ({withheld})")
            elif result["effective"]:
                print(name, "effective:", result["effective"]["decision"],
                      f"[signature: {result['effective']['signature_status']}]")
            else:
                print(name, "effective: none")
            for row in result["rows"]:
                print(f"  record {row['line_index'] + 1}: integrity={row['status']} "
                      f"signature={row['signature_status']} key={row['signature_key_id']}")
                print(" ", json.dumps(row, sort_keys=True))
        return 0
    records, chain_break, _ = read_log(log_path)
    anchored = check_anchor(records, chain_break, where.get("signoff_anchor"))
    if anchored["status"] in ANCHOR_FAILURES:
        print(f"sign-off refused: anchor {anchored['status']}: {anchored['detail']}", file=sys.stderr)
        return 2
    if bool(args.key_id) != bool(args.private_key):
        print("sign-off refused: --key-id and --private-key must be given together", file=sys.stderr)
        return 2
    signer = None
    if args.private_key:
        try:
            signer = {"key_id": args.key_id, "private_key": load_private_key(args.private_key, paths.ROOT),
                      "allowlist": load_allowlist(where["reviewer_keys"])}
        except KeyFileRefused as refused:
            print(f"sign-off refused: {refused}", file=sys.stderr)
            return 2
    elif paths.require_signature():
        print("sign-off refused: MODELAUDIT_REQUIRE_SIGNATURE is on, so give --key-id and --private-key",
              file=sys.stderr)
        return 2
    _, bundle, plan, plan_sha, workpaper, source_check = _context(args.bundle)
    request = {"bundle": args.bundle, "bundle_sha256": args.bundle_sha256,
               "workpaper_sha256": args.workpaper_sha256, "owner": args.owner, "role": args.role,
               "decision": args.decision, "conditions": args.condition, "date": args.date}
    try:
        record = append_signoff(log_path, request, bundle, plan, plan_sha, workpaper, source_check,
                                signer=signer)
    except SignoffRefused as refused:
        print(refused, file=sys.stderr)
        return 2
    how = f"signed with key {args.key_id}" if signer else "unsigned; the reviewer name is unverified typed text"
    print(f"Recorded sign-off {record['sequence']} in {log_path} ({how})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
