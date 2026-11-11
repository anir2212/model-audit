"""Signature tests. Every key, allowlist and sign-off here is a temporary EXAMPLE.

No real reviewer signed anything and no real key was issued. Keys are generated at run time
inside pytest's temporary folder and are never written to the repository.
"""
import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit import paths
from audit.reviewer_signature import (ALLOWLIST_SCHEMA, SIGNATURE_DOMAIN, KeyFileRefused, add_key,
                                      canonical_bytes, generate_key_file, load_allowlist,
                                      load_private_key, public_key_text, revoke_key, sign_record,
                                      signing_payload, verify_record)
from audit.signoff import (GENESIS, SignoffRefused, _record_hash, append_signoff, assess, main,
                           read_log, withheld_reason)
from conftest import EXAMPLE_OWNER, TODAY

ROOT = Path(__file__).resolve().parents[1]
ROLE = "Example validator (test only)"
UNCHECKED_ANCHOR = {"status": "unconfigured", "detail": ""}


class Keyed:
    """A sign-off case with one EXAMPLE reviewer key, listed in a temporary allowlist."""

    def __init__(self, case, folder: Path):
        self.case, self.folder = case, folder
        self.keys = folder / "reviewer_keys.json"
        self.pem = folder / "example_reviewer.pem"
        self.public = public_key_text(generate_key_file(self.pem, ROOT))
        self.private = load_private_key(self.pem, ROOT)
        add_key(self.keys, "example-key", self.public, EXAMPLE_OWNER, ROLE)

    def allowlist(self):
        return load_allowlist(self.keys)

    def signer(self, key_id="example-key", private=None):
        return {"key_id": key_id, "private_key": private or self.private, "allowlist": self.allowlist()}

    def append(self, signer="default", **request):
        case = self.case
        return append_signoff(case.log, case.request(**request), case.bundle, case.plan, case.plan_sha,
                              case.workpaper(), case.source_match, today=TODAY,
                              signer=self.signer() if signer == "default" else signer)

    def rows(self):
        case = self.case
        records, broken, _ = read_log(case.log)
        return assess(records, broken, case.name, case.bundle["sha256"], case.workpaper(), case.plan_sha,
                      None, self.allowlist())

    def status(self):
        return [row["signature_status"] for row in self.rows()["rows"]]

    def rewrite(self, records):
        """Rewrite the whole log so its chain verifies, as someone with write access could."""
        previous, lines = GENESIS, []
        for number, record in enumerate(records, start=1):
            record = {k: v for k, v in record.items() if k != "record_sha256"}
            record.update(sequence=number, prev_record_sha256=previous)
            record["record_sha256"] = previous = _record_hash(record)
            lines.append(json.dumps(record, sort_keys=True))
        self.case.log.write_text("\n".join(lines) + "\n")
        assert read_log(self.case.log)[1] is None


@pytest.fixture
def keyed(signoff_case, tmp_path):
    return Keyed(signoff_case, tmp_path)


def _rehashed_with_signature(keyed, record, key_id, private):
    """A chain-valid line signed with `private` for the given claimed content."""
    body = sign_record({k: v for k, v in record.items() if k != "record_sha256"}, key_id, private)
    keyed.rewrite([body])


# Canonical form

def test_canonical_bytes_ignore_key_order_and_are_pinned():
    first = {"b": [1, {"y": None, "x": True}], "a": "é\n\""}
    second = {"a": "é\n\"", "b": [1, {"x": True, "y": None}]}
    expected = '{"a":"é\\n\\"","b":[1,{"x":true,"y":null}]}'.encode()
    assert canonical_bytes(first) == canonical_bytes(second) == expected


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf"), 2 ** 53, b"bytes", {1: "x"},
                                   {"nested": [1.5]}, "\ud800"])
def test_canonical_bytes_reject_values_without_one_stable_form(value):
    with pytest.raises(ValueError):
        canonical_bytes(value)


def test_signing_payload_covers_the_whole_record_except_derived_fields():
    record = {"sequence": 2, "prev_record_sha256": "aa", "owner": "EXAMPLE", "extra": "x",
              "record_sha256": "bb",
              "signature": {"algorithm": "ed25519", "key_id": "k", "value": "cc"}}
    # Pinned: changing this format would invalidate every signature already in a log.
    assert signing_payload(record) == (
        b'modelaudit-signoff-signature/1\n{"extra":"x","owner":"EXAMPLE","prev_record_sha256":"aa",'
        b'"sequence":2,"signature":{"algorithm":"ed25519","key_id":"k"}}')
    assert signing_payload(record).startswith(SIGNATURE_DOMAIN)


# The required verification outcomes

def test_valid_signature_from_listed_key(keyed):
    record = keyed.append()
    assert record["signature"]["key_id"] == "example-key" and record["signature"]["algorithm"] == "ed25519"
    result = keyed.rows()
    row = result["rows"][0]
    assert row["status"] == "current" and row["signature_status"] == "valid"
    assert "does not prove who holds the key" in row["signature_detail"]
    assert result["effective"]["sequence"] == 1
    assert withheld_reason(result, UNCHECKED_ANCHOR, require_signature=True) is None


def test_legacy_unsigned_record_stays_readable_and_is_never_presented_as_signed(keyed):
    # A record as written before signatures existed: no signature field, same schema and hash.
    keyed.append(signer=None)
    line = json.loads(keyed.case.log.read_text())
    assert "signature" not in line
    assert keyed.status() == ["unsigned"]
    row = keyed.rows()["rows"][0]
    assert row["signature_key_id"] is None and "typed text" in row["signature_detail"]
    assert keyed.rows()["effective"]["sequence"] == 1  # default behaviour is unchanged


def test_forged_signature_without_the_private_key_fails(keyed):
    record = keyed.append(signer=None)
    attacker = Ed25519PrivateKey.generate()
    _rehashed_with_signature(keyed, record, "example-key", attacker)
    assert keyed.status() == ["bad_signature"]
    record = json.loads(keyed.case.log.read_text())
    record["signature"]["value"] = "A" * 86 + "=="
    keyed.rewrite([record])
    assert keyed.status() == ["bad_signature"]


@pytest.mark.parametrize("change", [
    {"decision": "approve", "conditions": []}, {"owner": "Someone else"}, {"role": "Other role"},
    {"bundle_sha256": "0" * 64}, {"date": "2026-01-01"}, {"recorded_at": "2026-01-01T00:00:00+00:00"},
    {"workpaper_sha256": {"html": "0" * 64, "pdf": "0" * 64}}, {"added_field": "x"},
])
def test_altered_record_fails_even_when_the_chain_is_rebuilt(keyed, change):
    record = keyed.append()
    keyed.rewrite([{**record, **change}])
    assert keyed.status() == ["bad_signature"]


def test_signature_cannot_be_moved_to_another_position_or_chain(keyed):
    first = keyed.append(signer=None)
    second = keyed.append(decision="reject", conditions=[])
    assert keyed.status() == ["valid", "unsigned"]
    # Removing the record before it moves the signed record to sequence 1 with a new link.
    keyed.rewrite([second])
    assert keyed.status() == ["bad_signature"]
    # Same sequence, different previous record: the signed link no longer holds.
    keyed.rewrite([{**first, "conditions": ["Different earlier record"]}, second])
    assert keyed.status()[0] == "bad_signature"


def test_signature_cannot_be_reassigned_to_another_listed_key(keyed):
    other = Ed25519PrivateKey.generate()
    add_key(keyed.keys, "other-key", public_key_text(other.public_key()), EXAMPLE_OWNER + " 2", ROLE)
    record = keyed.append()
    record["signature"]["key_id"] = "other-key"
    keyed.rewrite([record])
    assert keyed.status() == ["bad_signature"]


def test_wrong_key_fails(keyed):
    keyed.append()
    document = json.loads(keyed.keys.read_text())
    document["keys"]["example-key"]["public_key"] = public_key_text(
        Ed25519PrivateKey.generate().public_key())
    keyed.keys.write_text(json.dumps(document))
    assert keyed.status() == ["bad_signature"]


def test_unknown_key_and_missing_allowlist(keyed):
    keyed.append()
    document = json.loads(keyed.keys.read_text())
    document["keys"] = {}
    keyed.keys.write_text(json.dumps(document))
    assert keyed.status() == ["unknown_key"]
    keyed.keys.unlink()
    assert keyed.status() == ["unknown_key"]
    records = read_log(keyed.case.log)[0]
    assert verify_record(records[0])["status"] == "unknown_key"  # no allowlist given at all


def test_claimed_name_or_role_not_matching_the_listing_is_flagged(keyed):
    record = keyed.append(signer=None)
    _rehashed_with_signature(keyed, {**record, "owner": "Claimed other name"}, "example-key", keyed.private)
    assert keyed.status() == ["name_mismatch"]
    _rehashed_with_signature(keyed, {**record, "role": "Claimed other role"}, "example-key", keyed.private)
    assert keyed.status() == ["role_mismatch"]


def test_revoked_key_stops_counting_for_all_its_records_and_cannot_sign(keyed):
    keyed.append()
    assert keyed.status() == ["valid"]
    revoke_key(keyed.keys, "example-key", "2026-11-06")
    assert keyed.status() == ["revoked_key"]
    assert withheld_reason(keyed.rows(), UNCHECKED_ANCHOR, True) is not None
    with pytest.raises(KeyFileRefused, match="already revoked"):
        revoke_key(keyed.keys, "example-key", "2026-11-07")
    with pytest.raises(SignoffRefused, match="revoked"):
        keyed.append()
    assert len(read_log(keyed.case.log)[0]) == 1


def test_removing_a_signature_downgrades_only_visibly(keyed):
    first = keyed.append()
    second = keyed.append(decision="reject", conditions=[])
    assert keyed.status() == ["valid", "valid"]
    # Stripping the newest record's signature and rehashing is possible for a log writer. It reads
    # as unsigned, never as valid, and the requirement option withholds it.
    keyed.rewrite([first, {k: v for k, v in second.items() if k != "signature"}])
    assert keyed.status() == ["unsigned", "valid"]
    assert "unsigned" in withheld_reason(keyed.rows(), UNCHECKED_ANCHOR, True)
    # Stripping an earlier record changes its hash, so the later signed link fails.
    keyed.rewrite([{k: v for k, v in first.items() if k != "signature"}, second])
    assert keyed.status() == ["bad_signature", "unsigned"]


@pytest.mark.parametrize("block", [
    None, "text", {}, {"algorithm": "ed25519", "key_id": "example-key"},
    {"algorithm": "rsa", "key_id": "example-key", "value": "A" * 86 + "=="},
    {"algorithm": "ed25519", "key_id": 7, "value": "A" * 86 + "=="},
    {"algorithm": "ed25519", "key_id": "example-key", "value": "not base64"},
    {"algorithm": "ed25519", "key_id": "example-key", "value": "AAAA"},
])
def test_malformed_signature_block_is_bad_never_unsigned(keyed, block):
    record = keyed.append()
    keyed.rewrite([{**record, "signature": block}])
    assert keyed.status() == ["bad_signature"]


def test_noncanonical_values_fail_rather_than_verify(keyed):
    record = keyed.append()
    assert verify_record({**record, "sequence": 1.0}, keyed.allowlist())["status"] == "bad_signature"
    # The last character before "==" has four unused bits, so this is a second spelling of the
    # same 64 bytes. It is refused so that a signature value has only one accepted form.
    value = record["signature"]["value"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    respelled = value[:-3] + alphabet[alphabet.index(value[-3]) | 1] + "=="
    assert respelled != value and base64.b64decode(respelled) == base64.b64decode(value)
    tampered = {**record, "signature": {**record["signature"], "value": respelled}}
    assert verify_record(tampered, keyed.allowlist())["status"] == "bad_signature"


def test_unparsed_line_has_no_signature_claim(keyed):
    keyed.append()
    keyed.case.log.write_text("{not json\n" + keyed.case.log.read_text())
    assert "unreadable" in {row["signature_status"] for row in keyed.rows()["rows"]}


# Sign-time refusals

@pytest.mark.parametrize("request_change, message", [
    ({"owner": "Someone else"}, "does not match the name"),
    ({"role": "Other role"}, "does not match the role"),
])
def test_signing_refuses_a_claim_that_differs_from_the_listing(keyed, request_change, message):
    with pytest.raises(SignoffRefused, match=message):
        keyed.append(**request_change)
    assert not keyed.case.log.exists()


def test_signing_refuses_wrong_private_key_and_unlisted_key(keyed):
    with pytest.raises(SignoffRefused, match="does not match the public key"):
        keyed.append(signer=keyed.signer(private=Ed25519PrivateKey.generate()))
    with pytest.raises(SignoffRefused, match="not in the reviewer key allowlist"):
        keyed.append(signer=keyed.signer(key_id="unlisted"))
    keyed.keys.unlink()
    with pytest.raises(SignoffRefused, match="allowlist is missing"):
        keyed.append()
    assert not keyed.case.log.exists()


# The requirement option

def test_requirement_option_withholds_and_default_does_not(keyed):
    keyed.append(signer=None)
    result = keyed.rows()
    assert withheld_reason(result, UNCHECKED_ANCHOR, False) is None
    assert "record 1 is unsigned" in withheld_reason(result, UNCHECKED_ANCHOR, True)
    assert "anchor" in withheld_reason(result, {"status": "truncated", "detail": ""}, False)
    assert withheld_reason({"rows": [], "effective": None, "chain_ok": True}, UNCHECKED_ANCHOR, True) is None


def test_requirement_does_not_fall_back_to_an_older_signed_record(keyed):
    keyed.append(decision="reject", conditions=[])
    keyed.append(signer=None)
    result = keyed.rows()
    assert result["effective"]["sequence"] == 2
    assert "record 2 is unsigned" in withheld_reason(result, UNCHECKED_ANCHOR, True)
    keyed.append()  # a newer valid record ends the withholding; old unsigned ones do not block it
    assert withheld_reason(keyed.rows(), UNCHECKED_ANCHOR, True) is None


def test_requirement_withholds_on_a_broken_chain(keyed):
    keyed.append()
    keyed.case.log.write_text(keyed.case.log.read_text() + "{not json\n")
    result = keyed.rows()
    assert result["effective"] is not None and not result["chain_ok"]
    assert "chain is broken" in withheld_reason(result, UNCHECKED_ANCHOR, True)
    assert withheld_reason(result, UNCHECKED_ANCHOR, False) is None


@pytest.mark.parametrize("value, expected", [(None, False), ("", False), ("0", False), ("false", False),
                                             ("OFF", False), ("no", False), ("1", True), ("true", True),
                                             ("anything else", True)])
def test_requirement_setting_fails_closed(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("MODELAUDIT_REQUIRE_SIGNATURE", raising=False)
    else:
        monkeypatch.setenv("MODELAUDIT_REQUIRE_SIGNATURE", value)
    assert paths.require_signature() is expected


# Key files

def test_keygen_writes_owner_only_key_that_loads(tmp_path):
    path = tmp_path / "example.pem"
    public = generate_key_file(path, ROOT)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert public_key_text(load_private_key(path, ROOT).public_key()) == public_key_text(public)


def test_keygen_permissions_hold_under_a_permissive_umask(tmp_path):
    previous = os.umask(0)
    try:
        generate_key_file(tmp_path / "example.pem", ROOT)
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "example.pem").stat().st_mode) == 0o600


def test_keygen_refuses_to_overwrite_file_or_symlink(tmp_path):
    path = tmp_path / "example.pem"
    generate_key_file(path, ROOT)
    original = path.read_bytes()
    with pytest.raises(KeyFileRefused, match="refusing to overwrite"):
        generate_key_file(path, ROOT)
    assert path.read_bytes() == original
    link = tmp_path / "link.pem"
    link.symlink_to(tmp_path / "target_that_does_not_exist")
    with pytest.raises(KeyFileRefused, match="refusing to overwrite"):
        generate_key_file(link, ROOT)
    assert not (tmp_path / "target_that_does_not_exist").exists()


def test_keygen_refuses_any_git_working_tree_and_missing_folder(tmp_path):
    inside = ROOT / "reviews" / "must_not_exist_example.pem"
    with pytest.raises(KeyFileRefused, match="inside this repository"):
        generate_key_file(inside, ROOT)
    assert not inside.exists()
    other = tmp_path / "other_repo"
    (other / ".git").mkdir(parents=True)
    (other / "sub").mkdir()
    with pytest.raises(KeyFileRefused, match="inside the Git working tree"):
        generate_key_file(other / "sub" / "example.pem", ROOT)
    assert not (other / "sub" / "example.pem").exists()
    with pytest.raises(KeyFileRefused, match="does not exist"):
        generate_key_file(tmp_path / "missing" / "example.pem", ROOT)


def test_loading_refuses_shared_foreign_or_unusable_key_files(tmp_path):
    path = tmp_path / "example.pem"
    generate_key_file(path, ROOT)
    path.chmod(0o640)
    with pytest.raises(KeyFileRefused, match="chmod 600"):
        load_private_key(path, ROOT)
    with pytest.raises(KeyFileRefused, match="cannot read"):
        load_private_key(tmp_path / "absent.pem", ROOT)
    junk = tmp_path / "junk.pem"
    junk.write_text("not a key")
    junk.chmod(0o600)
    with pytest.raises(KeyFileRefused, match="not a readable private key"):
        load_private_key(junk, ROOT)
    example = Ed25519PrivateKey.generate()
    encrypted = tmp_path / "encrypted.pem"
    encrypted.write_bytes(example.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"example passphrase")))
    encrypted.chmod(0o600)
    with pytest.raises(KeyFileRefused, match="passphrase"):
        load_private_key(encrypted, ROOT)
    elliptic = tmp_path / "other_algorithm.pem"
    elliptic.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    elliptic.chmod(0o600)
    with pytest.raises(KeyFileRefused, match="not an Ed25519"):
        load_private_key(elliptic, ROOT)


# Allowlist

def test_allowlist_refuses_repeats_and_keeps_the_original_listing(keyed):
    before = keyed.keys.read_bytes()
    with pytest.raises(KeyFileRefused, match="already listed; choose"):
        add_key(keyed.keys, "example-key", public_key_text(Ed25519PrivateKey.generate().public_key()),
                "New name", ROLE)
    with pytest.raises(KeyFileRefused, match="under another key ID"):
        add_key(keyed.keys, "second-id", keyed.public, "New name", ROLE)
    with pytest.raises(KeyFileRefused, match="not Base64"):
        add_key(keyed.keys, "second-id", "not a key", "New name", ROLE)
    with pytest.raises(KeyFileRefused, match="short name"):
        add_key(keyed.keys, "bad id/with slash", public_key_text(Ed25519PrivateKey.generate().public_key()),
                "New name", ROLE)
    assert keyed.keys.read_bytes() == before
    assert keyed.keys.resolve() != keyed.case.log.resolve()


def _entry(public, **changes):
    return {"public_key": public, "name": "EXAMPLE", "role": "EXAMPLE", "revoked_on": None, **changes}


def _allowlist_faults(public):
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    good = _entry(public)
    document = lambda keys: json.dumps({"schema": ALLOWLIST_SCHEMA, "keys": keys})  # noqa: E731
    return {
        "not json": "{not json",
        "wrong schema": json.dumps({"schema": "other", "keys": {}}),
        "duplicate key id": ('{"schema": "%s", "keys": {"a": %s, "a": %s}}'
                             % (ALLOWLIST_SCHEMA, json.dumps(good), json.dumps(good))),
        "bad key": document({"a": _entry("AAAA")}),
        "extra field": document({"a": {**good, "note": "x"}}),
        "private key field": document({"a": {**good, "note": pem}}),
        "private key as name": document({"a": _entry(public, name=pem)}),
        "blank name": document({"a": _entry(public, name=" ")}),
        "bad revocation date": document({"a": _entry(public, revoked_on="yesterday")}),
        "same key twice": document({"a": good, "b": good}),
    }


@pytest.mark.parametrize("fault", ["not json", "wrong schema", "duplicate key id", "bad key", "extra field",
                                   "private key field", "private key as name", "blank name",
                                   "bad revocation date", "same key twice"])
def test_faulty_allowlist_accepts_no_signature(keyed, fault):
    keyed.append()
    keyed.keys.write_text(_allowlist_faults(keyed.public)[fault])
    assert keyed.allowlist()["status"] == "invalid"
    assert keyed.status() == ["allowlist_invalid"]
    with pytest.raises(SignoffRefused, match="allowlist is invalid"):
        keyed.append()
    with pytest.raises(KeyFileRefused, match="is invalid"):
        add_key(keyed.keys, "second-id", public_key_text(Ed25519PrivateKey.generate().public_key()), "N", "R")


# Command line, in-process

@pytest.fixture
def cli(keyed, monkeypatch):
    case = keyed.case
    monkeypatch.setenv("MODELAUDIT_AUDIT_DIR", str(case.audit))
    monkeypatch.setenv("MODELAUDIT_WORKPAPER_DIR", str(case.workpapers))
    monkeypatch.setenv("MODELAUDIT_SIGNOFF_LOG", str(case.log))
    monkeypatch.setenv("MODELAUDIT_REVIEWER_KEYS", str(keyed.keys))
    monkeypatch.setattr("audit.signoff.source_archive_check", lambda bundle, raw: case.source_match)
    base = ["sign", "--bundle", case.name, "--bundle-sha256", case.bundle["sha256"],
            "--workpaper-sha256", case.workpaper()["html"], "--owner", EXAMPLE_OWNER, "--role", ROLE,
            "--decision", "reject", "--date", "2026-10-01"]
    return keyed, base


def test_cli_key_id_and_private_key_go_together(cli, capsys):
    keyed, base = cli
    assert main(base + ["--key-id", "example-key"]) == 2
    assert main(base + ["--private-key", str(keyed.pem)]) == 2
    assert "must be given together" in capsys.readouterr().err
    assert not keyed.case.log.exists()


def test_cli_refuses_loose_private_key_file(cli, capsys):
    keyed, base = cli
    keyed.pem.chmod(0o644)
    assert main(base + ["--key-id", "example-key", "--private-key", str(keyed.pem)]) == 2
    assert "chmod 600" in capsys.readouterr().err and not keyed.case.log.exists()


def test_cli_requirement_refuses_unsigned_signing(cli, monkeypatch, capsys):
    keyed, base = cli
    monkeypatch.setenv("MODELAUDIT_REQUIRE_SIGNATURE", "1")
    assert main(base) == 2
    assert "MODELAUDIT_REQUIRE_SIGNATURE is on" in capsys.readouterr().err
    assert main(base + ["--key-id", "example-key", "--private-key", str(keyed.pem)]) == 0
    capsys.readouterr()
    assert main(["show", "--bundle", keyed.case.name]) == 0
    out = capsys.readouterr().out
    assert "Signatures: required" in out and "effective: reject [signature: valid]" in out
    assert "integrity=current signature=valid key=example-key" in out


def test_cli_keygen_never_prints_the_private_key(tmp_path, capsys):
    path = tmp_path / "printed_example.pem"
    assert main(["keygen", "--private-key", str(path)]) == 0
    out = capsys.readouterr().out
    body = "".join(path.read_text().splitlines()[1:-1])
    assert body not in out and "PRIVATE KEY-----" not in out and "Public key: " in out
    assert main(["keygen", "--private-key", str(path)]) == 2
    assert "refusing to overwrite" in capsys.readouterr().err


# Real end-to-end command-line flow in a temporary folder

@pytest.mark.skipif(not (ROOT / "data/raw/uci_german_144.zip").exists(),
                    reason="source archives not fetched; run `make data`")
def test_end_to_end_cli_flow_in_temporary_folder(signoff_case, tmp_path):
    reviews_before = sorted(path.name for path in (ROOT / "reviews").iterdir())
    keys_folder = tmp_path / "held_by_example_reviewer"
    keys_folder.mkdir(mode=0o700)
    pem = keys_folder / "example.pem"
    allowlist = tmp_path / "separate" / "reviewer_keys.json"
    env = {**os.environ, "MODELAUDIT_AUDIT_DIR": str(signoff_case.audit),
           "MODELAUDIT_WORKPAPER_DIR": str(signoff_case.workpapers),
           "MODELAUDIT_RAW_DIR": str(ROOT / "data/raw"),
           "MODELAUDIT_SIGNOFF_LOG": str(signoff_case.log), "MODELAUDIT_REVIEWER_KEYS": str(allowlist)}
    env.pop("MODELAUDIT_REQUIRE_SIGNATURE", None)

    def run(*arguments, require=False):
        extra = {"MODELAUDIT_REQUIRE_SIGNATURE": "1"} if require else {}
        return subprocess.run([sys.executable, "-m", "audit.signoff", *arguments], cwd=ROOT,
                              env={**env, **extra}, capture_output=True, text=True)

    created = run("keygen", "--private-key", str(pem))
    assert created.returncode == 0, created.stderr
    assert stat.S_IMODE(pem.stat().st_mode) == 0o600
    public = next(line.split(": ")[1] for line in created.stdout.splitlines()
                  if line.startswith("Public key: "))
    assert run("keygen", "--private-key", str(pem)).returncode == 2
    assert run("key-add", "--key-id", "example-key", "--public-key", public, "--owner", EXAMPLE_OWNER,
               "--role", ROLE).returncode == 0
    assert "example-key" in run("keys").stdout

    base = ["sign", "--bundle", "german_xgb", "--bundle-sha256", signoff_case.bundle["sha256"],
            "--workpaper-sha256", signoff_case.workpaper()["html"], "--role", ROLE,
            "--decision", "reject", "--date", "2026-10-01"]
    key = ["--key-id", "example-key", "--private-key", str(pem)]
    refused = run(*base, "--owner", "Someone else", *key)
    assert refused.returncode == 2 and "does not match the name" in refused.stderr
    assert not signoff_case.log.exists()
    signed = run(*base, "--owner", EXAMPLE_OWNER, *key)
    assert signed.returncode == 0, signed.stderr
    assert "signed with key example-key" in signed.stdout

    shown = run("show", "--bundle", "german_xgb")
    assert "effective: reject" in shown.stdout
    assert "integrity=current signature=valid key=example-key" in shown.stdout

    # Edit the decision and rebuild the record hash: the chain passes, the signature does not.
    record = json.loads(signoff_case.log.read_text())
    original = signoff_case.log.read_text()
    record.update(decision="approve")
    record.pop("record_sha256")
    record["record_sha256"] = _record_hash(record)
    signoff_case.log.write_text(json.dumps(record, sort_keys=True) + "\n")
    shown = run("show", "--bundle", "german_xgb")
    assert "integrity=current signature=bad_signature" in shown.stdout
    # The default keeps the earlier decision logic, but the decision line states the signature status.
    assert "effective: approve [signature: bad_signature]" in shown.stdout
    shown = run("show", "--bundle", "german_xgb", require=True)
    assert "effective: withheld (signatures are required and record 1 is bad_signature)" in shown.stdout

    signoff_case.log.write_text(original)
    assert "signature=valid" in run("show", "--bundle", "german_xgb", require=True).stdout
    assert run("key-revoke", "--key-id", "example-key", "--date", "2026-11-06").returncode == 0
    shown = run("show", "--bundle", "german_xgb", require=True)
    assert "signature=revoked_key" in shown.stdout and "effective: withheld" in shown.stdout
    assert run(*base, "--owner", EXAMPLE_OWNER, *key).returncode == 2

    # Nothing about this example touched the repository's reviews folder.
    assert sorted(path.name for path in (ROOT / "reviews").iterdir()) == reviews_before


# Accidental commit protection

def _git(folder, *arguments):
    return subprocess.run(["git", "-C", str(folder), *arguments], capture_output=True, text=True)


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs the Git repository")
def test_ignore_rules_cover_private_keys_and_real_review_files():
    for path in ("reviewer.pem", "reviews/reviewer.pem", "keys/reviewer.key", "reviewer.p8",
                 "reviewer_private.txt", "reviews/private_key.txt", "reviews/signoffs.jsonl",
                 "reviews/reviewer_keys.json", "reviews/signoffs.anchor.json"):
        assert _git(ROOT, "check-ignore", "-q", path).returncode == 0, path
    for path in ("reviews/reviewer_keys_template.json", "reviews/signoff_template.json",
                 "audit/reviewer_signature.py", "scripts/check_no_committed_keys.py",
                 "tests/test_reviewer_signature.py"):
        assert _git(ROOT, "check-ignore", "-q", path).returncode == 1, path


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="needs the Git repository")
def test_no_private_key_is_tracked_here():
    done = subprocess.run([sys.executable, str(ROOT / "scripts/check_no_committed_keys.py")],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_key_check_catches_a_force_added_key_by_name_and_content(tmp_path):
    repository = tmp_path / "scratch_repo"
    repository.mkdir()
    assert _git(repository, "init", "-q").returncode == 0
    script = str(ROOT / "scripts/check_no_committed_keys.py")
    check = lambda: subprocess.run([sys.executable, script, str(repository)],  # noqa: E731
                                   capture_output=True, text=True)
    assert check().returncode == 0
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    (repository / "innocent_name.txt").write_bytes(pem)
    assert _git(repository, "add", "-f", "innocent_name.txt").returncode == 0
    found = check()
    assert found.returncode == 1 and "private key content: innocent_name.txt" in found.stderr
    assert _git(repository, "rm", "-q", "--cached", "innocent_name.txt").returncode == 0
    (repository / "named.pem").write_text("example")
    (repository / "signoffs.jsonl").write_text("example")
    assert _git(repository, "add", "-f", "named.pem", "signoffs.jsonl").returncode == 0
    found = check()
    assert found.returncode == 1 and "named.pem" in found.stderr and "signoffs.jsonl" in found.stderr


def test_repository_ships_only_empty_key_template():
    template = json.loads((ROOT / "reviews/reviewer_keys_template.json").read_text())
    assert template["schema"] == ALLOWLIST_SCHEMA and template["keys"] == {}
