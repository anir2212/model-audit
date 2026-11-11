"""Optional Ed25519 signatures on sign-off records and the local reviewer-key allowlist.

A signature proves one thing: a holder of the private key signed these exact record bytes.
It does not prove who holds the key, that the person reviewed carefully, or that they have
any institutional authority. The allowlist only says "this repository's keeper lists this
public key under this name"; an actor who can edit both the allowlist and the log can list a
new key and re-sign, so keep the allowlist under separate control.

What is signed: the fixed domain string below, then the canonical JSON of the whole record
except `record_sha256` (which is derived later and covers the signature) and `signature.value`
(which cannot sign itself). `signature.algorithm`, `signature.key_id`, `sequence` and
`prev_record_sha256` are therefore all signed, so a signature cannot be moved to another
position or log, reassigned to another key, or kept after any field is edited or added.

Canonical JSON: UTF-8, keys sorted, no whitespace, shortest escapes. Only strings, booleans,
null, integers up to 2**53 - 1, lists and string-keyed objects are accepted. Floats are
rejected because their text form is what makes JSON signatures unstable.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ALGORITHM = "ed25519"
SIGNATURE_DOMAIN = b"modelaudit-signoff-signature/1\n"
ALLOWLIST_SCHEMA = "modelaudit-reviewer-keys/1"
KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_INTEGER = 2 ** 53 - 1
SIGNATURE_BYTES, PUBLIC_KEY_BYTES = 64, 32
ENTRY_FIELDS = {"public_key", "name", "role", "revoked_on"}
NO_ALLOWLIST = {"status": "missing", "detail": "no reviewer key allowlist was given", "keys": {}}

VALID, UNSIGNED = "valid", "unsigned"
UNKNOWN_KEY, BAD_SIGNATURE, NAME_MISMATCH = "unknown_key", "bad_signature", "name_mismatch"
ROLE_MISMATCH, REVOKED_KEY = "role_mismatch", "revoked_key"
ALLOWLIST_INVALID, UNREADABLE = "allowlist_invalid", "unreadable"


class KeyFileRefused(ValueError):
    """A private-key or allowlist operation was refused; the message never holds key material."""


def _check_canonical(value) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_INTEGER:
            raise ValueError("integer is too large to serialize canonically")
    elif isinstance(value, list):
        for item in value:
            _check_canonical(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
            _check_canonical(item)
    else:
        raise ValueError(f"{type(value).__name__} values cannot be serialized canonically")


def canonical_bytes(value) -> bytes:
    """One byte string per value, whatever the original key order. Raises ValueError if unsupported."""
    _check_canonical(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def signing_payload(record: dict) -> bytes:
    """The exact bytes signed for a record that carries a `signature` block."""
    body = {key: value for key, value in record.items() if key != "record_sha256"}
    body["signature"] = {key: value for key, value in record["signature"].items() if key != "value"}
    return SIGNATURE_DOMAIN + canonical_bytes(body)


def sign_record(record: dict, key_id: str, private_key: Ed25519PrivateKey) -> dict:
    """Return a copy of an unhashed record with its signature block added."""
    if "record_sha256" in record or "signature" in record:
        raise ValueError("sign the record before it is hashed, and only once")
    signed = dict(record, signature={"algorithm": ALGORITHM, "key_id": key_id})
    value = private_key.sign(signing_payload(signed))
    signed["signature"]["value"] = base64.b64encode(value).decode("ascii")
    return signed


def _decode(text, length: int) -> bytes | None:
    """Strict standard Base64 of exactly `length` bytes, with one accepted spelling per value."""
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == length and base64.b64encode(raw).decode("ascii") == text else None


def _result(status: str, key_id, detail: str) -> dict:
    return {"status": status, "key_id": key_id, "detail": detail}


def verify_record(record: dict, allowlist: dict | None = None) -> dict:
    """Signature status of one record. Only `valid` means the signature and listing both agree."""
    allowlist = allowlist or NO_ALLOWLIST
    if "unparsed_line" in record:
        return _result(UNREADABLE, None, "this log line could not be parsed")
    if "signature" not in record:
        return _result(UNSIGNED, None, "no signature; the reviewer name is unverified typed text")
    block = record["signature"]
    if not isinstance(block, dict):
        return _result(BAD_SIGNATURE, None, "signature block is malformed")
    key_id = block.get("key_id") if isinstance(block.get("key_id"), str) else None
    if block.get("algorithm") != ALGORITHM or key_id is None:
        return _result(BAD_SIGNATURE, key_id, f"signature must name a key ID and use {ALGORITHM}")
    value = _decode(block.get("value"), SIGNATURE_BYTES)
    if value is None:
        return _result(BAD_SIGNATURE, key_id, "signature value is malformed")
    if allowlist["status"] == "invalid":
        return _result(ALLOWLIST_INVALID, key_id, f"reviewer key allowlist is invalid: {allowlist['detail']}")
    entry = allowlist["keys"].get(key_id)
    if entry is None:
        return _result(UNKNOWN_KEY, key_id, f"key ID {key_id} is not in the reviewer key allowlist")
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"]))
        public.verify(value, signing_payload(record))
    except (InvalidSignature, ValueError):
        return _result(BAD_SIGNATURE, key_id, "record was altered after signing or signed by another key")
    if entry.get("revoked_on"):
        return _result(REVOKED_KEY, key_id, f"key {key_id} was revoked on {entry['revoked_on']}; "
                       "record dates are the signer's own claim, so all its signatures stop counting")
    if record.get("owner") != entry["name"]:
        return _result(NAME_MISMATCH, key_id, f"record names {record.get('owner')!r} but key {key_id} "
                       f"is listed for {entry['name']!r}")
    if record.get("role") != entry["role"]:
        return _result(ROLE_MISMATCH, key_id, f"record says role {record.get('role')!r} but key {key_id} "
                       f"is listed with role {entry['role']!r}")
    return _result(VALID, key_id, f"a holder of the private key listed as {key_id} signed this record; "
                   "this does not prove who holds the key or how carefully they reviewed")


def signature_summary(row: dict) -> str:
    """One sentence for a banner about an `audit.signoff.assess` row."""
    status = row["signature_status"]
    if status == VALID:
        return (f"Signature valid (key {row['signature_key_id']}): a holder of that private key signed "
                "this record. This does not prove who holds the key or how carefully they reviewed.")
    if status == UNSIGNED:
        return "Unsigned: the reviewer name is unverified typed text."
    return f"Signature {status}: {row['signature_detail']}. Do not treat the named reviewer as verified."


def _inside_repository(path: Path, repo_root: Path) -> str | None:
    target = path.parent.resolve() / path.name
    if repo_root.resolve() in target.parents:
        return f"{path} is inside this repository; keep private keys outside it"
    for folder in target.parents:
        if (folder / ".git").exists():
            return f"{path} is inside the Git working tree at {folder}; keep private keys outside it"
    return None


def generate_key_file(path: Path, repo_root: Path) -> Ed25519PublicKey:
    """Create a new owner-only private-key file. Never overwrites and never writes into a Git tree."""
    path = Path(path).expanduser()
    refusal = _inside_repository(path, Path(repo_root))
    if refusal:
        raise KeyFileRefused(refusal)
    if not path.parent.is_dir():
        raise KeyFileRefused(f"folder {path.parent} does not exist; create it with owner-only access first")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    try:  # O_EXCL fails on any existing path, including a symlink, so nothing is ever replaced.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise KeyFileRefused(f"{path} already exists; refusing to overwrite a key file") from None
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(pem)
    return key.public_key()


def load_private_key(path: Path, repo_root: Path) -> Ed25519PrivateKey:
    """Load a signing key, refusing one that is inside a repository or readable by anyone else."""
    path = Path(path).expanduser()
    refusal = _inside_repository(path, Path(repo_root))
    if refusal:
        raise KeyFileRefused(refusal)
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise KeyFileRefused(f"{path} is not a regular file")
        if info.st_mode & 0o077:
            raise KeyFileRefused(f"{path} is accessible by group or others; run: chmod 600 {path}")
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except KeyFileRefused:
        raise
    except OSError as exc:
        raise KeyFileRefused(f"cannot read private key file {path}: {exc.strerror}") from None
    except TypeError:
        raise KeyFileRefused(f"{path} is passphrase-protected, which this command does not support") from None
    except (ValueError, UnsupportedAlgorithm):
        raise KeyFileRefused(f"{path} is not a readable private key file") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyFileRefused(f"{path} is not an Ed25519 private key")
    return key


def public_key_text(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def fingerprint(public_key: str) -> str:
    """SHA-256 of the raw public key, for comparing a listing with its holder out of band."""
    return hashlib.sha256(base64.b64decode(public_key)).hexdigest()


def _unique_pairs(pairs: list) -> dict:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key in JSON object")
    return dict(pairs)


def _iso_date(value) -> bool:
    try:
        return dt.date.fromisoformat(value).isoformat() == value
    except (TypeError, ValueError):
        return False


def _entry_problem(key_id, entry) -> str | None:
    if not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None:
        return f"key ID {key_id!r} is not a short name"
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        return f"entry {key_id} must have exactly {', '.join(sorted(ENTRY_FIELDS))}"
    raw = _decode(entry["public_key"], PUBLIC_KEY_BYTES)
    if raw is None:
        return f"entry {key_id} public key is not Base64 of {PUBLIC_KEY_BYTES} bytes"
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        return f"entry {key_id} public key is not an Ed25519 key"
    for field in ("name", "role"):
        text = entry[field]
        if not isinstance(text, str) or not text.strip() or text != text.strip():
            return f"entry {key_id} needs a {field} without surrounding spaces"
    if entry["revoked_on"] is not None and not _iso_date(entry["revoked_on"]):
        return f"entry {key_id} revoked_on must be null or an ISO date"
    return None


def load_allowlist(path: Path) -> dict:
    """Return status ok, missing or invalid, a detail and the keys. Any fault makes it all invalid."""
    path = Path(path)
    if not path.is_file():
        return {"status": "missing", "detail": f"no reviewer key allowlist at {path}", "keys": {}}
    invalid = lambda detail: {"status": "invalid", "detail": detail, "keys": {}}  # noqa: E731
    try:
        text = path.read_text()
        document = json.loads(text, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError):
        return invalid("file is not readable JSON with unique keys")
    if "PRIVATE KEY" in text:
        return invalid("file appears to contain a private key; remove it and replace that key")
    if (not isinstance(document, dict) or document.get("schema") != ALLOWLIST_SCHEMA
            or not isinstance(document.get("keys"), dict)):
        return invalid(f"file is not a {ALLOWLIST_SCHEMA} document")
    for key_id, entry in document["keys"].items():
        problem = _entry_problem(key_id, entry)
        if problem:
            return invalid(problem)
    publics = [entry["public_key"] for entry in document["keys"].values()]
    if len(publics) != len(set(publics)):
        return invalid("one public key is listed under more than one key ID")
    return {"status": "ok", "detail": f"{len(publics)} key(s) listed", "keys": document["keys"]}


def _write_allowlist(path: Path, keys: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"schema": ALLOWLIST_SCHEMA, "keys": keys}, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(payload)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise


def _usable_allowlist(path: Path) -> dict:
    allowlist = load_allowlist(path)
    if allowlist["status"] == "invalid":
        raise KeyFileRefused(f"allowlist {path} is invalid: {allowlist['detail']}")
    return allowlist


def add_key(path: Path, key_id: str, public_key: str, name: str, role: str) -> dict:
    """List a public key. Refuses a repeated ID or key, so an old listing is never silently replaced."""
    path = Path(path)
    keys = _usable_allowlist(path)["keys"]
    entry = {"public_key": public_key, "name": name.strip(), "role": role.strip(), "revoked_on": None}
    problem = _entry_problem(key_id, entry)
    if problem:
        raise KeyFileRefused(problem)
    if key_id in keys:
        raise KeyFileRefused(f"key ID {key_id} is already listed; choose a new ID instead of replacing it")
    if any(other["public_key"] == public_key for other in keys.values()):
        raise KeyFileRefused("this public key is already listed under another key ID")
    _write_allowlist(path, {**keys, key_id: entry})
    return entry


def revoke_key(path: Path, key_id: str, date: str) -> None:
    """Mark a listed key revoked. The entry stays, so its old records report `revoked_key`."""
    path = Path(path)
    keys = _usable_allowlist(path)["keys"]
    if key_id not in keys:
        raise KeyFileRefused(f"key ID {key_id} is not listed")
    if keys[key_id]["revoked_on"]:
        raise KeyFileRefused(f"key {key_id} was already revoked on {keys[key_id]['revoked_on']}")
    if not _iso_date(date):
        raise KeyFileRefused("revocation date must be an ISO date such as 2026-11-06")
    _write_allowlist(path, {**keys, key_id: dict(keys[key_id], revoked_on=date)})


def signer_problems(owner: str, role: str, key_id: str, private_key: Ed25519PrivateKey,
                    allowlist: dict) -> list[str]:
    """Every reason this key may not sign for this claimed reviewer; checked before anything is written."""
    if allowlist["status"] != "ok":
        return [f"reviewer key allowlist is {allowlist['status']}: {allowlist['detail']}"]
    entry = allowlist["keys"].get(key_id)
    if entry is None:
        return [f"key ID {key_id} is not in the reviewer key allowlist"]
    problems = []
    if entry["revoked_on"]:
        problems.append(f"key {key_id} was revoked on {entry['revoked_on']}")
    if public_key_text(private_key.public_key()) != entry["public_key"]:
        problems.append(f"this private key does not match the public key listed as {key_id}")
    if owner != entry["name"]:
        problems.append(f"owner {owner!r} does not match the name listed for {key_id}")
    if role != entry["role"]:
        problems.append(f"role {role!r} does not match the role listed for {key_id}")
    return problems
