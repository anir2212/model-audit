import hashlib
from pathlib import Path

import pytest

from audit.integrity import check_file, source_archive_check, workpaper_version
from data.fetch import SOURCES

ROOT = Path(__file__).resolve().parents[1]
GERMAN_PIN = SOURCES["uci_german_144.zip"][1]


def _bundle(recorded):
    return {"dataset": "german", "model": "xgb", "provenance": {"sha256_zip": recorded}}


def test_check_file_match_mismatch_missing_unrecorded(tmp_path):
    path = tmp_path / "file.bin"
    path.write_bytes(b"recorded bytes")
    digest = hashlib.sha256(b"recorded bytes").hexdigest()
    assert check_file(path, digest, "x")["status"] == "match"
    path.write_bytes(b"recorded bytes, then edited")
    changed = check_file(path, digest, "x")
    assert changed["status"] == "mismatch" and changed["actual"] != digest
    missing = check_file(tmp_path / "absent.bin", digest, "x")
    assert missing["status"] == "missing" and missing["actual"] is None
    assert check_file(path, None, "x")["status"] == "unrecorded"


def test_source_archive_mismatch_when_zip_replaced(tmp_path):
    (tmp_path / "uci_german_144.zip").write_bytes(b"not the UCI archive")
    result = source_archive_check(_bundle(GERMAN_PIN), tmp_path)
    assert result["status"] == "mismatch" and result["expected"] == GERMAN_PIN
    assert result["recorded_equals_pin"]


def test_source_archive_missing(tmp_path):
    result = source_archive_check(_bundle(GERMAN_PIN), tmp_path)
    assert result["status"] == "missing" and "cannot be rechecked" in result["detail"]


def test_recorded_hash_that_differs_from_pin_is_flagged_even_on_match(tmp_path):
    (tmp_path / "uci_german_144.zip").write_bytes(b"substitute data")
    recorded = hashlib.sha256(b"substitute data").hexdigest()
    result = source_archive_check(_bundle(recorded), tmp_path)
    assert result["status"] == "match" and not result["recorded_equals_pin"]
    assert "differs from the pin" in result["detail"]


@pytest.mark.skipif(not (ROOT / "data/raw/uci_german_144.zip").exists(),
                    reason="source archives not fetched; run `make data`")
@pytest.mark.parametrize("name", ["taiwan_scorecard", "german_xgb"])
def test_committed_bundles_match_fetched_archives(name):
    import json
    bundle = json.loads((ROOT / "evidence/audit" / f"{name}.json").read_text())
    result = source_archive_check(bundle, ROOT / "data/raw")
    assert result["status"] == "match" and result["recorded_equals_pin"]


def test_workpaper_version_reports_missing_files(tmp_path):
    (tmp_path / "german_xgb.html").write_text("<html></html>")
    version = workpaper_version(tmp_path, "german_xgb")
    assert version["html"] == hashlib.sha256(b"<html></html>").hexdigest()
    assert version["pdf"] is None
