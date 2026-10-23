"""View-time file integrity: re-hash source archives and workpapers when a reviewer opens a bundle.

`data.fetch` verifies the UCI archives when the pipeline runs, and each bundle records the
archive hash it was built from (`provenance.sha256_zip`). Those checks say nothing about the
files on disk later. The helpers here hash the files again at the moment of review and
compare them with the recorded values, so a replaced, edited or missing archive is visible.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from data.fetch import SOURCES

ARCHIVES = {"taiwan": "uci_taiwan_350.zip", "german": "uci_german_144.zip"}
CHUNK = 1 << 20


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def check_file(path: Path, expected: str | None, label: str) -> dict:
    """Hash `path` now and compare it with `expected`; status is match, mismatch or missing."""
    path = Path(path)
    if not path.is_file():
        return {"label": label, "path": str(path), "expected": expected, "actual": None,
                "status": "missing", "detail": "file not found; it cannot be rechecked"}
    actual = sha256_file(path)
    if expected is None:
        return {"label": label, "path": str(path), "expected": None, "actual": actual,
                "status": "unrecorded", "detail": "no recorded hash to compare against"}
    if actual == expected:
        return {"label": label, "path": str(path), "expected": expected, "actual": actual,
                "status": "match", "detail": "recomputed hash equals the recorded hash"}
    return {"label": label, "path": str(path), "expected": expected, "actual": actual,
            "status": "mismatch", "detail": "file changed since the hash was recorded"}


def source_archive_check(bundle: dict, raw_dir: Path) -> dict:
    """Recheck the source ZIP named by the bundle's dataset against its recorded hash.

    The recorded hash is the one inside the (already digest-verified) bundle. The result also
    says whether that recorded hash still equals the pin in `data/fetch.py`.
    """
    dataset = bundle["dataset"]
    name = ARCHIVES[dataset]
    recorded = bundle.get("provenance", {}).get("sha256_zip")
    result = check_file(Path(raw_dir) / name, recorded, f"{dataset} source archive")
    pinned = SOURCES[name][1]
    result["pinned"] = pinned
    result["recorded_equals_pin"] = recorded == pinned
    if recorded != pinned:
        result["detail"] += "; the bundle's recorded hash differs from the pin in data/fetch.py"
    return result


def workpaper_checks(workpaper_dir: Path, name: str) -> list[dict]:
    """Current hashes of a bundle's HTML and PDF workpapers (expected values come from sign-offs)."""
    return [check_file(Path(workpaper_dir) / f"{name}.{suffix}", None, f"workpaper {suffix.upper()}")
            for suffix in ("html", "pdf")]


def workpaper_version(workpaper_dir: Path, name: str) -> dict:
    """Map `html`/`pdf` to the current SHA-256 (None when the file is missing)."""
    return {row["label"].split()[-1].lower(): row["actual"]
            for row in workpaper_checks(workpaper_dir, name)}
