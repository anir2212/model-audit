"""Shared fixtures for the sign-off and integrity tests.

The sign-off below is an EXAMPLE used only inside temporary test folders. It is not a real
review decision and is never written to `reviews/signoffs.jsonl`.
"""
import datetime as dt
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from audit.integrity import sha256_file, workpaper_version
from audit.registry import load_plan
from data.fetch import SOURCES

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_OWNER = "EXAMPLE ONLY - test fixture reviewer"
TODAY = dt.date(2026, 10, 23)


def redigest(bundle: dict) -> dict:
    body = {key: value for key, value in bundle.items() if key != "sha256"}
    body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    return body


class SignoffCase:
    """Copies of the committed evidence plus everything `append_signoff` needs."""

    def __init__(self, tmp_path: Path, name: str = "german_xgb"):
        self.name = name
        self.audit = tmp_path / "audit"
        self.workpapers = tmp_path / "workpapers"
        shutil.copytree(ROOT / "evidence/audit", self.audit)
        shutil.copytree(ROOT / "evidence/workpapers", self.workpapers)
        self.log = tmp_path / "signoffs.jsonl"
        self.plan_path = ROOT / "configs/audit_plan.yaml"
        self.plan = load_plan(self.plan_path)
        self.plan_sha = sha256_file(self.plan_path)
        self.bundle = json.loads((self.audit / f"{name}.json").read_text())
        archive = "uci_taiwan_350.zip" if name.startswith("taiwan") else "uci_german_144.zip"
        self.source_match = {"status": "match", "actual": SOURCES[archive][1]}

    def workpaper(self):
        return workpaper_version(self.workpapers, self.name)

    def request(self, **changes):
        request = {"bundle": self.name, "bundle_sha256": self.bundle["sha256"],
                   "workpaper_sha256": self.workpaper()["html"], "owner": EXAMPLE_OWNER,
                   "role": "Example validator (test only)", "decision": "approve_with_conditions",
                   "conditions": ["Example condition: rerun on a dated cohort"],
                   "date": TODAY.isoformat()}
        request.update(changes)
        return request


@pytest.fixture
def signoff_case(tmp_path):
    return SignoffCase(tmp_path)
