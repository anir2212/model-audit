"""Drive the real Streamlit console in headless Chrome and check what a reviewer sees.

Each scenario starts its own `streamlit run` on a loopback port with environment overrides
pointing at temporary copies of `evidence/`, opens the page through the Chrome DevTools
Protocol, waits for the expected banners, opens the "Integrity and sign-off" tab and records
pass/fail per check. Sign-offs and reviewer keys used here are EXAMPLE records and throwaway keys
written to the temporary folder only. Output: `runs/browser/console_check.json` and one PNG screenshot per scenario.

Usage: .venv/bin/python scripts/browser_check.py [--chrome PATH] [--out DIR]
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from tornado.websocket import websocket_connect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from audit.reviewer_signature import (add_key, generate_key_file, load_allowlist,  # noqa: E402
                                      load_private_key, public_key_text)
from audit.signoff import _record_hash, append_signoff  # noqa: E402
from conftest import EXAMPLE_OWNER, TODAY, SignoffCase, redigest  # noqa: E402

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
BUNDLE = "german_scorecard"  # first bundle in the selector, shown on page load
TAB = "Integrity and sign-off"


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_http(url: str, timeout: float = 30) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return response.read().decode()
        except OSError:
            time.sleep(0.3)
    raise TimeoutError(url)


class Page:
    def __init__(self, socket_):
        self.socket, self.next_id = socket_, 0

    async def call(self, method, **params):
        self.next_id += 1
        await self.socket.write_message(json.dumps({"id": self.next_id, "method": method, "params": params}))
        while True:
            message = json.loads(await self.socket.read_message())
            if message.get("id") == self.next_id:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message.get("result", {})

    async def evaluate(self, expression):
        result = await self.call("Runtime.evaluate", expression=expression, returnByValue=True)
        return result.get("result", {}).get("value")

    async def wait_for(self, texts, timeout=40):
        deadline, body = time.time() + timeout, ""
        while time.time() < deadline:
            body = await self.evaluate("document.body ? document.body.innerText : ''") or ""
            running = await self.evaluate(
                "!!document.querySelector('[data-testid=\"stStatusWidget\"]')")
            if all(text in body for text in texts) and not running:
                return body
            await asyncio.sleep(0.5)
        return body


def _scenarios(work: Path) -> list[dict]:
    scenarios = []
    real_raw = ROOT / "data/raw"
    empty_log = work / "empty.jsonl"

    def case(name):
        folder = work / name
        folder.mkdir()
        return SignoffCase(folder, BUNDLE)

    if (real_raw / "uci_german_144.zip").exists():
        c = case("match")
        scenarios.append({"name": "source_match_no_signoff", "env": {
            "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
            "MODELAUDIT_RAW_DIR": real_raw, "MODELAUDIT_SIGNOFF_LOG": empty_log},
            "expect": ["uci_german_144.zip was hashed now and matches", "Sign-off: none recorded"],
            "expect_tab": ["Files rechecked when this page loaded",
                           "No sign-off has been recorded for this bundle"]})
    c = case("mismatch")
    raw = work / "mismatch_raw"
    raw.mkdir()
    (raw / "uci_german_144.zip").write_bytes(b"replaced archive")
    scenarios.append({"name": "source_mismatch", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": raw, "MODELAUDIT_SIGNOFF_LOG": empty_log},
        "expect": ["Source archive mismatch: uci_german_144.zip"],
        "expect_tab": ["Files rechecked when this page loaded", "To sign, quote bundle SHA-256"]})
    c = case("missing")
    raw = work / "missing_raw"
    raw.mkdir()
    scenarios.append({"name": "source_missing", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": raw, "MODELAUDIT_SIGNOFF_LOG": empty_log},
        "expect": ["Source archive missing: uci_german_144.zip"],
        "expect_tab": ["Files rechecked when this page loaded", "No sign-off has been recorded"]})
    c = case("signoffs")
    earlier = redigest(dict(c.bundle, scope="earlier run of the same audit (example)"))
    for bundle, decision, conditions in ((earlier, "reject", []),
                                         (c.bundle, "approve_with_conditions", ["Example condition"])):
        append_signoff(c.log, c.request(bundle_sha256=bundle["sha256"], decision=decision,
                                        conditions=conditions),
                       bundle, c.plan, c.plan_sha, c.workpaper(), c.source_match, today=TODAY)
    scenarios.append({"name": "example_signoffs_current_and_stale", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": raw, "MODELAUDIT_SIGNOFF_LOG": c.log},
        "expect": ["Current sign-off: approve_with_conditions by EXAMPLE ONLY",
                   "source archive missing, so it was not rechecked"],
        "expect_tab": ["Reviewer sign-offs", "record 1 stale_bundle"]})
    c = case("replaced_source")
    append_signoff(c.log, c.request(), c.bundle, c.plan, c.plan_sha, c.workpaper(), c.source_match,
                   today=TODAY)
    scenarios.append({"name": "source_mismatch_with_signoff", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": work / "mismatch_raw", "MODELAUDIT_SIGNOFF_LOG": c.log},
        "expect": ["Source archive mismatch: uci_german_144.zip", "earlier sign-offs are stale"],
        "expect_tab": ["record 1 stale_source"]})
    c = case("tampered")
    append_signoff(c.log, c.request(), c.bundle, c.plan, c.plan_sha, c.workpaper(), c.source_match,
                   today=TODAY)
    c.log.write_text(c.log.read_text().replace("approve_with_conditions", "approve"))
    scenarios.append({"name": "edited_signoff_log", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": raw, "MODELAUDIT_SIGNOFF_LOG": c.log},
        "expect": ["Sign-off log integrity failure"],
        "expect_tab": ["record 1 log_integrity_failed"]})

    def keyed_case(name):
        """A case with one throwaway EXAMPLE key, listed in its own temporary allowlist."""
        c = case(name)
        folder = c.log.parent
        keys = folder / "reviewer_keys.json"
        add_key(keys, "example-key", public_key_text(generate_key_file(folder / "example.pem", ROOT)),
                EXAMPLE_OWNER, c.request()["role"])
        return c, keys, {"key_id": "example-key", "private_key": load_private_key(folder / "example.pem", ROOT),
                         "allowlist": load_allowlist(keys)}

    c, keys, signer = keyed_case("signed")
    append_signoff(c.log, c.request(), c.bundle, c.plan, c.plan_sha, c.workpaper(), c.source_match,
                   today=TODAY, signer=signer)
    scenarios.append({"name": "signed_example_valid", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": raw, "MODELAUDIT_SIGNOFF_LOG": c.log, "MODELAUDIT_REVIEWER_KEYS": keys},
        "expect": ["Current sign-off: approve_with_conditions by EXAMPLE ONLY",
                   "Signature valid (key example-key)", "does not prove who holds the key"],
        "expect_tab": ["Reviewer signatures: optional", "1 key(s) listed", "institutional authority"]})
    c, keys, signer = keyed_case("altered")
    record = append_signoff(c.log, c.request(), c.bundle, c.plan, c.plan_sha, c.workpaper(),
                            c.source_match, today=TODAY, signer=signer)
    record = {key: value for key, value in record.items() if key != "record_sha256"}
    record.update(decision="approve", conditions=[])
    record["record_sha256"] = _record_hash(record)  # the chain passes; only the signature can object
    c.log.write_text(json.dumps(record, sort_keys=True) + "\n")
    scenarios.append({"name": "altered_signed_record_chain_rebuilt", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": raw, "MODELAUDIT_SIGNOFF_LOG": c.log, "MODELAUDIT_REVIEWER_KEYS": keys},
        "expect": ["Signature bad_signature", "Do not treat the named reviewer as verified"],
        "expect_tab": ["record 1 bad_signature"]})
    c, keys, _ = keyed_case("unsigned_required")
    append_signoff(c.log, c.request(), c.bundle, c.plan, c.plan_sha, c.workpaper(), c.source_match,
                   today=TODAY)
    scenarios.append({"name": "unsigned_withheld_when_required", "env": {
        "MODELAUDIT_AUDIT_DIR": c.audit, "MODELAUDIT_WORKPAPER_DIR": c.workpapers,
        "MODELAUDIT_RAW_DIR": raw, "MODELAUDIT_SIGNOFF_LOG": c.log, "MODELAUDIT_REVIEWER_KEYS": keys,
        "MODELAUDIT_REQUIRE_SIGNATURE": "1"},
        "expect": ["Sign-off status withheld because signatures are required and record 1 is unsigned"],
        "expect_tab": ["Reviewer signatures: required"]})
    return scenarios


async def _run_scenario(page: Page, url: str, scenario: dict, out: Path) -> list[dict]:
    checks = []
    await page.call("Page.navigate", url=url)
    body = await page.wait_for(["ModelAudit"] + scenario["expect"])
    for text in ["ModelAudit"] + scenario["expect"]:
        checks.append({"check": f"page shows {text!r}", "passed": text in body})
    exceptions = await page.evaluate("document.querySelectorAll('[data-testid=\"stException\"]').length")
    checks.append({"check": "no Streamlit exception on load", "passed": exceptions == 0})
    clicked = await page.evaluate(
        "(() => { const tab = [...document.querySelectorAll('button[role=\"tab\"]')]"
        f".find(b => b.innerText.includes('{TAB}')); if (!tab) return false; tab.click(); return true; }})()")
    checks.append({"check": f"tab {TAB!r} opens", "passed": bool(clicked)})
    body = await page.wait_for(scenario["expect_tab"])
    visible = await page.evaluate(
        "[...document.querySelectorAll('[role=\"tabpanel\"]')].filter(p => !p.hidden && "
        "p.offsetParent !== null).map(p => p.innerText).join('\\n')") or ""
    for text in scenario["expect_tab"]:
        checks.append({"check": f"open tab shows {text!r}", "passed": text in visible})
    await asyncio.sleep(1.5)  # let the canvas-drawn data grids paint before the screenshot
    shot = await page.call("Page.captureScreenshot", format="png", captureBeyondViewport=True)
    (out / f"{scenario['name']}.png").write_bytes(base64.b64decode(shot["data"]))
    return checks


async def main_async(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="modelaudit_browser_"))
    chrome_port, processes, report = _port(), [], []
    profile = work / "chrome_profile"
    try:
        chrome = subprocess.Popen([args.chrome, "--headless=new", f"--remote-debugging-port={chrome_port}",
                                   f"--user-data-dir={profile}", "--no-first-run",
                                   "--no-default-browser-check", "--disable-gpu",
                                   "--window-size=1400,1800", "about:blank"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(chrome)
        version = json.loads(_wait_http(f"http://127.0.0.1:{chrome_port}/json/version"))
        targets = json.loads(_wait_http(f"http://127.0.0.1:{chrome_port}/json/list"))
        target = next(t for t in targets if t["type"] == "page")
        page = Page(await websocket_connect(target["webSocketDebuggerUrl"], max_message_size=64 << 20))
        await page.call("Page.enable")
        await page.call("Emulation.setDeviceMetricsOverride", width=1400, height=1800,
                        deviceScaleFactor=1, mobile=False)
        for scenario in _scenarios(work):
            port = _port()
            env = {key: value for key, value in os.environ.items()
                   if key != "MODELAUDIT_REQUIRE_SIGNATURE"}
            env["MODELAUDIT_REVIEWER_KEYS"] = str(work / "no_reviewer_keys.json")
            env.update({key: str(value) for key, value in scenario["env"].items()})
            server = subprocess.Popen(
                [str(ROOT / ".venv/bin/streamlit"), "run", str(ROOT / "app/streamlit_app.py"),
                 "--server.headless", "true", "--server.address", "127.0.0.1",
                 "--server.port", str(port), "--browser.gatherUsageStats", "false"],
                cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(server)
            try:
                _wait_http(f"http://127.0.0.1:{port}/_stcore/health")
                checks = await _run_scenario(page, f"http://127.0.0.1:{port}/", scenario, out)
            finally:
                server.terminate()
                server.wait(timeout=20)
            report.append({"scenario": scenario["name"], "bundle": BUNDLE, "checks": checks})
            passed = sum(check["passed"] for check in checks)
            print(f"{scenario['name']}: {passed}/{len(checks)}")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=20)
        shutil.rmtree(work, ignore_errors=True)
    total = sum(len(item["checks"]) for item in report)
    passed = sum(check["passed"] for item in report for check in item["checks"])
    import streamlit
    result = {"date": dt.date.today().isoformat(), "browser": version.get("Browser"),
              "streamlit": streamlit.__version__, "passed": passed, "total": total,
              "note": "Sign-off records and reviewer keys in these scenarios are examples written to a "
                      "temporary folder and deleted afterwards. No real reviewer or key is involved.",
              "scenarios": report}
    (out / "console_check.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"browser checks passed: {passed}/{total}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--chrome", default=os.environ.get("CHROME", CHROME))
    parser.add_argument("--out", default=str(ROOT / "runs/browser"))
    raise SystemExit(asyncio.run(main_async(parser.parse_args())))
