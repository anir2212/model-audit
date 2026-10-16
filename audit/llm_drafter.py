"""Constrain optional prose generation to numeric literals in a test bundle."""
from __future__ import annotations

import json
import re
from urllib.request import Request, urlopen

NUMBER = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?")


def allowed_numbers(evidence):
    """Only recorded numeric values and test-id digits may appear in prose."""
    allowed = set()
    def visit(value):
        if isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            allowed.add(str(value))
        elif isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str) and (key in evidence.get("tests", {}) or key.endswith("_ci95")):
                    allowed.update(NUMBER.findall(key))
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(evidence)
    return allowed


def check_draft_numbers(draft: str, evidence: dict):
    found = set(NUMBER.findall(draft))
    return found <= allowed_numbers(evidence)


def guarded_ollama_draft(evidence: dict, model: str, base_url="http://127.0.0.1:11434"):
    """Optional local-only Ollama call; a rejected draft is never used."""
    payload = {"model": model, "stream": False,
               "prompt": "Paraphrase the following audit output. Copy numeric values exactly; do not infer new figures.\n" +
                         json.dumps(evidence["tests"], sort_keys=True)}
    request = Request(base_url + "/api/generate", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=120) as response:
        draft = json.load(response)["response"]
    if not check_draft_numbers(draft, evidence):
        raise ValueError("draft introduced an unverified number")
    return draft
