"""Render test-ID-linked HTML and PDF workpapers from measured JSON bundles."""
from __future__ import annotations

import hashlib
import json
import textwrap
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from jinja2 import Environment, select_autoescape

from models.data import ROOT

TEMPLATE = """<!doctype html><html lang="en"><meta charset="utf-8"><title>{{ title }}</title>
<style>body{font:15px system-ui;max-width:960px;margin:2rem auto;color:#1d2633}h1,h2{color:#153d64}section{border-top:1px solid #bbc;padding:1rem 0}pre{white-space:pre-wrap;background:#f2f5f8;padding:1rem;overflow:auto}.fail{color:#a82020}.warn{color:#9b5c00}small{color:#52606b}</style>
<h1>{{ title }}</h1><p>{{ scope }}</p><p>Dataset: {{ dataset }} · Model: {{ model }} · Test cohort: {{ count }} rows</p>
<p>Evidence SHA-256: <code>{{ digest }}</code></p><p>Finding confirmation: {{ confirmation }}</p>
<h2>Findings</h2>{% for item in findings %}<section id="finding-{{ item.test_id }}"><strong class="{{ item.severity }}">{{ item.test_id }} · {{ item.severity }}</strong>
<p>Observed {{ item.observed }} · confirmation {{ item.confirmation }} ({{ item.confirmation_value }})</p>
<p>Recommendation: investigate this local review flag and assess materiality, data and threshold choice with a domain owner.</p>
<p>Management response: ____________________</p></section>{% endfor %}
<h2>Registered tests</h2>{% for id, test in tests.items() %}<section id="{{ id }}"><h3>{{ id }} — {{ test.status }}</h3>
<p>Objective: evaluate the {{ id }} registered diagnostic on the stated cohort.</p>
<p>Procedure and threshold:</p><pre>{{ test['threshold'] | tojson(indent=2) }}</pre>
<p>Measured evidence:</p><pre>{{ test['values'] | tojson(indent=2) }}</pre>
<small>Source: {{ source }}; evidence hash {{ digest }}</small></section>{% endfor %}
</html>"""


def _pdf(bundle, output):
    with PdfPages(output) as pdf:
        items = [("Summary", {"dataset": bundle["dataset"], "model": bundle["model"],
                              "scope": bundle["scope"], "evidence_sha256": bundle["sha256"],
                              "findings": [{"test_id": f["test_id"], "severity": f["severity"],
                                            "confirmation": f["confirmation"]} for f in bundle["findings"]]})]
        items += [(test_id, test) for test_id, test in bundle["tests"].items()]
        for title, values in items:
            lines = []
            for line in json.dumps(values, indent=2, default=str).splitlines():
                lines.extend(textwrap.wrap(line, width=105, subsequent_indent="  ",
                                           replace_whitespace=False) or [""])
            for page_start in range(0, len(lines), 56):
                fig = plt.figure(figsize=(8.27, 11.69))
                fig.text(0.07, 0.95, f"ModelAudit — {title} (page {page_start // 56 + 1})",
                         fontsize=14, weight="bold")
                for index, line in enumerate(lines[page_start:page_start + 56]):
                    fig.text(0.07, 0.91 - index * 0.0145, line, family="monospace", fontsize=7)
                fig.text(0.07, 0.04, f"Evidence: {bundle['sha256']}  |  {title}", fontsize=6)
                pdf.savefig(fig)
                plt.close(fig)


def render(bundle: dict):
    output = ROOT / "runs/workpapers"
    output.mkdir(parents=True, exist_ok=True)
    name = f"{bundle['dataset']}_{bundle['model']}"
    env = Environment(autoescape=select_autoescape(enabled_extensions=("html",)))
    page = env.from_string(TEMPLATE).render(
        title=f"ModelAudit workpaper — {name}", scope=bundle["scope"],
        dataset=bundle["dataset"], model=bundle["model"], count=bundle["test_cohort_rows"],
        digest=bundle["sha256"], confirmation=bundle["confirmation_source"],
        findings=bundle["findings"], tests=bundle["tests"],
        source=f"runs/audit/{name}.json")
    html_path = output / f"{name}.html"
    html_path.write_text(page)
    pdf_path = output / f"{name}.pdf"
    _pdf(bundle, pdf_path)
    return {"html": str(html_path), "pdf": str(pdf_path),
            "html_sha256": hashlib.sha256(html_path.read_bytes()).hexdigest()}


if __name__ == "__main__":
    for path in sorted((ROOT / "runs/audit").glob("*.json")):
        if path.stem.endswith("_explain"):
            continue
        print(render(json.loads(path.read_text())))
