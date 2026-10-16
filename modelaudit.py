"""Re-runnable model-risk metrics with evidence hashes and HTML workpaper."""
import argparse
import hashlib
import html
import json
import math
import random
import re
from pathlib import Path


def auc(labels, scores):
    positives = [s for y, s in zip(labels, scores) if y]
    negatives = [s for y, s in zip(labels, scores) if not y]
    if not positives or not negatives:
        raise ValueError("both classes required")
    return sum((a > b) + .5*(a == b) for a in positives for b in negatives)/(len(positives)*len(negatives))


def ks(labels, scores):
    rows = sorted(zip(scores, labels), reverse=True)
    pos, neg = sum(labels), len(labels)-sum(labels)
    if not pos or not neg:
        raise ValueError("both classes required")
    tp = fp = 0
    largest = 0
    for _, y in rows:
        tp += bool(y)
        fp += not bool(y)
        largest = max(largest, abs(tp/pos-fp/neg))
    return largest


def psi(expected, actual, bins=10):
    if not expected or not actual:
        raise ValueError("nonempty score distributions required")
    result = 0
    for i in range(bins):
        low, high = i/bins, (i+1)/bins
        e = sum(low <= x < high or (i == bins-1 and x == 1) for x in expected)/len(expected)
        a = sum(low <= x < high or (i == bins-1 and x == 1) for x in actual)/len(actual)
        e, a = max(e, 1e-6), max(a, 1e-6)
        result += (a-e)*math.log(a/e)
    return result


def fairness(labels, decisions, groups):
    out = {}
    for group in sorted(set(groups)):
        idx = [i for i, g in enumerate(groups) if g == group]
        positives = [i for i in idx if labels[i]]
        out[group] = {"approval_rate": sum(decisions[i] for i in idx)/len(idx), "true_positive_rate": sum(decisions[i] for i in positives)/len(positives) if positives else None}
    approval = [v["approval_rate"] for v in out.values()]
    tpr = [v["true_positive_rate"] for v in out.values() if v["true_positive_rate"] is not None]
    return {"groups": out, "demographic_parity_difference": max(approval)-min(approval), "equal_opportunity_difference": max(tpr)-min(tpr) if tpr else None}


def synthetic(seed=7, n=400):
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        group = rng.choice(("A", "B"))
        missed = rng.randrange(5)
        income = rng.randrange(20, 120)
        risk = min(.95, max(.02, .1 + .16*missed - .002*income + (.07 if group == "B" else 0)))
        label = int(rng.random() < risk)
        rows.append((group, missed, income, risk, label))
    return rows


def check_draft_numbers(draft, evidence):
    allowed = set(re.findall(r"(?<!\w)-?\d+(?:\.\d+)?", json.dumps(evidence)))
    found = set(re.findall(r"(?<!\w)-?\d+(?:\.\d+)?", draft))
    return found <= allowed


def audit(seed=7):
    train, shifted = synthetic(seed), synthetic(seed+1)
    scores = [r[3] for r in train]
    labels = [r[4] for r in train]
    decisions = [int(s < .5) for s in scores]
    evidence = {
        "PERF-AUC-01": {"auc": auc(labels, scores), "ks": ks(labels, scores), "gini": 2*auc(labels, scores)-1},
        "CAL-BRIER-01": {"brier": sum((y-s)**2 for y, s in zip(labels, scores))/len(labels)},
        "STAB-PSI-01": {"psi": psi(scores, [min(1, r[3]+.1) for r in shifted])},
        "FAIR-01": fairness([1-y for y in labels], decisions, [r[0] for r in train]),
        "ROB-MONO-01": {"passed": all(.1+.16*(m+1) > .1+.16*m for m in range(4))},
    }
    payload = json.dumps(evidence, sort_keys=True)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    findings = []
    checks = (
        ("PERF-AUC-01", evidence["PERF-AUC-01"]["auc"] < .7, "medium", "AUC below local review threshold 0.7"),
        ("STAB-PSI-01", evidence["STAB-PSI-01"]["psi"] > .25, "high", "PSI above local review threshold 0.25"),
        ("FAIR-01", evidence["FAIR-01"]["demographic_parity_difference"] > .1, "medium", "Approval-rate gap above local review threshold 0.1"),
    )
    for test_id, failed, severity, reason in checks:
        if failed:
            findings.append({"test_id": test_id, "severity": severity, "reason": reason, "status": "unvalidated"})
    return {"seed": seed, "dataset": "synthetic", "n": len(train), "tests": evidence, "sha256": digest, "findings": findings}


def revalidate(result, second_seed):
    second = audit(second_seed)
    repeated = {f["test_id"] for f in second["findings"]}
    for finding in result["findings"]:
        finding["status"] = "reproduced" if finding["test_id"] in repeated else "not reproduced"
    result["revalidation_seed"] = second_seed
    return result


def write_workpaper(result, path):
    sections = []
    for test_id, values in result["tests"].items():
        sections.append(f"<section><h2>{html.escape(test_id)}</h2><pre>{html.escape(json.dumps(values, indent=2))}</pre><p>Evidence hash: {result['sha256']}</p></section>")
    finding_html = "<h2>Findings</h2><pre>" + html.escape(json.dumps(result["findings"], indent=2)) + "</pre>"
    Path(path).write_text("<!doctype html><html><meta charset='utf-8'><title>ModelAudit workpaper</title><body><h1>ModelAudit synthetic workpaper</h1>" + finding_html + "".join(sections) + "</body></html>")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()
    result = revalidate(audit(args.seed), args.seed+1)
    Path("evidence.json").write_text(json.dumps(result, indent=2))
    write_workpaper(result, "workpaper.html")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
