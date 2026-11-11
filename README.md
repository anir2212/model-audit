# ModelAudit

ModelAudit helps a reviewer ask whether a credit-risk model is behaving as expected and trace each concern back to evidence. It trains a readable scorecard and an XGBoost comparison model on two licensed UCI datasets, applies a registered set of checks, and exports HTML/PDF workpapers. A separate fictional-policy fixture exercises the application-audit harness.

## Why this project

A strong overall score can hide calibration problems, unstable inputs or different outcomes across groups. This project makes the review tests explicit and keeps their thresholds, measured values and source limitations together. The flags invite investigation; they are not credit decisions or legal findings.

## Current milestones

| Area | What works today | Next question |
|---|---|---|
| Credit-model review | Hash-checked inputs, two models, registered checks, saved findings and workpapers | Do flags repeat in an authorized, timestamped cohort? |
| Additional diagnostics | Retrospective repayment-status survival analysis and local evidence viewer | Which questions matter for a defined lending use case? |
| Reviewer navigation | The local console verifies each audit bundle's hash, re-checks stored statuses against the current check plan, gives findings stable IDs and traces each one to its evidence keys and workpaper section | It never edits evidence |
| Sign-off and file rechecks | An append-only, hash-chained reviewer sign-off log kept outside the bundles; a sign-off is refused against a stale bundle, workpaper, plan or source archive. The console re-hashes the source ZIP and workpapers on every load and marks older sign-offs stale. An optional separately held anchor can expose a shortened or rewritten log | No real sign-off or independently stored anchor has been recorded |
| Optional signed reviewer identity | Ed25519 signatures on whole sign-off records, a local public-key allowlist with revocation, and separate signature status in the CLI and console. An optional setting withholds a decision unless the newest applicable record is validly signed | A signature establishes key possession, not real-world identity or institutional authority. There are no user accounts or access control; no real key was issued |
| Application harness | Authored bounded and deliberately unsafe fictional-policy cases | How would an independent, human-labeled live-LLM evaluation behave? |

## Run locally

You need Python 3.12.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
make audit
make test
make key-check
make browser-check   # optional: needs Google Chrome
```

`make dashboard` opens the local, read-only Streamlit viewer after `make audit` has written its working files. Dataset provenance and hashes are in [source notes](data/SOURCES.md). The saved [results](RESULTS.md) include Taiwan scorecard/XGBoost AUCs of 0.7837/0.7908 and German AUCs of 0.8142/0.8032, with split and confirmation caveats. The fictional-policy measurements use deterministic authored cases; no live LLM was run.

Each time a bundle is opened, the console re-hashes its source ZIP and compares it with the hash recorded in the bundle and the pin in `data/fetch.py`. The "Integrity and sign-off" tab lists those checks, the current workpaper hashes and every reviewer sign-off with its integrity and signature status. Sign-offs are added with `python -m audit.signoff sign` and written to `reviews/signoffs.jsonl`, which Git ignores; the repository ships only empty templates. The hash chain catches edits to earlier lines; `python -m audit.signoff anchor` can export its head for separate storage. Optional `keygen`, `key-add`, `key-revoke` and `sign --key-id --private-key` commands add Ed25519 signatures checked against a local reviewer-key allowlist. `MODELAUDIT_REQUIRE_SIGNATURE=1` requires the newest applicable record to have a valid signature before the decision is shown. Keep the private key, allowlist and anchor under separate control; this example has no authentication or access control. `make browser-check` drives the real console in headless Chrome through nine file, sign-off and signature scenarios. [Results](RESULTS.md) records the checks and limits.

## Repository map

`models/` trains baselines; `audit/` produces validation evidence; `llm_app_audit/` checks the local RAG fixture; `app/` displays the outputs.

## Scope

This is a validation exercise, not a lending decision system or a compliance certification. Taiwan ID order is a proxy split, not an application timeline; German confirmation reuses test rows. Raw source archives, private keys, reviewer allowlists and real sign-off logs stay outside this repository. A real review needs authorized dated data, institution-approved thresholds, accountable key issuance and responsible domain/legal review.
