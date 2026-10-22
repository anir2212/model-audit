# ModelAudit

ModelAudit helps a reviewer ask whether a credit-risk model is behaving as expected and trace each concern back to evidence. It trains a readable scorecard and an XGBoost comparison model on two licensed UCI datasets, applies a registered set of checks, and exports HTML/PDF workpapers. A separate fictional-policy fixture exercises the application-audit harness.

## Why this project

A strong overall score can hide calibration problems, unstable inputs or different outcomes across groups. This project makes the review tests explicit and keeps their thresholds, measured values and source limitations together. The flags invite investigation; they are not credit decisions or legal findings.

## Current milestones

| Area | What works today | Next question |
|---|---|---|
| Credit-model review | Hash-checked inputs, two models, registered checks, saved findings and workpapers | Do flags repeat in an authorized, timestamped cohort? |
| Additional diagnostics | Retrospective repayment-status survival analysis and local evidence viewer | Which questions matter for a defined lending use case? |
| Reviewer navigation | The local console verifies each audit bundle's hash, re-checks stored statuses against the current check plan, gives findings stable IDs and traces each one to its evidence keys and workpaper section | It is read-only, with no user accounts or reviewer sign-off |
| Application harness | Authored bounded and deliberately unsafe fictional-policy cases | How would an independent, human-labeled live-LLM evaluation behave? |

## Run locally

You need Python 3.12.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
make audit
make test
```

`make dashboard` opens the local, read-only Streamlit viewer after `make audit` has written its working files. Dataset provenance and hashes are in [source notes](data/SOURCES.md). The saved [results](RESULTS.md) include Taiwan scorecard/XGBoost AUCs of 0.7837/0.7908 and German AUCs of 0.8142/0.8032, with split and confirmation caveats. The fictional-policy measurements use deterministic authored cases; no live LLM was run.

## Repository map

`models/` trains baselines; `audit/` produces validation evidence; `llm_app_audit/` checks the local RAG fixture; `app/` displays the outputs.

## Scope

This is a validation exercise, not a lending decision system or a compliance certification. Taiwan ID order is a proxy split, not an application timeline; German confirmation reuses test rows. Raw source archives stay outside this repository. A real review needs authorized dated data, institution-approved thresholds and responsible domain/legal review.
