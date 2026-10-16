# ModelAudit

Reproducible model validation workpapers.

A model-validation workflow that builds credit-score baselines, checks data and performance, and exports evidence-linked HTML/PDF workpapers. A local RAG fixture probes evidence and refusal behavior.

## Why this project

A model score is hard to trust without a reproducible trail from source data to validation finding. This project turns that trail into workpapers that another reviewer can inspect, including where the evidence is thin.

## Run locally

You need Python 3.12.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
make audit
make test
```

`make dashboard` opens the local Streamlit viewer. Dataset provenance and hashes are in [source notes](data/SOURCES.md); [results](RESULTS.md) distinguishes the measured validation cases.

## Repository map

`models/` trains baselines; `audit/` produces validation evidence; `llm_app_audit/` checks the local RAG fixture; `app/` displays the outputs.

## Scope

This is a validation exercise, not a lending decision system or a compliance certification. Check the source licenses before redistributing input archives.
