PYTHON ?= .venv/bin/python
export MPLCONFIGDIR := $(CURDIR)/.mplconfig
export OPENBLAS_NUM_THREADS := 2
export OMP_NUM_THREADS := 2
.PHONY: data models survival explain testsuite llm workpapers audit test app-test dashboard

data:
	$(PYTHON) -m data.fetch
models: data
	$(PYTHON) -m models.train
survival: data
	$(PYTHON) -m models.survival
explain: models
	$(PYTHON) -m audit.explain
testsuite: explain survival
	$(PYTHON) -m audit.run --dataset all
llm:
	$(PYTHON) -m llm_app_audit.workpaper
workpapers: testsuite llm
	$(PYTHON) -m audit.workpaper
audit: workpapers

test:
	$(PYTHON) -m pytest -q
app-test:
	$(PYTHON) -m pytest -q tests/test_app.py
dashboard:
	.venv/bin/streamlit run app/streamlit_app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
