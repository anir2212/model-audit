import json
import shutil
from pathlib import Path

import yaml
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / 'app/streamlit_app.py')


def _run(monkeypatch, audit_dir=None, plan=None):
    if audit_dir:
        monkeypatch.setenv('MODELAUDIT_AUDIT_DIR', str(audit_dir))
    if plan:
        monkeypatch.setenv('MODELAUDIT_PLAN', str(plan))
    return AppTest.from_file(APP, default_timeout=30).run()


def _evidence_copy(tmp_path):
    target = tmp_path / 'audit'
    shutil.copytree(ROOT / 'evidence/audit', target)
    return target


def test_console_loads_measured_bundle():
    app = AppTest.from_file(APP, default_timeout=30).run()
    assert not app.exception
    assert len(app.tabs) == 4
    assert [m.label for m in app.metric] == ['Test cohort rows', 'Registered tests', 'Findings']
    assert not app.error


def test_findings_trace_to_evidence_and_label_confirmation_limit(monkeypatch, tmp_path):
    app = _run(monkeypatch, _evidence_copy(tmp_path))
    app.selectbox[0].select('german_xgb').run()
    assert not app.exception and not app.error
    assert any('Reuses 125 rows' in w.value for w in app.warning)
    trace_box = next(box for box in app.selectbox if box.label == 'Trace a finding to its evidence')
    assert trace_box.options[0].startswith('german-xgb-')
    trace_box.select('german-xgb-CAL-ECE-01').run()
    text = ' '.join(m.value for m in app.markdown)
    assert 'runs/audit/german_xgb.json' in text and 'tests.CAL-ECE-01' in text
    assert 'german_xgb.html#CAL-ECE-01' in text
    assert not any('stale' in w.value for w in app.warning)


def test_changed_plan_marks_status_stale(monkeypatch, tmp_path):
    plan = yaml.safe_load((ROOT / 'configs/audit_plan.yaml').read_text())
    plan['thresholds']['CAL-ECE-01'] = {'metric': 'ece', 'warn_above': 0.5, 'fail_above': 0.6}
    plan_path = tmp_path / 'plan.yaml'
    plan_path.write_text(yaml.safe_dump(plan))
    app = _run(monkeypatch, _evidence_copy(tmp_path), plan_path)
    app.selectbox[0].select('german_xgb').run()
    assert not app.exception
    stale = [w.value for w in app.warning if 'stale' in w.value]
    assert stale and 'CAL-ECE-01 warn → pass (threshold changed)' in stale[0]


def test_tampered_bundle_is_refused(monkeypatch, tmp_path):
    audit = _evidence_copy(tmp_path)
    for name in ('taiwan_scorecard', 'taiwan_xgb', 'german_scorecard', 'german_xgb'):
        path = audit / f'{name}.json'
        bundle = json.loads(path.read_text())
        bundle['tests']['PERF-AUC-01']['values']['auc'] = 0.99
        path.write_text(json.dumps(bundle))
    app = _run(monkeypatch, audit)
    assert not app.exception
    assert app.error and 'hash mismatch' in app.error[0].value
    assert not app.metric
