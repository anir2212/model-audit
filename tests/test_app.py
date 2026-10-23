import json
import shutil
from pathlib import Path

import pytest
import yaml
from streamlit.testing.v1 import AppTest

from audit.signoff import append_signoff
from conftest import EXAMPLE_OWNER, TODAY, SignoffCase, redigest

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / 'app/streamlit_app.py')


def _run(monkeypatch, audit_dir=None, plan=None, raw=None, workpapers=None, log=None):
    for variable, value in (('MODELAUDIT_AUDIT_DIR', audit_dir), ('MODELAUDIT_PLAN', plan),
                            ('MODELAUDIT_RAW_DIR', raw), ('MODELAUDIT_WORKPAPER_DIR', workpapers),
                            ('MODELAUDIT_SIGNOFF_LOG', log)):
        if value:
            monkeypatch.setenv(variable, str(value))
    return AppTest.from_file(APP, default_timeout=30).run()


def _evidence_copy(tmp_path):
    target = tmp_path / 'audit'
    shutil.copytree(ROOT / 'evidence/audit', target)
    return target


def test_console_loads_measured_bundle():
    app = AppTest.from_file(APP, default_timeout=30).run()
    assert not app.exception
    assert len(app.tabs) == 5
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


def _german(app):
    app.selectbox[0].select('german_xgb').run()
    assert not app.exception
    return app


@pytest.mark.skipif(not (ROOT / 'data/raw/uci_german_144.zip').exists(),
                    reason='source archives not fetched; run `make data`')
def test_source_archive_rechecked_as_match(monkeypatch, tmp_path):
    app = _german(_run(monkeypatch, _evidence_copy(tmp_path), raw=ROOT / 'data/raw',
                       log=tmp_path / 'none.jsonl'))
    assert any('uci_german_144.zip was hashed now and matches' in s.value for s in app.success)
    assert not app.error


def test_replaced_source_archive_shows_mismatch(monkeypatch, tmp_path):
    raw = tmp_path / 'raw'
    raw.mkdir()
    (raw / 'uci_german_144.zip').write_bytes(b'replaced archive')
    app = _german(_run(monkeypatch, _evidence_copy(tmp_path), raw=raw, log=tmp_path / 'none.jsonl'))
    assert app.error and 'Source archive mismatch: uci_german_144.zip' in app.error[0].value
    assert len(app.tabs) == 5  # evidence stays viewable; the mismatch is stated above it


def test_missing_source_archive_is_stated(monkeypatch, tmp_path):
    raw = tmp_path / 'raw'
    raw.mkdir()
    app = _german(_run(monkeypatch, _evidence_copy(tmp_path), raw=raw, log=tmp_path / 'none.jsonl'))
    assert any('Source archive missing: uci_german_144.zip' in w.value for w in app.warning)
    assert any('Sign-off: none recorded' in i.value for i in app.info)


def _signoff_table(app):
    return next(frame.value for frame in app.dataframe if 'decision' in frame.value.columns)


def test_console_shows_current_and_stale_example_signoffs(monkeypatch, tmp_path):
    case = SignoffCase(tmp_path)
    earlier = redigest(dict(case.bundle, scope='earlier run of the same audit (example)'))
    for bundle, decision, conditions in ((earlier, 'reject', []),
                                         (case.bundle, 'approve_with_conditions', ['Example condition'])):
        append_signoff(case.log, case.request(bundle_sha256=bundle['sha256'], decision=decision,
                                              conditions=conditions),
                       bundle, case.plan, case.plan_sha, case.workpaper(), case.source_match, today=TODAY)
    app = _german(_run(monkeypatch, case.audit, workpapers=case.workpapers, log=case.log))
    assert any(f'Current sign-off: approve_with_conditions by {EXAMPLE_OWNER}' in i.value for i in app.info)
    table = _signoff_table(app)
    assert list(table['status']) == ['current', 'stale_bundle']
    assert any('record 1 stale_bundle' in w.value for w in app.warning)
    files = next(frame.value for frame in app.dataframe if 'label' in frame.value.columns)
    assert set(files.loc[files['label'].str.startswith('workpaper'), 'status']) == {'match'}


def test_changed_workpaper_makes_signoff_stale(monkeypatch, tmp_path):
    case = SignoffCase(tmp_path)
    append_signoff(case.log, case.request(), case.bundle, case.plan, case.plan_sha, case.workpaper(),
                   case.source_match, today=TODAY)
    with (case.workpapers / 'german_xgb.html').open('a') as handle:
        handle.write('<!-- edited after sign-off -->')
    app = _german(_run(monkeypatch, case.audit, workpapers=case.workpapers, log=case.log))
    assert any('earlier sign-offs are stale' in w.value for w in app.warning)
    assert list(_signoff_table(app)['status']) == ['stale_workpaper']


def test_edited_signoff_log_is_flagged(monkeypatch, tmp_path):
    case = SignoffCase(tmp_path)
    append_signoff(case.log, case.request(), case.bundle, case.plan, case.plan_sha, case.workpaper(),
                   case.source_match, today=TODAY)
    case.log.write_text(case.log.read_text().replace('approve_with_conditions', 'approve'))
    app = _german(_run(monkeypatch, case.audit, workpapers=case.workpapers, log=case.log))
    assert any('Sign-off log integrity failure' in e.value for e in app.error)
    assert list(_signoff_table(app)['status']) == ['log_integrity_failed']


def test_replaced_source_archive_makes_signoff_stale(monkeypatch, tmp_path):
    case = SignoffCase(tmp_path)
    append_signoff(case.log, case.request(), case.bundle, case.plan, case.plan_sha, case.workpaper(),
                   case.source_match, today=TODAY)
    raw = tmp_path / 'raw'
    raw.mkdir()
    (raw / 'uci_german_144.zip').write_bytes(b'replaced archive')
    app = _german(_run(monkeypatch, case.audit, raw=raw, workpapers=case.workpapers, log=case.log))
    assert any('Source archive mismatch' in e.value for e in app.error)
    assert list(_signoff_table(app)['status']) == ['stale_source']
