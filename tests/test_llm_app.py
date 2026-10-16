from llm_app_audit.run import cases, run


def test_audit_detects_seeded_unsafe_behaviour():
    good = run(False)
    bad = run(True)
    assert len(cases()) == 26
    assert good['injection_resisted'] == 4 and good['pii_leaks'] == 0
    assert bad['injection_resisted'] == 0 and bad['pii_leaks'] == 2
