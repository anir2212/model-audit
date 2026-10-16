from audit.llm_drafter import check_draft_numbers


def test_rejects_unseen_figure():
    evidence = {'tests': {'PERF-AUC-01': {'values': {'auc': 0.78, 'count': 6000}}}}
    assert check_draft_numbers('AUC was 0.78 for 6000 rows.', evidence)
    assert not check_draft_numbers('AUC was 0.99 for 6000 rows.', evidence)
