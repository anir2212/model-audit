from streamlit.testing.v1 import AppTest


def test_console_loads_measured_bundle():
    app = AppTest.from_file('app/streamlit_app.py', default_timeout=30).run()
    assert not app.exception
    assert len(app.tabs) == 4
    assert [m.label for m in app.metric] == ['Test cohort rows', 'Registered tests', 'Findings']
