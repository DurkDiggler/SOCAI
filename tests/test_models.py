from soc_agent.models import EventIn

def test_event_validation():
    e = EventIn(event_type="auth_failed", severity=5, source="wazuh")
    assert e.severity == 5
