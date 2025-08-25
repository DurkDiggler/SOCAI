from typing import Dict, Any

def normalize_wazuh_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a Wazuh alert JSON into EventIn‑compatible dict.
    """
    rule = event.get("rule", {})
    agent = event.get("agent", {})
    srcip = event.get("srcip")

    return {
        "source": "wazuh",
        "event_type": rule.get("id", "unknown"),
        "severity": int(rule.get("level", 0)),
        "timestamp": event.get("@timestamp"),
        "message": rule.get("description"),
        "ip": srcip,
        "username": agent.get("name"),
        "raw": event,
    }
