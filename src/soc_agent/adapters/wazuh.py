from typing import Dict, Any
import re


def normalize_wazuh_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Wazuh alert JSON into :class:`EventIn` compatible dict."""

    rule = event.get("rule", {})
    data = event.get("data", {})

    # Wazuh uses rule descriptions such as ``"sshd: authentication failed"``.
    desc = rule.get("description", "")
    event_type = "auth_failed" if "authentication failed" in desc.lower() else rule.get("id", "unknown")

    ip = data.get("srcip")
    if not ip:
        # Fallback to parsing the IP from the full log line
        full_log = event.get("full_log", "")
        match = re.search(r"from ([0-9.]+)", full_log)
        if match:
            ip = match.group(1)

    return {
        "source": "wazuh",
        "event_type": event_type,
        "severity": int(rule.get("level", 0)),
        "timestamp": event.get("@timestamp"),
        "message": desc,
        "ip": ip,
        "username": data.get("srcuser"),
        "raw": event,
    }
