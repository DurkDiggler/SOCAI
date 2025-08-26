from typing import Dict, Any


def normalize_crowdstrike_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a CrowdStrike Falcon event into :class:`EventIn` compatible dict."""

    event_type_raw = event.get("eventType") or event.get("Name") or "unknown"
    event_type = "auth_failed" if "authfail" in event_type_raw.lower() or "authentication failed" in event_type_raw.lower() else event_type_raw.lower()

    ip = event.get("LocalIP") or event.get("RemoteIP")

    return {
        "source": "crowdstrike",
        "event_type": event_type,
        "severity": int(event.get("Severity", 0)),
        "timestamp": event.get("Timestamp"),
        "message": event.get("Name"),
        "ip": ip,
        "username": event.get("UserName"),
        "raw": event,
    }
