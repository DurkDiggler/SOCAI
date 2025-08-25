from typing import Dict, Any

def normalize_crowdstrike_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a CrowdStrike Falcon event into EventIn‑compatible dict.
    """
    meta = event.get("metadata", {})
    event_type = meta.get("eventType", "unknown")
    sev = int(event.get("Severity", 0)) if "Severity" in event else 0

    return {
        "source": "crowdstrike",
        "event_type": event_type.lower(),
        "severity": sev,
        "timestamp": meta.get("eventCreationTime"),
        "message": event.get("event_simpleName"),
        "ip": event.get("ComputerIP"),
        "username": event.get("UserName"),
        "raw": event,
    }
