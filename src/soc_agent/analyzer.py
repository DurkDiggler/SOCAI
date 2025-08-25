from __future__ import annotations
import re, socket
from typing import Any, Dict, List
from .intel import intel_client
from .config import SETTINGS

RULE_WEIGHTS = {
    "auth_failed": 15,
    "multiple_auth_failed": 25,
    "malware_detected": 40,
    "ransomware": 60,
    "port_scan": 15,
    "bruteforce": 35,
    "geo_anomaly": 20,
    "privilege_escalation": 50,
    "lateral_movement": 45,
    "exfil": 55,
}
SEVERITY_WEIGHT = 6


def is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def extract_iocs(event: Dict[str, Any]) -> Dict[str, List[str]]:
    ips: List[str] = []
    domains: List[str] = []
    for key in ("ip", "src_ip", "dst_ip", "attacker_ip", "host_ip"):
        v = event.get(key)
        if isinstance(v, str) and is_ip(v):
            ips.append(v)
    msg = event.get("message", "") or ""
    ips += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
    domains += re.findall(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", msg)
    ips = sorted({ip for ip in ips if is_ip(ip)})
    domains = sorted(set(domains))
    return {"ips": ips, "domains": domains}


def base_score(event: Dict[str, Any]) -> int:
    ev = (event.get("event_type") or "").lower()
    sev = int(event.get("severity") or 0)
    score = min(100, sev * SEVERITY_WEIGHT)
    score += RULE_WEIGHTS.get(ev, 0)
    raw = event.get("raw") or {}
    if isinstance(raw, dict):
        fail_count = int(raw.get("fail_count") or 0)
        if fail_count >= 5:
            score += min(20, 3 * (fail_count // 5))
        if raw.get("geo") in {"RU", "KP", "IR", "CN"}:
            score += 10
        if raw.get("new_admin_user"):
            score += 25
    return min(100, score)


def enrich_and_score(event: Dict[str, Any]) -> Dict[str, Any]:
    iocs = extract_iocs(event)
    intel_scores: List[int] = []
    intel_details: Dict[str, Any] = {"ips": [], "domains": []}

    for ip in iocs["ips"]:
        enriched = intel_client.enrich_ip(ip)
        intel_details["ips"].append(enriched)
        intel_scores.append(enriched.get("score", 0))

    bscore = base_score(event)
    isig = max(intel_scores) if intel_scores else 0
    final = min(100, int(round(0.6 * bscore + 0.4 * isig)))

    if final >= SETTINGS.score_high:
        category = "HIGH"
        action = "ticket"
    elif final >= SETTINGS.score_medium:
        category = "MEDIUM"
        action = "email"
    else:
        category = "LOW"
        action = "none"

    return {
        "iocs": iocs,
        "intel": intel_details,
        "scores": {"base": bscore, "intel": isig, "final": final},
        "category": category,
        "recommended_action": action,
    }
