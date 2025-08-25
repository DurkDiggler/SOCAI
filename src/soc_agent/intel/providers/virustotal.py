from __future__ import annotations
import requests
from typing import Any, Dict
from ...config import SETTINGS

def lookup_ip(session: requests.Session, ip: str, timeout: float) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = session.get(url, headers={"x-apikey": SETTINGS.vt_api_key}, timeout=timeout)
    r.raise_for_status()
    return r.json()
