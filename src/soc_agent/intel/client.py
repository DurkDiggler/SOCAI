from __future__ import annotations
import requests
from typing import Any, Dict, List
from ..config import SETTINGS
from ..logging import setup_json_logging
from .. import logging as _logging  # ensure formatter is registered
from .providers import otx, virustotal, abuseipdb

class IntelClient:
    def __init__(self):
        setup_json_logging()  # idempotent
        self.session = requests.Session()

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"indicator": ip, "sources": {}, "score": 0, "labels": []}
        votes: List[int] = []

        if SETTINGS.otx_api_key:
            try:
                data = otx.lookup_ip(self.session, ip, SETTINGS.http_timeout)
                results["sources"]["otx"] = data
                pulses = len(data.get("pulse_info", {}).get("pulses", []))
                if pulses:
                    votes.append(min(30, 10 + pulses))
            except Exception as e:
                results["sources"]["otx_error"] = str(e)

        if SETTINGS.vt_api_key:
            try:
                data = virustotal.lookup_ip(self.session, ip, SETTINGS.http_timeout)
                results["sources"]["virustotal"] = data
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                if malicious or suspicious:
                    votes.append(min(40, 5 * (malicious + suspicious)))
            except Exception as e:
                results["sources"]["vt_error"] = str(e)

        if SETTINGS.abuseipdb_api_key:
            try:
                data = abuseipdb.lookup_ip(self.session, ip, SETTINGS.http_timeout)
                results["sources"]["abuseipdb"] = data
                score = int(data.get("data", {}).get("abuseConfidenceScore", 0))
                if score:
                    votes.append(min(50, score))
            except Exception as e:
                results["sources"]["abuseipdb_error"] = str(e)

        agg = max(votes) if votes else 0
        results["score"] = agg
        if agg >= 70:
            results["labels"].append("malicious")
        elif agg >= 40:
            results["labels"].append("suspicious")
        else:
            results["labels"].append("unknown")
        return results

intel_client = IntelClient()
