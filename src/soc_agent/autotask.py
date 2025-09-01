from __future__ import annotations

from typing import Any, Optional, Tuple

import requests

from .config import SETTINGS


def create_autotask_ticket(
    title: str,
    description: str,
    priority: Optional[int] = None,
) -> Tuple[bool, str, Optional[Any]]:
    if not SETTINGS.enable_autotask:
        return False, "Autotask disabled", None
    for needed in (
        SETTINGS.at_base_url,
        SETTINGS.at_api_integration_code,
        SETTINGS.at_username,
        SETTINGS.at_secret,
        SETTINGS.at_account_id,
        SETTINGS.at_queue_id,
    ):
        if not needed:
            return False, "Autotask not fully configured", None

    url = f"{SETTINGS.at_base_url.rstrip('/')}/tickets"
    headers = {
        "ApiIntegrationCode": SETTINGS.at_api_integration_code,
        "UserName": SETTINGS.at_username,
        "Secret": SETTINGS.at_secret,
    }
    payload = {
        "title": title,
        "description": description,
        "status": 1,
        "queueID": int(SETTINGS.at_queue_id),
        "accountID": int(SETTINGS.at_account_id),
        "priority": int(priority or SETTINGS.at_ticket_priority),
    }
    try:
        r = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=SETTINGS.http_timeout,
        )
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}: {r.text}", None
        return True, "created", r.json()
    except Exception as e:
        return False, str(e), None
