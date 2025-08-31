from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .adapters import normalize_event
from .analyzer import enrich_and_score
from .autotask import create_autotask_ticket
from .config import SETTINGS
from .logging import setup_json_logging
from .models import EventIn
from .notifiers import send_email
from .security import WebhookAuth

app = FastAPI(title="SOC Agent – Webhook Analyzer", version="1.2.0")
setup_json_logging()


@app.get("/")
def root():
    return {"ok": True, "service": "SOC Agent – Webhook Analyzer", "version": "1.2.0"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    return {"status": "ready"}


@app.post("/webhook")
async def webhook(req: Request):
    body = await req.body()

    # Optional shared-secret or HMAC verification
    if SETTINGS.webhook_shared_secret:
        provided = req.headers.get("X-Webhook-Secret")
        if not WebhookAuth.verify_shared_secret(provided, SETTINGS.webhook_shared_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook secret")
    if SETTINGS.webhook_hmac_secret:
        signature = req.headers.get(SETTINGS.webhook_hmac_header)
        if not WebhookAuth.verify_hmac(
            body, signature, SETTINGS.webhook_hmac_secret, SETTINGS.webhook_hmac_prefix
        ):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    try:
        event = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Normalize vendor payloads first
    normalized = normalize_event(event)

    # Validate normalized payload
    try:
        payload = EventIn.model_validate(normalized)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid payload: {e}")

    result = enrich_and_score(payload.model_dump())

    title = (
        f"[{result['category']}] {payload.event_type or 'event'} – {payload.source or 'unknown'}"
    )
    summary_lines = [
        f"Source: {payload.source}",
        f"Type: {payload.event_type}  Severity: {payload.severity}",
        f"Timestamp: {payload.timestamp}",
        f"Message: {payload.message}",
        f"IOCs: {json.dumps(result['iocs'])}",
        (
            f"Scores: base={result['scores']['base']} "
            f"intel={result['scores']['intel']} "
            f"final={result['scores']['final']}"
        ),
        f"Recommended action: {result['recommended_action']}",
    ]
    for ipinfo in result.get("intel", {}).get("ips", []):
        label = ",".join(ipinfo.get("labels", []))
        scr = ipinfo.get("score", 0)
        summary_lines.append(f"Intel: {ipinfo['indicator']} -> {label} (score {scr})")
    body_out = "\n".join(summary_lines)

    actions = {}
    if result["recommended_action"] == "ticket":
        ok, msg, resp = create_autotask_ticket(title=title, description=body_out)
        actions["autotask_ticket"] = {"ok": ok, "message": msg, "response": resp}
    elif result["recommended_action"] == "email":
        ok, msg = send_email(subject=title, body=body_out)
        actions["email"] = {"ok": ok, "message": msg}

    return JSONResponse({"analysis": result, "actions": actions})
