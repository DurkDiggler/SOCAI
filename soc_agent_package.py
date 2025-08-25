# Project structure (YAML-based config, proper package, Dockerfile, unit tests)

soc_agent/
├── Dockerfile
├── pyproject.yaml          # (instead of pyproject.toml)
├── README.md
├── soc_agent/
│   ├── __init__.py
│   ├── app.py              # FastAPI app entry
│   ├── analyzer.py         # scoring rules + enrichment orchestrator
│   ├── config.py           # YAML-based config loader
│   ├── feeds.py            # Threat intel feed clients
│   ├── notifiers.py        # Email + Autotask
│   └── utils.py            # helpers (cache, ioc extraction)
├── config.yaml             # default config schema + settings
└── tests/
    ├── __init__.py
    ├── test_analyzer.py
    ├── test_feeds.py
    ├── test_notifiers.py
    └── test_utils.py

# ------------------ pyproject.yaml ------------------
project:
  name: soc-agent
  version: 0.1.0
  description: SOC Agent – webhook receiver, analyzer, notifier
  authors:
    - name: Your Name
      email: you@example.com
  dependencies:
    - fastapi
    - uvicorn
    - requests
    - pyyaml
  optional-dependencies:
    dev:
      - pytest
      - httpx

# ------------------ config.yaml ------------------
app:
  host: 0.0.0.0
  port: 8000
  score_thresholds:
    medium: 40
    high: 70

email:
  enabled: true
  smtp_host: smtp.example.com
  smtp_port: 587
  username: alerts@example.com
  password: supersecret
  from: alerts@example.com
  to:
    - soc@example.com

autotask:
  enabled: true
  base_url: https://webservices11.autotask.net/atservicesrest/v1.0
  api_integration_code: your_integration_code
  username: api-user@example.com
  secret: your_autotask_secret
  account_id: 12345
  queue_id: 67890
  priority: 3

feeds:
  otx:
    api_key: YOUR_OTX_KEY
  virustotal:
    api_key: YOUR_VT_KEY
  abuseipdb:
    api_key: YOUR_ABUSEIPDB_KEY

# ------------------ Dockerfile ------------------
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.yaml ./
RUN pip install --no-cache-dir pyyaml fastapi uvicorn requests

COPY soc_agent/ soc_agent/
COPY config.yaml ./config.yaml

EXPOSE 8000

CMD ["uvicorn", "soc_agent.app:app", "--host", "0.0.0.0", "--port", "8000"]

# ------------------ soc_agent/config.py ------------------
import yaml
import os

CONFIG_PATH = os.getenv("SOC_AGENT_CONFIG", "config.yaml")

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

CONFIG = load_config()

# ------------------ soc_agent/app.py ------------------
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from soc_agent.analyzer import enrich_and_score
from soc_agent.notifiers import send_email, create_autotask_ticket

app = FastAPI(title="SOC Agent", version="0.1.0")

@app.get("/")
def root():
    return {"ok": True, "service": "SOC Agent", "version": "0.1.0"}

@app.post("/webhook")
async def webhook(req: Request):
    try:
        event = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    result = enrich_and_score(event)

    # handle actions
    if result["recommended_action"] == "ticket":
        ok, msg, resp = create_autotask_ticket(result)
    elif result["recommended_action"] == "email":
        ok, msg = send_email(result)
    else:
        ok, msg, resp = (True, "noop", None)

    return JSONResponse({"analysis": result, "status": msg})

# ------------------ tests/test_analyzer.py ------------------
import pytest
from soc_agent.analyzer import enrich_and_score

def test_low_score_event():
    event = {"event_type": "auth_failed", "severity": 1, "message": "fail"}
    result = enrich_and_score(event)
    assert result["category"] in ["LOW", "MEDIUM", "HIGH"]
    assert "scores" in result

# ------------------ tests/test_utils.py ------------------
from soc_agent.utils import is_ip, extract_iocs

def test_is_ip():
    assert is_ip("8.8.8.8")
    assert not is_ip("not.an.ip")

def test_extract_iocs():
    e = {"message": "connection from 1.2.3.4 to evil.com"}
    out = extract_iocs(e)
    assert "1.2.3.4" in out["ips"]
    assert "evil.com" in out["domains"]