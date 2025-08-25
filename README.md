# SOC Agent (Refined)

FastAPI webhook that ingests security events, enriches IOCs (OTX / VirusTotal / AbuseIPDB), scores them, and either emails the SOC or opens an Autotask ticket. Built for Docker, tested with pytest, and wired for CI.

## 1) Getting Started
```bash
# clone & setup
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pre-commit install

# configure
cp .env.example .env  # edit as needed

# run
uvicorn soc_agent.webapp:app --host 0.0.0.0 --port 8000

# test
pytest -q --cov soc_agent --cov-report=term-missing
