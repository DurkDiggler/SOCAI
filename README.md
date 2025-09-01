# SOC Agent (Refined)

FastAPI webhook that ingests security events, enriches IOCs (OTX / VirusTotal / AbuseIPDB), scores them, and either emails the SOC or opens an Autotask ticket. Built for Docker, tested with pytest, and wired for CI.

## Deployment (Docker)

1. **Clone the repository**
   ```bash
   git clone https://github.com/DurkDiggler/SOCAI.git
   cd SOCAI
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env  # edit as needed
   ```

3. **Build and launch with Docker Compose**
   ```bash
   docker compose up --build
   # or
   make up
   ```

4. **Verify the API**
   ```bash
   curl http://localhost:8000/healthz
   ```
   Optionally, check the readiness probe:
   ```bash
   curl http://localhost:8000/readyz
   ```

5. **Run tests inside the container (optional)**
   ```bash
   docker compose run --rm app pytest -q --cov soc_agent --cov-report=term-missing
   ```

6. **Stop services**
   ```bash
   docker compose down
   # or
   make down
   ```

### Vendor Adapters (Wazuh & CrowdStrike)
The service auto-detects and normalizes common vendor payloads to the internal `EventIn` schema before scoring.

- **Wazuh** → severity from `rule.level`; event type inferred from `rule.description`; IP from `data.srcip` or `full_log`; username from `data.srcuser`.
- **CrowdStrike** → event type from `eventType`/`Name`; severity from `Severity`; IP from `LocalIP`/`RemoteIP`; username from `UserName`.

If you already POST in the normalized schema, adapters are skipped automatically.
