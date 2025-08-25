.PHONY: setup run test fmt build up down schema

setup:
	python -m venv .venv && . .venv/bin/activate && pip install -e .[dev] && pre-commit install

run:
	uvicorn soc_agent.webapp:app --host $${APP_HOST:-0.0.0.0} --port $${APP_PORT:-8000}

test:
	pytest -q --cov soc_agent --cov-report=term-missing

fmt:
	ruff check --fix && ruff format

build:
	docker build -t soc-agent:latest .

up:
	docker-compose up -d --build

down:
	docker-compose down

schema:
	python scripts/gen_schema.py > schema.json
