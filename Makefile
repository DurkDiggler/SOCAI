.PHONY: setup run test fmt build up down schema

setup:
	pip install -r requirements.txt && pre-commit install

run:
	docker compose up --build

test:
	docker compose run --rm app pytest -q --cov soc_agent --cov-report=term-missing

fmt:
	ruff check --fix && ruff format

build:
	docker build -t soc-agent:latest .

up:
	docker compose up -d --build

down:
	docker compose down

schema:
	python scripts/gen_schema.py > schema.json
