PYTHON ?= .venv/bin/python

.PHONY: install test lint proto run migrate docker-build up down

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check credbroker tests

proto:
	bash scripts/gen_proto.sh

run:
	$(PYTHON) -m credbroker.main

migrate:
	$(PYTHON) -m alembic upgrade head

docker-build:
	docker build -t credbroker:local .

up:
	docker compose up -d

down:
	docker compose down
