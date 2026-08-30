PYTHON ?= .venv/bin/python

.PHONY: install test lint proto run migrate docker-build up down demo

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

# One-command local demo: full stack against the fake Drive API (no Google
# credentials), seeded with a demo agent + connected account.
demo:
	docker compose up -d --build
	@echo "Waiting for the broker, then seeding demo data..."
	@for i in $$(seq 1 30); do \
		if curl -fsS -X POST http://localhost:8000/console/api/demo/seed; then \
			echo; break; \
		fi; \
		if [ $$i -eq 30 ]; then \
			echo "broker did not become ready; check 'docker compose logs broker'" >&2; \
			exit 1; \
		fi; \
		sleep 2; \
	done
	@echo "Console ready: http://localhost:8000/console"
