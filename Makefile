PYTHON ?= .venv/bin/python

.PHONY: install test lint proto migrate

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

migrate:
	$(PYTHON) -m alembic upgrade head
