# CredBroker container image.
#
# Multi-stage build: the builder stage installs the package (and its compiled
# dependencies) into an isolated virtualenv; the runtime stage copies only that
# virtualenv plus the Alembic migration tree onto a fresh slim base and runs as
# an unprivileged user. No compilers, package manager caches, or source
# metadata ship in the final image.
#
# The image never bakes in secrets: all configuration (database URL, KMS key,
# OAuth client, JWT keypair) arrives at runtime via CREDBROKER_* environment
# variables — see credbroker/config.py.

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN python -m venv /opt/venv

# Copy only what `pip install .` needs so unrelated edits don't bust the cache.
COPY pyproject.toml ./
COPY credbroker ./credbroker

RUN /opt/venv/bin/pip install .

# ---------------------------------------------------------------------------

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

# Unprivileged runtime user; the app needs no writable filesystem state.
RUN groupadd --system credbroker && \
    useradd --system --gid credbroker --home-dir /app --shell /usr/sbin/nologin credbroker

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

# Ship the migration tree so operators can run
# `python -m alembic upgrade head` inside the container (compose does this on
# boot; in AWS it runs as a one-off ECS task before a deploy).
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic

USER credbroker

EXPOSE 8000 50051

# python:slim has no curl; probe /healthz with the stdlib instead.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

CMD ["python", "-m", "credbroker.main"]
