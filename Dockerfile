# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG PYTHON_IMAGE=python:3.11-alpine3.23@sha256:0d4aa8a1d695338c310edfec1ca1e52bab7f5494ac3faf9f27863a36bf94bf1a

FROM ${PYTHON_IMAGE} AS dependencies

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY requirements/runtime.lock requirements/runtime.lock
RUN --mount=type=cache,target=/root/.cache/pip python -m pip install \
      --require-hashes \
      --only-binary=:all: \
      --no-deps \
      --prefix=/opt/python \
      -r requirements/runtime.lock

FROM ${PYTHON_IMAGE} AS runtime

# Packaging tools are needed only in the dependency stage.
RUN python -m pip uninstall --yes pip setuptools wheel

ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Autonomous SRE Incident Commander API" \
      org.opencontainers.image.description="Governed incident-command API and migration runtime" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/Stevemeg/Autonomous-SRE-Incident-Commander"

ENV PATH=/opt/python/bin:${PATH} \
    PYTHONPATH=/opt/python/lib/python3.11/site-packages:/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ASIC_API_HOST=0.0.0.0 \
    ASIC_API_PORT=8000

WORKDIR /app
COPY --from=dependencies /opt/python /opt/python
COPY --chown=10001:10001 src/asic ./src/asic
COPY --chown=10001:10001 migrations ./migrations
COPY --chown=10001:10001 alembic.ini ./alembic.ini

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/livez', timeout=2).read()"]

CMD ["/usr/local/bin/python", "-m", "asic.api"]
