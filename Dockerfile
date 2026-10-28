# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.13-trixie-slim AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
ARG COLLECTOR_VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${COLLECTOR_VERSION}
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE.md extension.yaml ./
COPY src ./src
RUN test -n "$COLLECTOR_VERSION"
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-editable --no-dev --group container

FROM gcr.io/distroless/python3-debian13:nonroot AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/.venv/lib/python3.13/site-packages \
    LOG_CONTAINER=true \
    RUNTIME__LOG_PATH=/app/logs \
    DESTINATION__BLOODHOUNDENTERPRISE__COLLECTOR_NAME=jamf
COPY --from=builder --chown=65532:65532 /app /app
WORKDIR /app
USER 65532:65532

FROM base AS cli
ENTRYPOINT ["python", "-m", "openhound"]
CMD ["--help"]

FROM base AS enterprise
ENTRYPOINT ["python", "src/scheduler.py"]
