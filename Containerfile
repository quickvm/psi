FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libdbus-1-dev \
        libglib2.0-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

FROM python:3.14-slim-bookworm

LABEL org.opencontainers.image.source=https://github.com/quickvm/psi

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libdbus-1-3 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app /app
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["psi"]
