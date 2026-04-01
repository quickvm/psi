FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libdbus-1-dev \
        libglib2.0-dev \
        pkg-config \
        swig \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev --extra dbus --extra nitrohsm
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra dbus --extra nitrohsm

FROM fedora:latest

LABEL org.opencontainers.image.source=https://github.com/quickvm/psi

RUN dnf install -y \
        python3.14 \
        dbus-libs \
        glib2 \
        opensc \
        pcsc-lite-libs \
    && dnf clean all

COPY --from=builder /app /app
RUN ln -sf /usr/bin/python3.14 /usr/local/bin/python3
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["psi"]
