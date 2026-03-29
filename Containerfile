FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

LABEL org.opencontainers.image.source=https://github.com/quickvm/psi

COPY . /app
WORKDIR /app

RUN uv pip install --system .

ENTRYPOINT ["psi"]
