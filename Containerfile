FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

COPY . /app
WORKDIR /app

RUN uv pip install --system .

ENTRYPOINT ["psi"]
