FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.2 /uv /uvx /bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY config ./config
COPY evals ./evals
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH" \
    ARGUS_DATA_DIR=/data ARGUS_VAR_DIR=/var/lib/argus ARGUS_OUT_DIR=/out
VOLUME ["/data", "/var/lib/argus", "/out"]
ENTRYPOINT ["argus"]
CMD ["watch", "--interval", "300"]
