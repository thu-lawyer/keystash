# keystash — zero-plaintext secret vault + MCP server
FROM python:3.12-slim

# Required by the MCP registry ownership check (must match server.json's name)
LABEL io.modelcontextprotocol.server.name="io.github.thu-lawyer/keystash"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# The vault is NOT baked into the image — mount or copy your own at runtime.
# MCP speaks stdio, so the server must stay in the foreground.
ENTRYPOINT ["keystash", "mcp"]
