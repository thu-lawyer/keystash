# keystash — zero-plaintext secret broker + MCP server
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

# v0.4.0 keeps values in the macOS login Keychain, so this Linux image serves
# MCP registry / tooling introspection (tools/list) only — it cannot store
# secrets. Run keystash on macOS to actually hold and use keys.
# No secret is ever baked into the image.
# MCP speaks stdio, so the server must stay in the foreground.
ENTRYPOINT ["keystash", "mcp"]
