"""Tests for keystash 0.4.2 — the local secret broker.

Two rules shape this suite:

* **The real login Keychain is never touched** unless you explicitly opt in
  with ``KEYSTASH_TEST_KEYCHAIN=1``. Every value store here is a
  :class:`~keystash.broker.MemoryStore`, and every HTTP call goes to a
  throwaway server on 127.0.0.1.
* **The CLI is driven as a subprocess.** keystash is a command-line tool with a
  stdio MCP mode; testing it the way it is actually used catches wiring bugs
  that in-process test runners hide, and keeps the suite independent of
  Typer/Click internals.
"""

from __future__ import annotations

import base64
import json
import os
import string
import subprocess
import sys
import threading
import urllib.parse
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:  # allow `pytest` from a checkout without install
    sys.path.insert(0, str(SRC))

from keystash import broker, keychain, mcp_server  # noqa: E402
from keystash.broker import (  # noqa: E402
    REDACTED,
    BrokerError,
    Entry,
    MemoryStore,
    check_allowed,
    generate_value,
    normalise_allow_prefix,
    normalise_url,
    scrub,
    validate_name,
)

TOOL_NAMES = [
    "secret_list",
    "secret_store",
    "secret_rotate",
    "secret_generate",
    "secret_use",
    "secret_delete",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _Recorder(BaseHTTPRequestHandler):
    """A tiny HTTP server that remembers exactly what it was sent."""

    routes: dict = {}
    seen: list = []

    def _handle(self) -> None:  # noqa: D102
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length) if length else b""
        type(self).seen.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": payload,
            }
        )
        status, body, headers = type(self).routes.get(self.path, (200, b"{}", {}))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *args) -> None:  # noqa: D102 - keep pytest output clean
        pass


@pytest.fixture()
def http_server():
    _Recorder.routes = {}
    _Recorder.seen = []
    server = HTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    try:
        yield base, _Recorder
    finally:
        server.shutdown()
        server.server_close()


def _seed(tmp_path, name, value, **kwargs):
    """Store a value in memory and write metadata to a scratch file."""
    meta = tmp_path / "entries.json"
    store = MemoryStore()
    broker.put(name, value, store=store, path=str(meta), **kwargs)
    return meta, store


def _cli(*args, meta, stdin=None, timeout=120):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("KEYSTASH_VAULT", None)
    if meta is not None:
        env["KEYSTASH_META"] = str(meta)
    return subprocess.run(
        [sys.executable, "-m", "keystash.cli", *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("good", ["A", "OPENAI_PROD_READONLY", "SMTP_163_AUTH_CODE", "A1_B2"])
def test_validate_name_accepts_service_env_purpose(good):
    assert validate_name(good) == good


@pytest.mark.parametrize("bad", ["openai", "1OPENAI", "_OPENAI", "OPENAI-PROD", "OPENAI PROD", "", "A" * 65])
def test_validate_name_rejects_everything_else(bad):
    with pytest.raises(BrokerError):
        validate_name(bad)


# ---------------------------------------------------------------------------
# entries and metadata
# ---------------------------------------------------------------------------


def test_entry_survives_a_roundtrip():
    entry = Entry(
        name="X",
        tags=["a", "b"],
        rotate_every_days=30,
        last_rotated="2026-01-01",
        allowed_urls=["https://api.example.com/"],
        created_at="2026-01-01",
    )
    assert Entry.from_dict(entry.to_dict()) == entry


def test_rotation_is_due_only_when_a_policy_exists():
    entry = Entry(name="X", rotate_every_days=30, last_rotated="2026-01-01")
    assert entry.rotate_due(date(2026, 1, 30)) is False
    assert entry.rotate_due(date(2026, 1, 31)) is True
    assert Entry(name="X").rotate_due() is None
    assert Entry(name="X", rotate_every_days=30).rotate_due() is None
    assert Entry(name="X", rotate_every_days=30, last_rotated="not-a-date").rotate_due() is None


def test_describe_exposes_metadata_and_nothing_else():
    described = Entry(name="X").describe()
    assert set(described) == {
        "name",
        "tags",
        "rotate_every_days",
        "last_rotated",
        "allowed_urls",
        "auth_header",
        "auth_prefix",
        "created_at",
        "rotate_due",
    }


def test_put_rotates_in_place_and_keeps_created_at(tmp_path):
    meta = tmp_path / "entries.json"
    store = MemoryStore()
    first = broker.put("DEMO_KEY", "value-aaaaaaaaaaaa", tags=["one"], store=store, path=str(meta))
    assert first.created_at == date.today().isoformat()
    assert first.last_rotated == first.created_at

    second = broker.put("DEMO_KEY", "value-bbbbbbbbbbbb", tags=["two"], store=store, path=str(meta))
    assert second.created_at == first.created_at
    assert second.tags == ["two"]
    assert store.get("DEMO_KEY") == "value-bbbbbbbbbbbb"
    assert len(broker.list_entries(path=str(meta))) == 1


def test_put_refuses_an_empty_value(tmp_path):
    with pytest.raises(BrokerError):
        broker.put("DEMO_KEY", "", store=MemoryStore(), path=str(tmp_path / "entries.json"))


def test_list_filter_forget_and_metadata_for(tmp_path):
    meta = tmp_path / "entries.json"
    store = MemoryStore()
    broker.put(
        "OPENAI_PROD_READONLY",
        "value-abcdefghijklmnop",
        tags=["llm", "prod"],
        rotate_every_days=90,
        allowed_urls=["https://api.openai.com/"],
        store=store,
        path=str(meta),
    )
    broker.put("SMTP_163_AUTH_CODE", "value-qrstuvwxyz0123", tags=["mail"], store=store, path=str(meta))

    assert [r["name"] for r in broker.list_entries(path=str(meta))] == [
        "OPENAI_PROD_READONLY",
        "SMTP_163_AUTH_CODE",
    ]
    assert [r["name"] for r in broker.list_entries(tag="mail", path=str(meta))] == ["SMTP_163_AUTH_CODE"]

    rows = broker.list_entries(path=str(meta))
    blob = json.dumps(rows)
    assert "value-abcdefghijklmnop" not in blob
    assert "value" not in rows[0]

    assert broker.metadata_for("OPENAI_PROD_READONLY", path=str(meta))["rotate_due"] is False
    with pytest.raises(BrokerError):
        broker.metadata_for("NOPE", path=str(meta))

    assert broker.forget("SMTP_163_AUTH_CODE", store=store, path=str(meta)) is True
    assert store.get("SMTP_163_AUTH_CODE") is None
    assert broker.forget("SMTP_163_AUTH_CODE", store=store, path=str(meta)) is False
    assert [r["name"] for r in broker.list_entries(path=str(meta))] == ["OPENAI_PROD_READONLY"]


def test_metadata_file_is_private_and_leaves_no_temp_files(tmp_path):
    meta = tmp_path / "nested" / "entries.json"
    broker.put("A_B", "value-1234567890", store=MemoryStore(), path=str(meta))

    doc = json.loads(meta.read_text("utf-8"))
    assert doc["version"] == broker.SCHEMA_VERSION
    assert list(doc["entries"]) == ["A_B"]
    assert [p.name for p in meta.parent.iterdir()] == ["entries.json"]
    if os.name != "nt":
        assert (meta.stat().st_mode & 0o777) == 0o600


def test_missing_metadata_reads_as_empty(tmp_path):
    assert broker.load_meta(path=str(tmp_path / "nothing-here.json")) == {}


def test_metadata_with_a_foreign_schema_is_refused(tmp_path):
    meta = tmp_path / "entries.json"
    meta.write_text(json.dumps({"version": 99, "entries": {}}), "utf-8")
    with pytest.raises(BrokerError):
        broker.load_meta(path=str(meta))


# ---------------------------------------------------------------------------
# the allow-list: the AI may name a URL, not a host
# ---------------------------------------------------------------------------


def test_normalise_url_canonicalises_host_and_path():
    assert normalise_url("HTTPS://API.OpenAI.COM/v1/models?x=1") == "https://api.openai.com/v1/models?x=1"
    assert normalise_url("  http://127.0.0.1:8080  ") == "http://127.0.0.1:8080/"


@pytest.mark.parametrize("bad", ["ftp://example.com/", "file:///etc/passwd", "example.com", "javascript:alert(1)"])
def test_normalise_url_rejects_anything_but_http(bad):
    with pytest.raises(BrokerError):
        normalise_url(bad)


def test_allow_prefix_must_end_with_a_slash():
    # A bare host is fine: normalise_url gives it the root path "/".
    assert normalise_allow_prefix("https://api.openai.com") == "https://api.openai.com/"
    assert normalise_allow_prefix("https://api.openai.com/") == "https://api.openai.com/"
    # A path that does not end in "/" is refused, because a prefix entry means
    # "this path and below" and there would be no way to express the boundary.
    with pytest.raises(BrokerError):
        normalise_allow_prefix("https://api.openai.com/v1")


def test_prefix_match_defeats_lookalike_hosts():
    allowed = ["https://api.openai.com/"]
    assert check_allowed("https://api.openai.com/v1/models", allowed) == "https://api.openai.com/v1/models"
    with pytest.raises(BrokerError):
        check_allowed("https://api.openai.com.evil.com/v1/models", allowed)
    with pytest.raises(BrokerError):
        check_allowed("https://evil.example/?next=https://api.openai.com/", allowed)
    with pytest.raises(BrokerError):
        check_allowed("http://api.openai.com/v1/models", allowed)  # scheme downgrade


def test_allow_list_can_be_scoped_to_a_path():
    allowed = [normalise_allow_prefix("https://api.example.com/v1/")]
    assert check_allowed("https://api.example.com/v1/models", allowed)
    with pytest.raises(BrokerError):
        check_allowed("https://api.example.com/v2/models", allowed)


def test_an_empty_allow_list_refuses_everything():
    with pytest.raises(BrokerError) as excinfo:
        check_allowed("https://api.openai.com/v1/models", [])
    assert "no allowed_urls" in str(excinfo.value)


# ---------------------------------------------------------------------------
# scrubbing
# ---------------------------------------------------------------------------


def test_variants_cover_the_encodings_a_value_realistically_leaks_as():
    secret = "ab+cd/ef=gh"
    raw = secret.encode("utf-8")
    forms = broker._variants(secret)
    assert secret in forms
    assert base64.b64encode(raw).decode("ascii") in forms
    assert base64.urlsafe_b64encode(raw).decode("ascii") in forms
    assert urllib.parse.quote(secret, safe="") in forms
    assert raw.hex() in forms
    lengths = [len(f) for f in forms]
    assert lengths == sorted(lengths, reverse=True), "longest forms must be replaced first"


def test_scrub_removes_the_value_in_every_variant():
    secret = "sk-abc+def/ghi="
    b64 = base64.b64encode(secret.encode("utf-8")).decode("ascii")
    text = f"raw={secret} b64={b64} hex={secret.encode('utf-8').hex()}"

    cleaned = scrub(text, [secret])

    assert secret not in cleaned
    assert b64 not in cleaned
    assert secret.encode("utf-8").hex() not in cleaned
    assert REDACTED in cleaned


def test_scrub_redacts_short_values_raw_but_not_their_encodings():
    # The raw value is always a needle, however short it is.
    assert scrub("the cat sat on the mat", ["cat"]) == "the [redacted] sat on the mat"
    # Encoded variants are only expanded for 8+ char values, so a short value
    # cannot start redacting innocuous base64/hex text elsewhere in a response.
    assert scrub("a Y2F0 b", ["cat"]) == "a Y2F0 b"


def test_scrub_edge_cases():
    assert scrub("hello", []) == "hello"
    assert scrub("", ["whatever"]) == ""
    assert scrub("hello", [""]) == "hello"


# ---------------------------------------------------------------------------
# use(): the credential leaves the machine only where the allow-list says
# ---------------------------------------------------------------------------


def test_use_sends_the_credential_and_scrubs_the_reply(tmp_path, http_server):
    base, recorder = http_server
    secret = "sk-echo-me-1234567890"
    recorder.routes["/v1/models"] = (200, json.dumps({"data": [{"id": secret}], "ok": True}).encode(), {})

    meta, store = _seed(tmp_path, "OPENAI_PROD", secret, allowed_urls=[base + "v1/"])

    result = broker.use("OPENAI_PROD", base + "v1/models", store=store, path=str(meta))

    assert result["status"] == 200
    assert result["url"] == base + "v1/models"
    assert result["truncated"] is False
    assert secret not in result["body"]
    assert REDACTED in result["body"]

    sent = recorder.seen[-1]
    assert sent["headers"]["authorization"] == "Bearer " + secret

    audit = (tmp_path / "audit.log").read_text("utf-8")
    assert "OPENAI_PROD" in audit
    assert "\tGET\t" in audit
    assert "\t200\n" in audit
    assert secret not in audit


def test_use_posts_json_with_a_custom_auth_scheme(tmp_path, http_server):
    base, recorder = http_server
    meta, store = _seed(
        tmp_path,
        "SLACK_BOT",
        "xoxb-secret-value",
        allowed_urls=[base + "api/"],
        auth_prefix="",
    )

    result = broker.use(
        "SLACK_BOT",
        base + "api/chat.postMessage",
        method="post",
        body={"text": "hi"},
        store=store,
        path=str(meta),
    )

    assert result["status"] == 200
    sent = recorder.seen[-1]
    assert sent["method"] == "POST"
    assert sent["headers"]["authorization"] == "xoxb-secret-value"
    assert sent["headers"]["content-type"] == "application/json"
    assert json.loads(sent["body"]) == {"text": "hi"}


def test_use_returns_an_error_status_instead_of_raising(tmp_path, http_server):
    base, recorder = http_server
    recorder.routes["/v1/bad"] = (401, b'{"error":"invalid api key"}', {})

    meta, store = _seed(tmp_path, "OPENAI_PROD", "sk-nope-value-123", allowed_urls=[base + "v1/"])

    result = broker.use("OPENAI_PROD", base + "v1/bad", store=store, path=str(meta))

    assert result["status"] == 401
    assert "invalid api key" in result["body"]


def test_use_refuses_a_host_outside_the_allow_list(tmp_path, http_server):
    base, _ = http_server
    meta, store = _seed(tmp_path, "STRIPE_LIVE", "sk_live_value_123", allowed_urls=["https://api.stripe.com/"])

    with pytest.raises(BrokerError) as excinfo:
        broker.use("STRIPE_LIVE", base + "v1/charges", store=store, path=str(meta))
    assert "allowed_urls" in str(excinfo.value)


def test_use_refuses_when_the_allow_list_is_empty(tmp_path, http_server):
    base, _ = http_server
    meta, store = _seed(tmp_path, "LOOSE_KEY", "value-abcdefghijkl")

    with pytest.raises(BrokerError) as excinfo:
        broker.use("LOOSE_KEY", base + "anything", store=store, path=str(meta))
    assert "no allowed_urls" in str(excinfo.value)


def test_use_refuses_to_follow_a_redirect(tmp_path, http_server):
    base, recorder = http_server
    recorder.routes["/v1/start"] = (302, b"", {"Location": "https://evil.example.com/steal"})

    meta, store = _seed(tmp_path, "OPENAI_PROD", "sk-redirect-me-123", allowed_urls=[base + "v1/"])

    with pytest.raises(BrokerError) as excinfo:
        broker.use("OPENAI_PROD", base + "v1/start", store=store, path=str(meta))
    assert "redirect" in str(excinfo.value).lower()


def test_use_requires_a_stored_value_and_a_known_entry(tmp_path):
    meta = tmp_path / "entries.json"
    store = MemoryStore()
    broker.put("KNOWN_KEY", "value-abcdefghijkl", allowed_urls=["https://api.example.com/"], store=store, path=str(meta))

    assert store.delete("KNOWN_KEY") is True
    with pytest.raises(BrokerError) as excinfo:
        broker.use("KNOWN_KEY", "https://api.example.com/v1", store=store, path=str(meta))
    assert "no value is stored" in str(excinfo.value)

    with pytest.raises(BrokerError):
        broker.use("MISSING_KEY", "https://api.example.com/v1", store=store, path=str(meta))


def test_use_truncates_a_huge_reply(tmp_path, http_server):
    base, recorder = http_server
    recorder.routes["/v1/big"] = (200, b"x" * (broker.MAX_OUTPUT_CHARS * 3), {})

    meta, store = _seed(tmp_path, "OPENAI_PROD", "sk-big-reply-123", allowed_urls=[base + "v1/"])

    result = broker.use("OPENAI_PROD", base + "v1/big", store=store, path=str(meta))

    assert result["truncated"] is True
    assert len(result["body"]) == broker.MAX_OUTPUT_CHARS


# ---------------------------------------------------------------------------
# generated values
# ---------------------------------------------------------------------------


def test_generate_value_is_url_safe_entropy():
    alphabet = set(string.ascii_letters + string.digits + "-_")
    values = {generate_value(43) for _ in range(20)}
    assert len(values) == 20
    for value in values:
        assert len(value) == 43
        assert set(value) <= alphabet
    assert len(generate_value(8)) == 16, "16 characters is the floor"


# ---------------------------------------------------------------------------
# the MCP surface
# ---------------------------------------------------------------------------


def test_mcp_exposes_exactly_the_six_agreed_tools():
    assert [tool["name"] for tool in mcp_server._tools_schema()] == TOOL_NAMES


def test_mcp_has_no_read_tool():
    names = [tool["name"] for tool in mcp_server._tools_schema()]
    assert "secret_read" not in names
    assert not [name for name in names if "read" in name or name.endswith("_get")]


def test_mcp_tool_schemas_are_well_formed():
    for tool in mcp_server._tools_schema():
        assert tool["name"] and tool["description"]
        assert tool["inputSchema"]["type"] == "object"


# ---------------------------------------------------------------------------
# the real Keychain (opt-in: writes a scratch service, cleans up after itself)
# ---------------------------------------------------------------------------


needs_keychain = pytest.mark.skipif(
    not keychain.AVAILABLE or os.environ.get("KEYSTASH_TEST_KEYCHAIN") != "1",
    reason="set KEYSTASH_TEST_KEYCHAIN=1 on macOS to exercise the real Keychain",
)


@needs_keychain
def test_keychain_roundtrip_uses_a_scratch_service():
    service = f"keystash-pytest-{os.getpid()}"
    account = "ROUNDTRIP_TEST"
    assert keychain.store(service, account, "value-abcdefghijkl") is None
    try:
        assert keychain.retrieve(service, account, gate=False) == "value-abcdefghijkl"
    finally:
        keychain.delete(service, account)
    assert keychain.retrieve(service, account, gate=False) is None


# ---------------------------------------------------------------------------
# the CLI
# ---------------------------------------------------------------------------


def test_cli_reports_version_0_4_0(tmp_path):
    result = _cli("--version", meta=tmp_path / "entries.json")
    assert result.returncode == 0
    assert "0.4.2" in result.stdout


def test_cli_help_lists_no_way_to_read_a_value(tmp_path):
    result = _cli("--help", meta=tmp_path / "entries.json")
    assert result.returncode == 0
    for expected in ("list", "show", "add", "rotate", "generate", "edit", "copy", "use", "rm", "migrate", "doctor", "mcp"):
        assert expected in result.stdout
    assert " secret_read" not in result.stdout


def test_cli_list_on_empty_metadata_is_empty_json(tmp_path):
    result = _cli("list", "--json", meta=tmp_path / "entries.json")
    assert result.returncode == 0
    assert "[]" in result.stdout


def test_cli_show_of_an_unknown_entry_fails_loudly(tmp_path):
    result = _cli("show", "NOPE", meta=tmp_path / "entries.json")
    assert result.returncode == 1
    assert "unknown entry" in (result.stdout + result.stderr)


def test_cli_list_and_show_never_touch_a_value(tmp_path):
    meta, _store = _seed(
        tmp_path,
        "DEMO_KEY",
        "value-abcdefghijkl",
        tags=["demo"],
        allowed_urls=["https://api.example.com/"],
    )

    listed = _cli("list", "--json", "--tag", "demo", meta=meta)
    assert listed.returncode == 0
    assert "DEMO_KEY" in listed.stdout
    assert "value-abcdefghijkl" not in listed.stdout

    shown = _cli("show", "DEMO_KEY", meta=meta)
    assert shown.returncode == 0
    assert "DEMO_KEY" in shown.stdout
    assert "value-abcdefghijkl" not in shown.stdout


def test_cli_doctor_runs(tmp_path):
    result = _cli("doctor", meta=tmp_path / "entries.json")
    assert result.returncode in (0, 1)
    assert "platform" in result.stdout


def test_cli_mcp_stdio_speaks_the_protocol(tmp_path):
    stdin = (
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "pytest", "version": "1"},
                        },
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            ]
        )
        + "\n"
    )

    result = _cli("mcp", meta=tmp_path / "entries.json", stdin=stdin)

    assert result.returncode == 0, result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    handshake = [message for message in replies if message.get("id") == 1][-1]
    assert handshake["result"]["serverInfo"]["name"] == "keystash"
    listing = [message for message in replies if message.get("id") == 2][-1]
    assert [tool["name"] for tool in listing["result"]["tools"]] == TOOL_NAMES


def test_cli_mcp_rejects_an_unknown_tool(tmp_path):
    stdin = (
        "\n".join(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "pytest", "version": "1"},
                        },
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "secret_read", "arguments": {"name": "DEMO_KEY"}},
                    }
                ),
            ]
        )
        + "\n"
    )

    result = _cli("mcp", meta=tmp_path / "entries.json", stdin=stdin)

    assert result.returncode == 0, result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    answer = [message for message in replies if message.get("id") == 2][-1]
    assert "error" in answer or answer.get("result", {}).get("isError") is True


def test_legacy_password_prefers_the_environment(monkeypatch):
    from keystash import cli

    monkeypatch.setenv("KEYSTASH_MASTER_PASSWORD", "from-env")
    monkeypatch.setattr(cli.keychain, "retrieve", lambda *a, **k: "from-keychain")
    assert cli._legacy_password(Path("/nonexistent/vault.json")) == "from-env"


def _stub_keychain(seen, value):
    class _Stub:
        AVAILABLE = True
        KeychainError = keychain.KeychainError

        @staticmethod
        def retrieve(service, account, gate=True):
            seen.append((service, account))
            return value

    return _Stub


def test_legacy_password_falls_back_to_the_login_keychain(monkeypatch, tmp_path):
    from keystash import cli

    monkeypatch.delenv("KEYSTASH_MASTER_PASSWORD", raising=False)
    seen = []
    vault_path = tmp_path / "v.json"
    monkeypatch.setattr(cli, "keychain", _stub_keychain(seen, "from-keychain"))
    assert cli._legacy_password(vault_path) == "from-keychain"
    assert seen == [("keystash", str(vault_path))]


def test_legacy_password_tries_the_unrenamed_path_after_retiring(monkeypatch, tmp_path):
    from keystash import cli

    monkeypatch.delenv("KEYSTASH_MASTER_PASSWORD", raising=False)
    seen = []
    vault_path = tmp_path / "v.json.migrated"
    monkeypatch.setattr(cli, "keychain", _stub_keychain(seen, None))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "typed")
    assert cli._legacy_password(vault_path) == "typed"
    assert [a for _, a in seen] == [str(vault_path), str(vault_path.with_name("v.json"))]


def test_legacy_password_survives_a_keychain_that_refuses(monkeypatch, tmp_path):
    from keystash import cli

    monkeypatch.delenv("KEYSTASH_MASTER_PASSWORD", raising=False)
    attempts = []
    vault_path = tmp_path / "v.json"

    class _Angry:
        AVAILABLE = True
        KeychainError = keychain.KeychainError

        @staticmethod
        def retrieve(service, account, gate=True):
            attempts.append(account)
            raise keychain.KeychainError(-128, "authentication declined")

    monkeypatch.setattr(cli, "keychain", _Angry)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "typed")
    assert cli._legacy_password(vault_path) == "typed"
    assert attempts == [str(vault_path)]


def test_legacy_password_skips_the_keychain_off_macos(monkeypatch, tmp_path):
    from keystash import cli

    monkeypatch.delenv("KEYSTASH_MASTER_PASSWORD", raising=False)

    class _Elsewhere:
        AVAILABLE = False
        KeychainError = keychain.KeychainError

        @staticmethod
        def retrieve(service, account, gate=True):  # pragma: no cover - must not run
            raise AssertionError("keychain touched on a platform without one")

    monkeypatch.setattr(cli, "keychain", _Elsewhere)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "typed")
    assert cli._legacy_password(tmp_path / "v.json") == "typed"
