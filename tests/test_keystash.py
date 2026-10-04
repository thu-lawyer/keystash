import json
import sys

import pytest
from typer.testing import CliRunner

from keystash import keychain, scanner
from keystash.cli import app
from keystash.gen import generate
from keystash.mcp_server import KeystashMCPServer
from keystash.model import Entry, parse_expires
from keystash.search import score_entry, search
from keystash.vault import Vault, VaultError

runner = CliRunner()

MASTER = "test-master-pw"


@pytest.fixture()
def vault_env(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTASH_VAULT", str(tmp_path / "vault.json"))
    monkeypatch.setenv("KEYSTASH_PASSWORD", MASTER)
    return tmp_path / "vault.json"


def _init():
    return runner.invoke(app, ["init"], input=f"{MASTER}\n{MASTER}\n")


def _add(name, secret="s3cret", *extra):
    return runner.invoke(app, ["add", name, "-s", secret, *extra])


class TestVaultCore:
    def test_create_load_save_roundtrip(self, tmp_path):
        path = tmp_path / "v.json"
        v = Vault(path)
        v.create(MASTER)
        assert path.exists()
        v.load(MASTER)
        v.add(Entry(name="a", secret="topsecret"), overwrite=True)
        v.save(MASTER)
        v2 = Vault(path)
        v2.load(MASTER)
        assert v2.get("a").secret == "topsecret"

    def test_wrong_password(self, tmp_path):
        path = tmp_path / "v.json"
        Vault(path).create(MASTER)
        with pytest.raises(VaultError) as e:
            Vault(path).load("nope")
        assert e.value.code == "bad_password"

    def test_create_twice_rejected(self, tmp_path):
        path = tmp_path / "v.json"
        Vault(path).create(MASTER)
        with pytest.raises(VaultError) as e:
            Vault(path).create(MASTER)
        assert e.value.code == "vault_exists"

    def test_file_is_not_plaintext(self, tmp_path):
        path = tmp_path / "v.json"
        v = Vault(path)
        v.create(MASTER)
        v.load(MASTER)
        v.add(Entry(name="github", secret="ghp_verysecret"), overwrite=True)
        v.save(MASTER)
        raw = path.read_text()
        assert "ghp_verysecret" not in raw
        assert "github" not in raw


class TestModel:
    def test_expiry_parsing(self):
        assert parse_expires("2026-01-31").isoformat() == "2026-01-31"
        assert parse_expires("") is None
        assert parse_expires(None) is None
        with pytest.raises(ValueError):
            parse_expires("31-01-2026")

    def test_expired_flags(self):
        e = Entry(name="x", secret="s", expires_at=parse_expires("2000-01-01"))
        assert e.is_expired()
        assert (e.days_left() or 0) < 0
        alive = Entry(name="y", secret="s")
        assert not alive.is_expired()

    def test_default_env_var(self):
        assert Entry(name="openai-prod", secret="s").default_env_var == "OPENAI_PROD"
        assert Entry(name="x", secret="s", env_var="MY_KEY").default_env_var == "MY_KEY"

    def test_edit_updates_timestamp(self):
        e = Entry(name="x", secret="old")
        e2 = e.with_updates(secret="new")
        assert e2.secret == "new"
        assert e2.updated_at >= e.updated_at


class TestSearch:
    def _entries(self):
        return {
            e.name: e
            for e in [
                Entry(name="openai-prod", secret="s", tags=["llm"]),
                Entry(name="anthropic-key", secret="s", tags=["llm", "ai"]),
                Entry(name="db-password", secret="s", notes="postgres primary"),
                Entry(name="smtp", secret="s"),
            ]
        }

    def test_exact_beats_substring(self):
        ranked = search(self._entries(), "openai-prod")
        assert ranked[0].name == "openai-prod"

    def test_substring_match(self):
        names = [e.name for e in search(self._entries(), "key")]
        assert "anthropic-key" in names and "openai-prod" not in names

    def test_matches_notes_and_tags(self):
        assert search(self._entries(), "postgres")[0].name == "db-password"
        assert search(self._entries(), "llm")[0].name in ("openai-prod", "anthropic-key")

    def test_subsequence_and_no_match(self):
        assert score_entry("oaip", self._entries()["openai-prod"]) == 60
        assert score_entry("zzzz", self._entries()["smtp"]) is None
        assert search(self._entries(), "") and {e.name for e in search(self._entries(), "")} == set(self._entries())


class TestGen:
    def test_length_and_uniqueness(self):
        assert len(generate(16)) == 16
        assert len(generate(40)) == 40
        assert generate(24) != generate(24)

    def test_symbols_toggle(self):
        assert all(c.isalnum() for c in generate(64, symbols=False))
        assert any(not c.isalnum() for c in generate(64, symbols=True))

    def test_no_ambiguous_chars(self):
        banned = set("Il1O0o|`'\";:,.")
        for _ in range(20):
            assert not (set(generate(32)) & banned)

    def test_minimum_length(self):
        with pytest.raises(ValueError):
            generate(4)


class TestCli:
    def test_init_add_get_flow(self, vault_env):
        result = _init()
        assert result.exit_code == 0, result.output
        result = _add("openai", "sk-abc123")
        assert result.exit_code == 0, result.output
        result = runner.invoke(app, ["get", "openai", "--quiet"])
        assert result.exit_code == 0
        assert result.output.strip() == "sk-abc123"

    def test_get_masks_by_default(self, vault_env):
        _init()
        _add("longsecret", "abcdefgh12345678")
        result = runner.invoke(app, ["get", "longsecret"])
        assert result.exit_code == 0
        assert "abcdefgh12345678" not in result.output
        assert "abcd" in result.output  # masked head

    def test_duplicate_add_rejected_force_overwrites(self, vault_env):
        _init()
        assert _add("x", "one").exit_code == 0
        result = _add("x", "two")
        assert result.exit_code == 1 and "already exists" in result.output
        assert _add("x", "two", "--force").exit_code == 0
        out = runner.invoke(app, ["get", "x", "--quiet"]).output.strip()
        assert out == "two"

    def test_missing_entry_exit_code(self, vault_env):
        _init()
        result = runner.invoke(app, ["get", "ghost"])
        assert result.exit_code == 3 and "No entry" in result.output

    def test_ls_and_fuzzy(self, vault_env):
        _init()
        _add("openai-prod", "s1", "-t", "llm,prod")
        _add("db-password", "s2")
        result = runner.invoke(app, ["ls", "oprod"])
        assert result.exit_code == 0 and "openai-prod" in result.output
        result = runner.invoke(app, ["ls", "--tag", "llm"])
        assert "openai-prod" in result.output and "db-password" not in result.output
        result = runner.invoke(app, ["ls", "--json"])
        data = json.loads(result.output)
        assert {d["name"] for d in data} == {"openai-prod", "db-password"}

    def test_rm(self, vault_env):
        _init()
        _add("tmp", "s")
        result = runner.invoke(app, ["rm", "tmp", "-f"])
        assert result.exit_code == 0
        assert runner.invoke(app, ["get", "tmp"]).exit_code == 3

    def test_edit_changes_field_only(self, vault_env):
        _init()
        _add("svc", "keepme", "-u", "old-user")
        result = runner.invoke(app, ["edit", "svc", "-u", "new-user"])
        assert result.exit_code == 0
        assert runner.invoke(app, ["get", "svc", "--quiet"]).output.strip() == "keepme"

    def test_gen_saves_entry(self, vault_env):
        _init()
        result = runner.invoke(app, ["gen", "20", "--save", "rand", "--no-symbols"])
        assert result.exit_code == 0, result.output
        saved = runner.invoke(app, ["get", "rand", "--quiet"]).output.strip()
        assert len(saved) == 20 and saved.isalnum()

    def test_env_exports(self, vault_env):
        _init()
        _add("openai", "sk-1", "-e", "OPENAI_API_KEY")
        result = runner.invoke(app, ["env", "openai"])
        assert result.exit_code == 0
        assert "export OPENAI_API_KEY='sk-1'" in result.output

    def test_env_with_tag(self, vault_env):
        _init()
        _add("a", "va", "-t", "llm", "-e", "A_KEY")
        _add("b", "vb", "-t", "llm", "-e", "B_KEY")
        result = runner.invoke(app, ["env", "--tag", "llm"])
        assert "export A_KEY='va'" in result.output
        assert "export B_KEY='vb'" in result.output

    def test_run_injects_env(self, vault_env, tmp_path):
        _init()
        _add("prov", "injected-value", "-e", "PROV_KEY")
        out = tmp_path / "out.txt"
        result = runner.invoke(
            app,
            [
                "run",
                "-n",
                "prov",
                "--",
                sys.executable,
                "-c",
                f"import os; open({str(out)!r}, 'w').write(os.environ['PROV_KEY'])",
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.read_text() == "injected-value"

    def test_run_with_tag_injects_env(self, vault_env, tmp_path):
        _init()
        _add("a", "va", "-t", "llm", "-e", "A_KEY")
        out = tmp_path / "out.txt"
        result = runner.invoke(
            app,
            [
                "run",
                "--tag",
                "llm",
                "--",
                sys.executable,
                "-c",
                f"import os; open({str(out)!r}, 'w').write(os.environ['A_KEY'])",
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.read_text() == "va"

    def test_run_requires_selection(self, vault_env):
        _init()
        result = runner.invoke(app, ["run", "--", sys.executable, "-c", "print(1)"])
        assert result.exit_code != 0 and "Specify entry names" in result.output

    def test_import_dotenv_and_export(self, vault_env, tmp_path):
        _init()
        envfile = tmp_path / "secrets.env"
        envfile.write_text(
            "# comment\nFOO=bar\nQUOTED='hello world'\n\nBAD\n", encoding="utf-8"
        )
        result = runner.invoke(app, ["import", str(envfile)])
        assert result.exit_code == 0, result.output
        assert runner.invoke(app, ["get", "FOO", "--quiet"]).output.strip() == "bar"
        assert (
            runner.invoke(app, ["get", "QUOTED", "--quiet"]).output.strip()
            == "hello world"
        )
        result = runner.invoke(app, ["export", "--with-secrets"])
        data = json.loads(result.output)
        assert data["FOO"]["secret"] == "bar"

    def test_import_json(self, vault_env, tmp_path):
        _init()
        jf = tmp_path / "k.json"
        jf.write_text(json.dumps({"svc": "v1"}), encoding="utf-8")
        result = runner.invoke(app, ["import", str(jf)])
        assert result.exit_code == 0
        assert runner.invoke(app, ["get", "svc", "--quiet"]).output.strip() == "v1"

    def test_export_dotenv_masks_without_secrets(self, vault_env):
        _init()
        _add("one", "real", "-e", "ONE")
        result = runner.invoke(app, ["export", "--format", "dotenv"])
        assert "ONE=" in result.output and "real" not in result.output

    def test_expiry_warning_on_get(self, vault_env):
        _init()
        _add("old", "s", "--expires", "2000-01-01")
        result = runner.invoke(app, ["get", "old"])
        assert "expired" in result.output

    def test_status(self, vault_env):
        _init()
        _add("fine", "s")
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0 and "1" in result.output

    def test_init_requires_vault(self, vault_env):
        result = runner.invoke(app, ["ls"])
        assert result.exit_code != 0 and "init" in result.output

    def test_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0 and "keystash" in result.output


class TestKeychainFlow:
    def test_unlock_stores_and_get_uses_keychain(self, vault_env, monkeypatch):
        monkeypatch.setenv("KEYSTASH_PASSWORD", MASTER)
        assert _init().exit_code == 0
        assert _add("kc-entry", "kc-secret").exit_code == 0
        stored = {}

        def fake_store(service, account, secret):
            stored[(service, account)] = secret
            return "keychain"

        monkeypatch.setattr(keychain, "store", fake_store)
        monkeypatch.setattr(keychain, "AVAILABLE", True)
        assert runner.invoke(app, ["unlock"]).exit_code == 0
        assert stored[("keystash", str(vault_env))] == MASTER

        # No KEYSTASH_PASSWORD anymore: the keychain must answer.
        monkeypatch.delenv("KEYSTASH_PASSWORD")
        monkeypatch.setattr(keychain, "retrieve", lambda s, a: stored.get((s, a)))
        result = runner.invoke(app, ["get", "kc-entry", "--quiet"])
        assert result.exit_code == 0, result.output
        assert result.output.strip() == "kc-secret"

    def test_keychain_error_falls_back_to_prompt(self, vault_env, monkeypatch):
        _init()
        monkeypatch.setenv("KEYSTASH_PASSWORD", MASTER)
        _add("fb", "fb-secret")
        monkeypatch.delenv("KEYSTASH_PASSWORD")
        monkeypatch.setattr(keychain, "AVAILABLE", True)

        def boom(s, a):
            raise keychain.KeychainError(-128, "authentication declined")

        monkeypatch.setattr(keychain, "retrieve", boom)
        monkeypatch.setattr("keystash.cli.getpass.getpass", lambda *_: MASTER)
        result = runner.invoke(app, ["get", "fb", "--quiet"])
        assert result.exit_code == 0, result.output
        assert result.output.strip() == "fb-secret"

    def test_no_keychain_flag_skips_lookup(self, vault_env, monkeypatch):
        _init()
        monkeypatch.setenv("KEYSTASH_PASSWORD", MASTER)
        _add("nk", "nk-secret")
        monkeypatch.delenv("KEYSTASH_PASSWORD")
        monkeypatch.setattr(keychain, "AVAILABLE", True)
        monkeypatch.setattr("keystash.cli.getpass.getpass", lambda *_: MASTER)
        result = runner.invoke(app, ["--no-keychain", "get", "nk", "--quiet"])
        assert result.exit_code == 0 and result.output.strip() == "nk-secret"

    def test_lock_removes_stored_credential(self, vault_env, monkeypatch):
        removed = {}
        monkeypatch.setattr(keychain, "AVAILABLE", True)
        monkeypatch.setattr(keychain, "delete", lambda s, a: removed.setdefault((s, a), True))
        result = runner.invoke(app, ["lock"])
        assert result.exit_code == 0
        assert ("keystash", str(vault_env)) in removed

    @pytest.mark.skipif(not keychain.AVAILABLE, reason="macOS only")
    def test_real_keychain_roundtrip_plain_items(self, monkeypatch):
        # Background sessions (CI, agent shells) cannot present the Touch ID
        # UI — bypass the gate to test the keychain layer itself.
        monkeypatch.setattr(keychain, "biometric_gate", lambda *a, **kw: True)
        svc, acct = "keystash-selftest", "pytest"
        keychain.delete(svc, acct)
        keychain.store(svc, acct, "roundtrip-value")
        assert keychain.retrieve(svc, acct) == "roundtrip-value"
        assert keychain.delete(svc, acct) is True
        assert keychain.retrieve(svc, acct) is None


class TestScanner:
    def test_high_confidence_rules(self):
        text = "\n".join([
            "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD",
            "aws = AKIAIOSFODNN7EXAMPLE",
            "key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD",
            "# google AIzaSyD-9tJqX0123456789abcdefghijklmnopqrstuvw",
        ])
        rules = {f.rule for f in scanner.scan_text(text, "t")}
        assert {"github", "aws-access-key", "openai", "google-api"} <= rules

    def test_generic_assignment_and_placeholders(self):
        text = 'API_KEY="abcdefghijklmnopqrstuvwxyz123456"\nOTHER=<your-key-here>\n'
        findings = scanner.scan_text(text, "t")
        generic = [f for f in findings if f.rule == "generic-assignment"]
        assert len(generic) == 1 and generic[0].suspect
        assert generic[0].line == 1

    def test_low_entropy_generic_filtered(self):
        text = "password=helloworld123\nAPI_KEY=aaaaaaaaaaaaaaaaaaaa"
        assert scanner.scan_text(text, "t") == []

    def test_line_numbers_and_dedupe(self):
        text = "x=1\ntok='ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD'\n"
        findings = scanner.scan_text(text, "t")
        assert all(f.line == 2 for f in findings)
        assert len([f for f in findings if f.secret.startswith("ghp_")]) == 1

    def test_scan_paths_skips_excluded_and_binary(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "x.env").write_text("A=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD")
        (tmp_path / "bin.env").write_bytes(b"A=ghp_\x00\x00\x00break")
        (tmp_path / "real.env").write_text("B=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD")
        findings = scanner.scan_paths([tmp_path])
        files = {f.file for f in findings}
        assert any(f.endswith("real.env") for f in files)
        assert not any("node_modules" in f or f.endswith("bin.env") for f in files)

    def test_shred_replaces_values_only(self, tmp_path):
        target = tmp_path / ".env"
        target.write_text("TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD # keep comment\n")
        findings = scanner.scan_paths([target])
        assert len(findings) == 1
        assert scanner.shred(findings) == 1
        content = target.read_text()
        assert "ghp_" not in content and "[redacted→keystash:" in content
        assert "# keep comment" in content

    def test_shred_needs_nothing_when_no_change(self, tmp_path):
        empty = tmp_path / "empty.txt"
        empty.write_text("nothing here")
        assert scanner.shred([]) == 0


class TestDoctorCli:
    def _seed_project(self, tmp_path):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"
        proj = tmp_path / "proj"
        proj.mkdir(exist_ok=True)
        (proj / ".env").write_text(f"GITHUB_TOKEN={secret}\n")
        return proj, secret

    def test_report_without_vault(self, tmp_path, monkeypatch):
        proj, _ = self._seed_project(tmp_path)
        monkeypatch.setenv("KEYSTASH_VAULT", str(tmp_path / "vault.json"))
        monkeypatch.delenv("KEYSTASH_PASSWORD", raising=False)
        result = runner.invoke(app, ["doctor", str(proj), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert any(d["rule"] == "github" for d in data)

    def test_import_all_and_shred(self, tmp_path, monkeypatch):
        proj, secret = self._seed_project(tmp_path)
        monkeypatch.setenv("KEYSTASH_VAULT", str(tmp_path / "vault.json"))
        monkeypatch.setenv("KEYSTASH_PASSWORD", MASTER)
        assert _init().exit_code == 0
        result = runner.invoke(app, ["doctor", str(proj), "--import-all", "--shred", "--yes"])
        assert result.exit_code == 0, result.output
        # entry exists
        out = runner.invoke(app, ["ls", "--json"]).output
        names = {d["name"] for d in json.loads(out)}
        assert any("github" in n for n in names)
        # file redacted
        assert secret not in (proj / ".env").read_text()
        # second pass: nothing new
        result = runner.invoke(app, ["doctor", str(proj), "--json"])
        data = json.loads(result.output)
        assert all(d["stored"] for d in data)


class TestMCPServer:
    SECRET = "mcp-super-secret-value"

    @pytest.fixture()
    def server(self, vault_env):
        server = KeystashMCPServer(vault_env)
        vault = Vault(vault_env)
        vault.create(MASTER)
        vault.load(MASTER)
        vault.add(Entry(name="mcpentry", secret=self.SECRET, env_var="MCPT_KEY", tags=["t1"]), overwrite=True)
        vault.save(MASTER)
        return server

    def _rpc(self, server, method, params=None, request_id=1):
        msg = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            msg["params"] = params
        return server.handle(msg)

    def _call(self, server, tool, args):
        result = self._rpc(server, "tools/call", {"name": tool, "arguments": args})
        text = result["result"]["content"][0]["text"]
        return text, result["result"].get("isError", False)

    def test_initialize(self, server):
        result = self._rpc(server, "initialize", {"protocolVersion": "2024-11-05"})
        assert result["result"]["protocolVersion"] == "2024-11-05"
        assert "tools" in result["result"]["capabilities"]
        assert result["result"]["serverInfo"]["name"] == "keystash"

    def test_unknown_method(self, server):
        result = self._rpc(server, "resources/list", {})
        assert result["error"]["code"] == -32601

    def test_notification_returns_none(self, server):
        assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def test_tools_list_zero_read_tools(self, server):
        result = self._rpc(server, "tools/list", {})
        tools = {t["name"] for t in result["result"]["tools"]}
        assert {"list_entries", "run_command", "copy_secret", "generate_and_store",
                "add_secret", "update_entry", "delete_entry", "status"} == tools
        for t in result["result"]["tools"]:
            assert "inputSchema" in t

    def test_list_entries_never_contains_secret(self, server):
        text, err = self._call(server, "list_entries", {})
        assert not err
        data = json.loads(text)
        assert any(e["name"] == "mcpentry" for e in data)
        assert self.SECRET not in text

    def test_run_command_scrubs_output(self, server, tmp_path):
        out = tmp_path / "out.txt"
        text, err = self._call(server, "run_command", {
            "names": ["mcpentry"],
            "command": [sys.executable, "-c",
                        f"import os; open({str(out)!r}, 'w').write(os.environ['MCPT_KEY']); print(os.environ['MCPT_KEY'])"],
        })
        assert not err
        assert out.read_text() == self.SECRET          # subprocess got the real value
        assert self.SECRET not in text                  # agent sees it scrubbed
        assert "[redacted]" in text

    def test_run_command_blocks_dumpers(self, server):
        for cmd in (["printenv"], ["env"], ["sh", "-c", "printenv MCPT_KEY"]):
            text, err = self._call(server, "run_command", {"names": ["mcpentry"], "command": cmd})
            assert err, cmd
            assert "Refused" in text

    def test_run_command_missing_entry(self, server):
        text, err = self._call(server, "run_command", {
            "names": ["ghost"], "command": [sys.executable, "-c", "print(1)"]})
        assert err and "No such entries" in text

    def test_generate_and_store_value_never_revealed(self, server):
        text, err = self._call(server, "generate_and_store",
                               {"name": "gen1", "length": 32, "tags": ["mcp"]})
        assert not err
        assert "gen1" in text
        vault = Vault(server.vault_path)
        vault.load(MASTER)
        entry = vault.get("gen1")
        assert len(entry.secret) == 32
        assert entry.secret not in text

    def test_add_secret_stores(self, server):
        text, err = self._call(server, "add_secret", {"name": "pasted", "secret": "v"})
        assert not err
        vault = Vault(server.vault_path)
        vault.load(MASTER)
        assert vault.get("pasted").secret == "v"

    def test_delete_requires_confirm(self, server):
        text, err = self._call(server, "delete_entry", {"name": "mcpentry"})
        assert err and "confirm" in text
        text, err = self._call(server, "delete_entry", {"name": "mcpentry", "confirm": True})
        assert not err
        vault = Vault(server.vault_path)
        vault.load(MASTER)
        assert "mcpentry" not in vault.entries

    def test_update_entry_metadata_only(self, server):
        text, err = self._call(server, "update_entry",
                               {"name": "mcpentry", "tags": ["rotated"], "expires": "2027-01-01"})
        assert not err
        vault = Vault(server.vault_path)
        vault.load(MASTER)
        e = vault.get("mcpentry")
        assert e.tags == ["rotated"] and e.expires_at is not None
        assert e.secret == self.SECRET                  # secret untouched

    def test_copy_secret_never_echoes_value(self, server, monkeypatch):
        monkeypatch.setattr("keystash.mcp_server.clipboard.copy", lambda s: True)
        text, err = self._call(server, "copy_secret", {"name": "mcpentry"})
        assert not err and "clipboard" in text
        assert self.SECRET not in text

    def test_status_tool(self, server):
        text, err = self._call(server, "status", {})
        assert not err
        data = json.loads(text)
        assert data["entries"] >= 1

    def test_locked_server_reports_hint(self, vault_env, monkeypatch):
        monkeypatch.delenv("KEYSTASH_PASSWORD")
        monkeypatch.setattr(keychain, "AVAILABLE", False)
        server = KeystashMCPServer(vault_env)
        assert server.password is None
        text, err = self._call(server, "list_entries", {})
        assert err and "keystash unlock" in text
