import json
import sys

import pytest
from typer.testing import CliRunner

from keystash.cli import app
from keystash.gen import generate
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
