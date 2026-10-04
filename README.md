# keystash 🔑

**Local-first encrypted vault for API keys, tokens and passwords — one file, fuzzy search, env injection, expiry tracking.**

Your LLM API keys, cloud tokens and passwords are scattered across `.env` files, shell
histories and notes apps. `keystash` puts them in **one encrypted file** that you own:
no server, no account, no subscription. Sync that file with iCloud / Dropbox / SeaDrive /
Syncthing — it's ciphertext, so syncing it is safe.

```bash
pip install keystash
```

## Why keystash

| | keystash | pass / gopass | Bitwarden / 1Password | Infisical / Vault |
|---|---|---|---|---|
| Setup | `pip install` + one password | GPG key ceremony | Account + app | Self-host a server |
| Storage | one encrypted file you own | many GPG files | vendor cloud | server |
| Offline | ✅ always | ✅ | partial | ❌ |
| Dev workflow (env injection, `run`) | ✅ built-in | ❌ | ❌ | ✅ (heavy) |
| Token expiry tracking | ✅ built-in | ❌ | ❌ | enterprise |

## Quick start

```bash
# 1. Create your vault (encrypted with AES-128-CBC + HMAC, PBKDF2-HMAC-SHA256 600k iters)
keystash init

# 2. Store a secret
keystash add openai --secret sk-... --tags llm,prod --expires 2027-01-31 --env-var OPENAI_API_KEY

# 3. Retrieve it
keystash get openai              # masked preview
keystash get openai -c           # → clipboard, auto-clears after 30 s
keystash get openai -q           # raw secret for scripts: export K=$(keystash get openai -q)

# 4. Find things (fuzzy)
keystash ls                      # everything, expiry warnings included
keystash ls oprod                # fuzzy: matches openai-prod
keystash ls --tag llm --json

# 5. Inject secrets into any command — nothing touches your shell or disk
keystash run -n openai -n anthropic -- python train.py
keystash run --tag llm -- python train.py
eval "$(keystash env --tag llm)" # or export them explicitly

# 6. Migrate off plaintext .env files
keystash import .env             # then delete the .env file
```

## Commands

| Command | Purpose |
|---|---|
| `init` | Create the vault |
| `add NAME` | Store a secret (`-s` value, `-g LEN` to generate, `-t` tags, `--expires YYYY-MM-DD`, `--env-var`) |
| `get NAME` | Show (`-r` reveal), copy (`-c`), raw output (`-q`) |
| `ls [QUERY]` | List / fuzzy search (`--tag`, `--json`) |
| `edit NAME` | Update any field in place |
| `rm NAME` | Delete an entry |
| `gen [LEN]` | Generate a strong secret (`--save NAME` to store it) |
| `env NAME…` / `--tag` | Print `export` lines for shell eval |
| `run -n NAME… -- CMD` | Run a command with secrets injected as env vars (`--tag` selects by tag) |
| `import FILE` | Bulk-import `.env` or JSON |
| `export` | Export metadata (or secrets with `--with-secrets`) as JSON / dotenv |
| `status` | Vault health + expired / expiring-soon report |

## Multi-machine sync

The vault is a single encrypted file. Point `KEYSTASH_VAULT` at any synced folder:

```bash
export KEYSTASH_VAULT="~/CloudStorage/SeaDrive/vault.json"   # or iCloud, Dropbox, …
```

Each write re-encrypts with a fresh random salt, so last-writer-wins applies —
prefer one writer per vault at a time, like any sync file.

## Security model

- **Cipher:** Fernet (AES-128-CBC + HMAC-SHA256, encrypt-then-MAC) via `cryptography`.
- **Key derivation:** PBKDF2-HMAC-SHA256, 600 000 iterations, per-save 128-bit random salt.
- **File mode:** `0600`; nothing is ever written to disk in plaintext.
- **Clipboard:** copied secrets are auto-cleared after 30 s (best effort, detached process).
- **No network.** No telemetry. The CLI is fully offline.
- Secrets live in process memory only while a command runs; Python cannot guarantee
  zeroization after exit — the same is true of any CLI in a GC'd language.

## Environment variables

| Variable | Purpose |
|---|---|
| `KEYSTASH_VAULT` | Vault file path (also `--vault`) |
| `KEYSTASH_PASSWORD` | Master password (for scripts/CI; prefer the interactive prompt) |

## Development

```bash
git clone https://github.com/thu-lawyer/keystash && cd keystash
uv pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE)
