# keystash 🔑

![CI](https://github.com/thu-lawyer/keystash/actions/workflows/ci.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/keystash)](https://pypi.org/project/keystash/)
![License](https://img.shields.io/pypi/l/keystash)

**Local-first encrypted vault for API keys, tokens and passwords — one file, fuzzy search, env injection, expiry tracking, Touch ID unlock, and a leak hunter that cleans up the mess you already have.**

Your LLM API keys, cloud tokens and passwords are scattered across `.env` files, shell
histories and notes apps. `keystash` puts them in **one encrypted file** that you own:
no server, no account, no subscription. Sync that file with iCloud / Dropbox / SeaDrive /
Syncthing — it's ciphertext, so syncing it is safe.

```bash
pip install keystash
keystash init     # once; then `keystash unlock` for Touch ID–gated daily use
```

## Why keystash

| | keystash | pass / gopass | Bitwarden / 1Password | Infisical / Vault |
|---|---|---|---|---|
| Setup | `pip install` + one password | GPG key ceremony | Account + app | Self-host a server |
| Storage | one encrypted file you own | many GPG files | vendor cloud | server |
| Offline | ✅ always | ✅ | partial | ❌ |
| Touch ID unlock | ✅ built-in | ❌ | app-only | ❌ |
| Finds scattered plaintext keys on your machine | ✅ `doctor` | ❌ | ❌ | ❌ |
| Dev workflow (env injection, `run`) | ✅ built-in | ❌ | ❌ | ✅ (heavy) |
| Token expiry tracking | ✅ built-in | ❌ | ❌ | enterprise |

## Touch ID unlock

Typing the master password for every command is exactly the kind of friction that
pushes people back to plaintext notes. Unlock once and macOS gates it instead:

```bash
keystash unlock   # verify master password, store it behind Touch ID
keystash get openai -c   # → Touch ID prompt → copied
keystash lock     # remove the stored credential again
```

Every read shows the system authentication prompt (Touch ID → Apple Watch → device
passcode fallback). `--no-keychain` or `KEYSTASH_PASSWORD` bypass it for scripts and CI.
On machines without biometry the keychain still removes the typed password.

## keystash doctor — clean up the mess you already have

Browser password managers only guard the keys you *remember to move*. `doctor`
actively hunts the ones littering your machine:

```bash
keystash doctor                    # scan cwd + ~/.zshrc, ~/.zsh_history, ~/.env …
keystash doctor ~/projects         # scan any path
keystash doctor --import-all       # store every new finding in the vault
keystash doctor --import-all --shred --yes   # …and redact the plaintext in place
```

Knows OpenAI / Anthropic / GitHub / AWS / Google / Slack / Stripe / Hugging Face /
SendGrid token shapes, PEM private keys, JWTs, plus an entropy-checked
`API_KEY=...` sweep. Secrets already in the vault are reported as stored; `--shred`
replaces each value with a `[redacted→keystash:<name>]` placeholder so file structure
and comments survive.

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
| `unlock` / `lock` | Store / remove the master password behind Touch ID (macOS) |
| `doctor` | Scan for scattered plaintext secrets; `--import-all`, `--shred` |
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
