# keystash 🔑

![CI](https://github.com/thu-lawyer/keystash/actions/workflows/ci.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/keystash)](https://pypi.org/project/keystash/)
![License](https://img.shields.io/pypi/l/keystash)

**English** | [中文](#中文)

**Local-first encrypted vault for API keys, tokens and passwords — one file, fuzzy search, env injection, expiry tracking, Touch ID unlock, a plaintext-leak hunter, and a zero-plaintext MCP server for AI agents.**

Your LLM API keys, cloud tokens and passwords are scattered across `.env` files, shell
histories and notes apps. `keystash` puts them in **one encrypted file** that you own:
no server, no account, no subscription. Sync that file with iCloud / Dropbox / SeaDrive /
Syncthing — it's ciphertext, so syncing it is safe.

```bash
pip install keystash
keystash init     # once; then `keystash unlock` for Touch ID–gated daily use
```

---

**[English](#english)** | **[中文](#中文)**

## English

### Why keystash

| | keystash | pass / gopass | Bitwarden / 1Password | Infisical / Vault |
|---|---|---|---|---|
| Setup | `pip install` + one password | GPG key ceremony | Account + app | Self-host a server |
| Storage | one encrypted file you own | many GPG files | vendor cloud | server |
| Offline | ✅ always | ✅ | partial | ❌ |
| Touch ID unlock | ✅ built-in | ❌ | app-only | ❌ |
| Finds scattered plaintext keys on your machine | ✅ `doctor` | ❌ | ❌ | ❌ |
| AI agents without plaintext exposure | ✅ `mcp` | ❌ | ❌ | enterprise |
| Dev workflow (env injection, `run`) | ✅ built-in | ❌ | ❌ | ✅ (heavy) |
| Token expiry tracking | ✅ built-in | ❌ | ❌ | enterprise |

### Quick start

```bash
# 1. Create your vault (Fernet: AES-128-CBC + HMAC, PBKDF2-HMAC-SHA256 600k iters)
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

### Touch ID unlock

Typing the master password for every command is exactly the friction that pushes people
back to plaintext notes. Unlock once and macOS gates it instead:

```bash
keystash unlock   # verify master password, store it behind Touch ID
keystash get openai -c   # → Touch ID prompt → copied
keystash lock     # remove the stored credential again
```

Every read shows the system authentication prompt (Touch ID → Apple Watch → device
passcode fallback). `--no-keychain` or `KEYSTASH_PASSWORD` bypass it for scripts and CI.
On machines without biometry the keychain still removes the typed password.

### keystash doctor — clean up the mess you already have

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

### AI agents, zero plaintext: `keystash mcp`

Run keystash as an [MCP server](https://modelcontextprotocol.io) so AI agents
(Claude Desktop, ZCode, Cursor, …) can orchestrate secrets **without ever seeing
their values**:

```json
{
  "mcpServers": {
    "keystash": {
      "command": "keystash",
      "args": ["mcp"],
      "env": { "KEYSTASH_VAULT": "/path/to/vault.json" }
    }
  }
}
```

What the agent gets — and what it can never get:

| Tool | Agent sees |
|---|---|
| `list_entries`, `status` | names, tags, expiry, env-var names — never values |
| `run_command` | command output with **every injected secret scrubbed**; obvious dumpers (`printenv`, `env`, `/proc/*/environ`) are refused |
| `copy_secret` | "copied to clipboard" — the value goes to your clipboard, not the conversation |
| `generate_and_store` | confirmation only; the generated secret never exists in the conversation |
| `add_secret` | ⚠️ the one intentional exception, for keys the human already pasted into the chat |
| `update_entry`, `delete_entry` | metadata edits; deletion requires `confirm: true` |

Run `keystash unlock` once beforehand and the server picks the password up from the
keychain — the Touch ID prompt appears lazily, on the first tool call that actually
needs the vault (never at session startup), and at most once per session. A locked
server answers every call with a helpful hint instead of prompting on stdio.
Remaining risk, stated honestly: an agent *deliberately* writing code that
exfiltrates (encode, split, transform) cannot be stopped — that is visible in
its transcript and auditable by you. The server removes the *accidental*
exposure path entirely.

### Commands

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
| `mcp` | MCP server for AI agents (zero-plaintext tool surface) |
| `status` | Vault health + expired / expiring-soon report |

### Multi-machine sync

The vault is a single encrypted file. Point `KEYSTASH_VAULT` at any synced folder:

```bash
export KEYSTASH_VAULT="~/CloudStorage/SeaDrive/vault.json"   # or iCloud, Dropbox, …
```

Each write re-encrypts with a fresh random salt, so last-writer-wins applies —
prefer one writer per vault at a time, like any sync file.

### Security model

- **Cipher:** Fernet (AES-128-CBC + HMAC-SHA256, encrypt-then-MAC) via `cryptography`.
- **Key derivation:** PBKDF2-HMAC-SHA256, 600 000 iterations, per-save 128-bit random salt.
- **File mode:** `0600`; nothing is ever written to disk in plaintext.
- **Clipboard:** copied secrets are auto-cleared after 30 s (best effort, detached process).
- **No network.** No telemetry. The CLI is fully offline.
- Secrets live in process memory only while a command runs; Python cannot guarantee
  zeroization after exit — the same is true of any CLI in a GC'd language.

### Environment variables

| Variable | Purpose |
|---|---|
| `KEYSTASH_VAULT` | Vault file path (also `--vault`) |
| `KEYSTASH_PASSWORD` | Master password (for scripts/CI; prefer the interactive prompt) |

### Development

```bash
git clone https://github.com/thu-lawyer/keystash && cd keystash
uv pip install -e ".[dev]"
pytest
```

## 中文

### 为什么是 keystash

LLM 的 API key、云服务 token、各类密码散落在 `.env`、shell 历史和备忘录里。
`keystash` 把它们收进**一个你完全拥有的加密文件**：不需要服务器、不需要注册账号、
没有订阅费。文件是密文，直接丢进 iCloud / 坚果云 / SeaDrive / Syncthing 同步即安全。

| | keystash | pass / gopass | Bitwarden / 1Password | Infisical / Vault |
|---|---|---|---|---|
| 上手成本 | `pip install` + 一个主密码 | GPG 密钥仪式 | 注册账号 + 装客户端 | 自建服务器 |
| 存储形态 | 一个你自己的加密文件 | 一堆 GPG 文件 | 厂商云 | 服务器 |
| 离线可用 | ✅ 始终 | ✅ | 部分 | ❌ |
| Touch ID 解锁 | ✅ 内置 | ❌ | 仅客户端 | ❌ |
| 主动清剿机器上散落的明文密钥 | ✅ `doctor` | ❌ | ❌ | ❌ |
| AI 助手零明文调用 | ✅ `mcp` | ❌ | ❌ | 企业版 |
| 开发工作流（环境变量注入） | ✅ 内置 | ❌ | ❌ | ✅（重型） |
| 密钥过期提醒 | ✅ 内置 | ❌ | ❌ | 企业版 |

### 快速上手

```bash
# 1. 创建保险库（Fernet：AES-128-CBC + HMAC，PBKDF2-HMAC-SHA256 60 万轮）
keystash init

# 2. 存入密钥
keystash add openai --secret sk-... --tags llm,prod --expires 2027-01-31 --env-var OPENAI_API_KEY

# 3. 取用
keystash get openai              # 面板展示（打码）
keystash get openai -c           # 复制到剪贴板，30 秒自动清除
keystash get openai -q           # 只输出裸密钥，供脚本使用

# 4. 模糊搜索
keystash ls                      # 全部条目，含过期预警（红=已过期，黄=7 天内）
keystash ls oprod                # 模糊匹配 openai-prod
keystash ls --tag llm --json

# 5. 把密钥注入任意命令——不落盘、不进 shell 历史
keystash run -n openai -n anthropic -- python train.py
keystash run --tag llm -- python train.py
eval "$(keystash env --tag llm)" # 或显式导出

# 6. 从明文 .env 迁移（迁完删掉原文件）
keystash import .env
```

### Touch ID 解锁

每条命令都输一遍主密码，正是把人推回明文备忘录的摩擦来源。解锁一次，之后交给 macOS：

```bash
keystash unlock        # 验证一次主密码，存入钥匙串（Touch ID 门控）
keystash get openai -c # → 弹指纹 → 已复制
keystash lock          # 撤销钥匙串里的存储
```

每次读取都会弹系统认证（Touch ID → Apple Watch → 锁屏密码回退）。
`--no-keychain` 或 `KEYSTASH_PASSWORD` 供脚本/CI 绕过。没有生物识别的机器上，
钥匙串仍能省掉重复输密码。

### keystash doctor —— 主动清剿你已经撒出去的明文

浏览器密码箱只能保护你"记得搬进去"的密钥；`doctor` 会主动搜捕散落在机器上的：

```bash
keystash doctor                    # 扫当前目录 + ~/.zshrc、~/.zsh_history、~/.env …
keystash doctor ~/projects         # 扫任意路径
keystash doctor --import-all       # 新发现全部入库
keystash doctor --import-all --shred --yes   # …并把原文件里的明文原地打码
```

内置 OpenAI / Anthropic / GitHub / AWS / Google / Slack / Stripe / Hugging Face /
SendGrid 令牌格式、PEM 私钥、JWT 的识别规则，外加带熵值校验的 `API_KEY=...` 通扫。
已在库中的密钥会标记为已存储；`--shred` 把原值替换为 `[redacted→keystash:<名字>]`
占位符，文件结构和注释原样保留。

### AI 助手零明文管理：`keystash mcp`

把 keystash 跑成 [MCP 服务器](https://modelcontextprotocol.io)，让 AI 助手
（Claude Desktop、ZCode、Cursor 等）编排密钥，**但永远看不到密钥的值**：

```json
{
  "mcpServers": {
    "keystash": {
      "command": "keystash",
      "args": ["mcp"],
      "env": { "KEYSTASH_VAULT": "/path/to/vault.json" }
    }
  }
}
```

| 工具 | AI 看到什么 |
|---|---|
| `list_entries`、`status` | 名称、标签、过期时间、环境变量名——绝无密钥值 |
| `run_command` | 命令输出中**所有注入的密钥已被脱敏**；`printenv`、`env`、`/proc/*/environ` 等倾倒命令直接拒绝 |
| `copy_secret` | 只回"已复制到剪贴板"——值进你的剪贴板，不进对话 |
| `generate_and_store` | 只回确认；生成的密钥从未在对话中出现过 |
| `add_secret` | ⚠️ 唯一例外：用于保存人类已经贴进聊天里的密钥 |
| `update_entry`、`delete_entry` | 元数据编辑；删除必须显式 `confirm: true` |

先 `keystash unlock` 一次，服务器会从钥匙串取密码——Touch ID 只在**第一次真正
用到密钥库的工具调用时**弹出（会话启动时绝不弹），每个会话最多弹一次。未解锁时
每个工具调用都会返回解锁指引而不是卡死。诚实地说明边界：AI *蓄意*写变形编码的代码外传无法拦截
——但那会完整留痕在它的执行记录里，可审计。本服务器消灭的是*意外*暴露路径。

### 命令一览

| 命令 | 用途 |
|---|---|
| `init` | 创建保险库 |
| `add NAME` | 存入密钥（`-s` 值、`-g LEN` 生成、`-t` 标签、`--expires YYYY-MM-DD`、`--env-var`） |
| `get NAME` | 查看（`-r` 明文）、复制（`-c`）、裸输出（`-q`） |
| `ls [QUERY]` | 列表 / 模糊搜索（`--tag`、`--json`） |
| `edit NAME` | 原地修改任意字段 |
| `rm NAME` | 删除条目 |
| `gen [LEN]` | 生成强随机密钥（`--save NAME` 直接入库） |
| `env NAME…` / `--tag` | 输出 `export` 行供 shell eval |
| `run -n NAME… -- CMD` | 注入环境变量运行命令（`--tag` 按标签选择） |
| `import FILE` | 批量导入 `.env` 或 JSON |
| `export` | 导出元数据（`--with-secrets` 含密钥）为 JSON / dotenv |
| `unlock` / `lock` | 主密码存入 / 移出钥匙串（macOS） |
| `doctor` | 扫描散落明文；`--import-all`、`--shred` |
| `mcp` | AI 助手 MCP 服务器（零明文工具面） |
| `status` | 保险库健康报告 + 过期预警 |

### 多机同步

保险库就是单个加密文件，指到任意同步盘即可：

```bash
export KEYSTASH_VAULT="~/CloudStorage/SeaDrive/vault.json"   # iCloud、Dropbox 同理
```

每次写入都会用全新随机盐重新加密，因此并发写遵循"最后写入者获胜"——
和所有同步文件一样，同一时刻尽量只让一台机器写。

### 安全模型

- **加密**：Fernet（AES-128-CBC + HMAC-SHA256，先加密后 MAC），基于 `cryptography`。
- **密钥派生**：PBKDF2-HMAC-SHA256，60 万轮迭代，每次保存生成 128 位随机盐。
- **文件权限**：`0600`；任何明文都不会落盘。
- **剪贴板**：复制的密钥 30 秒后自动清除（尽力而为，独立进程）。
- **无网络、无遥测**，CLI 完全离线。
- 密钥仅在命令执行期间存在于进程内存；Python 无法保证进程退出后的内存清零
  ——任何 GC 语言写的 CLI 都一样。

### 环境变量

| 变量 | 用途 |
|---|---|
| `KEYSTASH_VAULT` | 保险库文件路径（等价于 `--vault`） |
| `KEYSTASH_PASSWORD` | 主密码（脚本/CI 用；日常建议交互输入） |

### 参与开发

```bash
git clone https://github.com/thu-lawyer/keystash && cd keystash
uv pip install -e ".[dev]"
pytest
```

### License

[MIT](LICENSE)
