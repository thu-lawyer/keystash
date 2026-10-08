# keystash 🔑

> 值留给钥匙串，AI 只拿引用名。
> The Keychain keeps the values; your AI agent only ever gets references.

`keystash` 让 AI 助手（MCP、Claude Code、任何 agent）帮你**管理** API key、token、密码，
而不让它**看见**它们。

v0.4.0 起：**值存在 macOS 登录钥匙串，磁盘上只剩元数据，而且全库没有 read 工具 ——
没有任何一个接口会把密钥交给 AI。**

一句话：**这一版的安全性来自「没有 read 工具」＋「全库没有明文出口」，不是来自「用了什么加密」。**

---

## English

### Why keystash

The usual advice — "don't paste your API key into the chat" — stopped working the day agents
became useful. An agent that cannot read `OPENAI_API_KEY` cannot rotate it, cannot call the API
on your behalf, cannot tell you which key expires next month.

So the goal is not "the agent never touches keys". It is **the agent manages keys it cannot see**:

- The value goes into the **macOS login Keychain**. It is never written to a file this tool owns,
  never printed, never returned by any API.
- Only **metadata** (name, tags, rotation schedule, allowed URLs) lives on disk, in plain 0600 JSON.
  Metadata is deliberately *not* secret — so listing and editing it needs no unlock.
- There is **no `secret_read` tool**, and no CLI command that echoes a value to stdout. Not a
  disabled flag — the code path does not exist.
- The one route to the outside world, `secret_use`, can only reach URLs you pre-approved per entry.

### Quick start

```bash
pip install keystash          # or: uv tool install keystash

keystash doctor               # check Keychain / osascript / security / pbcopy

# Store a key. The value is typed into a native hidden dialog — never argv, never the shell history.
keystash add OPENAI_PROD_KEY -a https://api.openai.com/ -r 90

# Let keystash invent one instead; it prints a fingerprint, never the value.
keystash generate STRIPE_PROD_SECRET -a https://api.stripe.com/ -r 180
# generated STRIPE_PROD_SECRET  sha256:1f3a9c02  (43 chars)

keystash list                 # metadata only
keystash list --json
keystash use OPENAI_PROD_KEY https://api.openai.com/v1/models
keystash rm OPENAI_PROD_KEY
```

Piping a value in (CI, another vault, a password manager export) skips the dialog:

```bash
printf '%s' "$VALUE" | keystash add MY_SERVICE_PROD_KEY --stdin -a https://api.myservice.com/
```

Naming convention: `SERVICE_ENV_PURPOSE` — `OPENAI_PROD_KEY`, `ALIYUN_OSS_STAGING_SECRET`.
Enforced: `^[A-Z][A-Z0-9_]{0,63}$`.

### Touch ID unlock

Values live in the login Keychain. `keystash copy NAME` puts the value on the clipboard and clears
it again after 30 seconds (`--clear-after 0` disables the clear). Nothing is printed.
The Touch ID prompt appears when a value is actually needed — not on `list`, not on `show`,
not on `doctor`, not on metadata edits.

### keystash doctor — clean up the mess you already have

`keystash doctor` reports the platform, whether the Keychain backend is available, the paths of
`osascript` / `security` / `pbcopy`, your metadata file, the audit log, and the legacy vault path.
If the metadata file exists it also prints the entry count and **which entries are past their
rotation interval**.

### AI agents, zero plaintext: keystash mcp

`keystash mcp` speaks MCP over **stdio only** — it opens no socket, not even on 127.0.0.1.
It exposes exactly six tools. There is no `secret_read`, and no `run_command`:

| Tool | What it does | Does the AI see the value? |
| --- | --- | --- |
| `secret_list` | List entries: name, tags, rotation dates, allowed URLs | No — metadata only |
| `secret_store` | Store a value the **user** types into a dialog | No |
| `secret_rotate` | Replace a value the same way | No |
| `secret_generate` | Generate a strong value and store it | No — a fingerprint is returned |
| `secret_use` | Call an allowed URL with the credential, return the reply | No — the key stays in the request header |
| `secret_delete` | Erase the entry and its Keychain item, after a native dialog you confirm | No |

Wire it into an MCP client:

```json
{
  "mcpServers": {
    "keystash": {
      "command": "keystash",
      "args": ["mcp"],
      "env": { "KEYSTASH_META": "/Users/you/.keystash/entries.json" }
    }
  }
}
```

Three things worth knowing about `secret_use`:

1. **Per-entry allow-list.** Every entry carries `allowed_urls`, and a URL must be a prefix match
   of one of them. `https://api.openai.com.evil.com/` does not match `https://api.openai.com/`,
   and prefix matching is why the entries must end in `/`. **An empty allow-list refuses
   everything** — the AI cannot pick the destination host, so `secret_use` cannot be turned into
   an exfiltration primitive.
2. **Redirects are refused**, not followed (`allow_redirects=False`), so an allowed host cannot
   bounce the credential somewhere else.
3. **The response body is scrubbed** against the value and its encodings (raw, base64, URL-encoded,
   hex) before it reaches the model, and truncated at 20 000 characters.

Every `secret_use` call appends one line to the audit log (`~/.keystash/audit.log`, mode 0600):
timestamp, entry name, method, URL, HTTP status. **Who called what, never the value.**

### Commands

| Command | Purpose |
| --- | --- |
| `keystash list [-t TAG] [--json]` | List entries (metadata only) |
| `keystash show NAME` | One entry's metadata |
| `keystash add NAME [-t TAG] [-r DAYS] [-a URL] [--auth-header H] [--auth-prefix P] [--stdin] [--force]` | Store a new secret |
| `keystash rotate NAME [--stdin]` | Replace the value, keep the metadata |
| `keystash generate NAME [-t TAG] [-r DAYS] [-a URL] [-l LEN]` | Generate and store (16–128 chars, default 43) |
| `keystash edit NAME [-t TAG] [-r DAYS] [-a URL]` | Metadata only — the value is never read or rewritten |
| `keystash copy NAME [--clear-after SECONDS]` | Clipboard, auto-cleared (default 30) |
| `keystash use NAME URL [-X METHOD] [-d BODY] [--timeout SECONDS]` | Call an allow-listed URL |
| `keystash rm NAME [--yes]` | Delete the entry and its Keychain item |
| `keystash migrate [-s VAULT] [--verify/--no-verify] [--retire-vault]` | Move a v0.3 encrypted vault into the Keychain |
| `keystash doctor` | Check this machine's prerequisites |
| `keystash mcp` | Serve the MCP stdio interface |

### Migrating from v0.3

v0.3 kept everything in one PBKDF2 + Fernet vault file. `migrate` reads that vault once and writes
each value into the Keychain:

```bash
keystash migrate -s ~/keystash-vault.json --retire-vault
```

You are prompted for the old master password (hidden dialog). Values pass through memory only;
the only output is a table of old name / new name / tags / verified. `--verify` (on by default) reads each value back out of the
Keychain and compares it before the entry is considered migrated, so a silent Keychain failure
cannot lose a key. `--retire-vault` renames the old file to `*.migrated` after a fully successful
run — it is not deleted. Keep that file until you have confirmed every entry.

### Multi-machine sync

The **metadata** file is plain JSON; sync it however you like. The **values** do not sync —
they are in this Mac's login Keychain, and that is the point. On a second machine, re-enter or
`keystash add --stdin` each value once, then copy the metadata file over.

### Security model

Read this part before trusting the tool.

**What keystash does eliminate.** The plaintext inventory. Before, your keys were in
`~/.zshrc`, in `.env` files, in shell history, in chat logs, in MCP transcripts, in your clipboard
buffer's past. Now they are in one place the AI has no tool to read, and no command prints them.

**What it does not do.** With Keychain storage, encryption at rest is the OS's job, and the
layer beneath is your login session. Concretely:

- **Any process running as you can read the same values.** `security find-generic-password -s keystash
  -a OPENAI_PROD_KEY -w` works from any same-user shell. keystash does not defend against a
  compromised account, and does not claim to.
- **The boundary is same-user process isolation, not encryption.** keystash removes plaintext from
  the *artifacts* — files, logs, transcripts, argv, env — not from a *trusted* process's memory.
- **Metadata is not secret** (plain 0600 JSON): names, tags, rotation dates and allowed URLs are
  readable by anyone who can read your home directory. Names leak intent ("ALIYUN_PROD_KEY" tells
  an attacker where to look). Do not put secrets in tags.
- **Scrubbing is literal replacement over a fixed encoding set** (raw, base64, urlsafe-base64,
  percent-encoded, hex). A value re-encoded some other way — encrypted, split across lines,
  character-shifted — can survive it. Values shorter than 8 characters are still redacted
  verbatim, but their encoding variants are not, so a short secret is only partially covered.
- **Rotation is a reminder, not an enforcement.** `-r DAYS` makes `doctor` and the MCP
  `secret_list` flag overdue entries. Nothing rotates automatically.
- **Secrets injected into a request are visible to same-user processes** in principle; that is the
  same boundary as above.

**What the AI can still do.** It can list your entry names, delete entries, call allow-listed URLs
with stored credentials (and read the responses), and store *new* values — including ones it
invents. Treat `secret_delete` and the allow-lists as things you review, not things you set once.
Read the audit log.

keystash 消掉的是明文，不是信任。

### Environment variables

| Variable | Meaning | Default |
| --- | --- | --- |
| `KEYSTASH_META` | Metadata file path | `~/.keystash/entries.json` |
| `KEYSTASH_VAULT` | Legacy v0.3 vault path — used only by `migrate` | `~/.keystash/vault.json` |

The `--meta/-m` and `--vault/-V` flags override them.

### Development

```bash
git clone https://github.com/thu-lawyer/keystash.git
cd keystash
pip install -e ".[dev]"
pytest -q          # the real Keychain is never touched
ruff check src tests
```

The test suite drives the CLI as a subprocess and injects an in-memory store, so it passes on
Linux and Windows CI with no Keychain. Set `KEYSTASH_TEST_KEYCHAIN=1` to opt into the one test
that touches the real login Keychain.

### License

MIT

---

## 中文

### 为什么是 keystash

「别把 API key 贴进对话」这条建议，在 agent 变得有用的那天就失效了。
一个读不到 `OPENAI_API_KEY` 的 agent，没法帮你轮换它、没法代你调接口、也说不清下个月哪个 key 过期。

所以目标不是「agent 永不接触密钥」，而是**让 agent 管理它看不见的密钥**：

- 值进 **macOS 登录钥匙串**，不写进本工具拥有的任何文件、不打印、不被任何接口返回。
- 磁盘上只有**元数据**（名字、标签、轮换周期、允许的 URL），0600 明文 JSON。
  元数据**故意不算秘密** —— 所以列出和编辑它不需要解锁。
- **没有 `secret_read` 工具**，也没有任何把值打到 stdout 的 CLI 命令。
  不是「关掉的开关」，是这条代码路径根本不存在。
- 唯一通往外面的路 `secret_use`，只能打你按条目预先批准的 URL。

### 快速上手

```bash
pip install keystash          # 或：uv tool install keystash

keystash doctor               # 检查 Keychain / osascript / security / pbcopy

# 存一个 key。值在系统隐藏输入框里手打 —— 不走 argv，不进 shell 历史。
keystash add OPENAI_PROD_KEY -a https://api.openai.com/ -r 90

# 也可以让 keystash 生成；它只打印指纹，不打印值。
keystash generate STRIPE_PROD_SECRET -a https://api.stripe.com/ -r 180
# generated STRIPE_PROD_SECRET  sha256:1f3a9c02  (43 chars)

keystash list                 # 只有元数据
keystash list --json
keystash use OPENAI_PROD_KEY https://api.openai.com/v1/models
keystash rm OPENAI_PROD_KEY
```

从管道喂值（CI、别的密码库导出）可以跳过弹窗：

```bash
printf '%s' "$VALUE" | keystash add MY_SERVICE_PROD_KEY --stdin -a https://api.myservice.com/
```

命名规范：`SERVICE_ENV_PURPOSE` —— `OPENAI_PROD_KEY`、`ALIYUN_OSS_STAGING_SECRET`。
已强制校验：`^[A-Z][A-Z0-9_]{0,63}$`。

### Touch ID 解锁

值在登录钥匙串里。`keystash copy NAME` 把值放进剪贴板，30 秒后自动清除（`--clear-after 0` 关闭清除）。
**不打印任何东西。** 真正取值时才出现 Touch ID 提示 —— `list`、`show`、`doctor`、
改元数据都不会触发。

### keystash doctor —— 主动清剿你已经撒出去的明文

`keystash doctor` 会报出平台、Keychain 后端是否可用、`osascript` / `security` / `pbcopy` 的路径、
元数据文件、审计日志、旧版 vault 路径。元数据文件存在时，还会给出条目总数和**已过轮换期的条目**。

### AI 助手零明文管理：keystash mcp

`keystash mcp` 只走 **stdio**，不开任何端口（连 127.0.0.1 都不开）。
它恰好暴露六个工具，没有 `secret_read`，也没有 `run_command`：

| 工具 | 做什么 | AI 会看见值吗 |
| --- | --- | --- |
| `secret_list` | 列出条目：名字、标签、轮换日期、允许的 URL | 不会 —— 只有元数据 |
| `secret_store` | 存一个**用户**在弹窗里亲手输入的值 | 不会 |
| `secret_rotate` | 用同样方式替换值 | 不会 |
| `secret_generate` | 生成强随机值并存入 | 不会 —— 只返回指纹 |
| `secret_use` | 带凭据调一个被允许的 URL，返回响应 | 不会 —— key 只在请求头里 |
| `secret_delete` | 你在原生弹窗里确认后，删除条目及其钥匙串项 | 不会 |

接到 MCP 客户端：

```json
{
  "mcpServers": {
    "keystash": {
      "command": "keystash",
      "args": ["mcp"],
      "env": { "KEYSTASH_META": "/Users/you/.keystash/entries.json" }
    }
  }
}
```

关于 `secret_use`，有三点值得知道：

1. **按条目的白名单。** 每个条目带 `allowed_urls`，URL 必须与其中一条前缀匹配。
   `https://api.openai.com.evil.com/` 匹配不上 `https://api.openai.com/` ——
   前缀匹配正是要求白名单项**必须以 `/` 结尾**的原因。**白名单为空 = 拒绝一切**。
   AI 无法自选目标主机，所以 `secret_use` 变不成外送通道。
2. **拒绝跟随重定向**（`allow_redirects=False`），被允许的主机无法把凭据弹去别处。
3. **响应体先擦洗再回给模型**（值本身及其 raw / base64 / URL 编码 / hex 变体），
   并在 20 000 字符处截断。

每次 `secret_use` 往审计日志（`~/.keystash/audit.log`，0600）追加一行：
时间戳、条目名、方法、URL、HTTP 状态。**只记谁在何时用了哪个 key，永不记值。**

### 命令一览

| 命令 | 作用 |
| --- | --- |
| `keystash list [-t TAG] [--json]` | 列出条目（仅元数据） |
| `keystash show NAME` | 单个条目的元数据 |
| `keystash add NAME [-t TAG] [-r DAYS] [-a URL] [--auth-header H] [--auth-prefix P] [--stdin] [--force]` | 存入新密钥 |
| `keystash rotate NAME [--stdin]` | 替换值，保留元数据 |
| `keystash generate NAME [-t TAG] [-r DAYS] [-a URL] [-l LEN]` | 生成并存入（16–128 字符，默认 43） |
| `keystash edit NAME [-t TAG] [-r DAYS] [-a URL]` | 只改元数据 —— 值不被读、不被重写 |
| `keystash copy NAME [--clear-after SECONDS]` | 复制到剪贴板并自动清除（默认 30 秒） |
| `keystash use NAME URL [-X METHOD] [-d BODY] [--timeout SECONDS]` | 调一个白名单内的 URL |
| `keystash rm NAME [--yes]` | 删除条目及其钥匙串项 |
| `keystash migrate [-s VAULT] [--verify/--no-verify] [--retire-vault]` | 把 v0.3 加密 vault 迁进钥匙串 |
| `keystash doctor` | 检查本机前置条件 |
| `keystash mcp` | 提供 MCP stdio 接口 |

### 从 v0.3 迁移

v0.3 把所有东西放在一个 PBKDF2 + Fernet 的 vault 文件里。`migrate` 读一次那个 vault，
把每个值写进钥匙串：

```bash
keystash migrate -s ~/keystash-vault.json --retire-vault
```

会提示输入旧主密码（隐藏弹窗）。值只经过内存；输出只有一张 旧名/新名/标签/已校验 的表。
`--verify`（默认开）会把每个值从钥匙串读回来比对，确认无误才算迁移成功 ——
这样钥匙串静默失败也不会悄悄丢 key。`--retire-vault` 在整轮成功后才把旧文件改名为
`*.migrated`，**不删除**。确认所有条目之前，先留着那个文件。

### 多机同步

**元数据**是明文 JSON，随便你怎么同步。**值不同步** —— 它们在这台 Mac 的登录钥匙串里，
而这正是重点。第二台机器上重新录入（或用 `keystash add --stdin` 喂一次），再把元数据文件拷过去。

### 安全模型

信这个工具之前，请读完这一段。

**keystash 消掉了什么。** 明文清单。过去你的 key 散在 `~/.zshrc`、`.env`、shell 历史、
对话记录、MCP 转录、剪贴板的历史里。现在它们在一个地方，AI 没有工具能读，也没有命令会打印。

**它不做什么。** 值放在钥匙串里，静态加密是操作系统的活，而它下面那一层是你的登录会话。具体说：

- **任何以你的身份运行的进程都能读到同样的值。** 在同一个用户下的任意 shell 里，
  `security find-generic-password -s keystash -a OPENAI_PROD_KEY -w` 就能取出来。
  keystash 不防「账号已被攻破」，也不声称能防。
- **边界是「同用户进程隔离」，不是「加密」。** keystash 把明文从**产物**里去掉 ——
  文件、日志、转录、argv、环境变量 —— 而不是从一个**受信任**进程的内存里去掉。
- **元数据不是秘密**（0600 明文 JSON）：名字、标签、轮换日期、允许的 URL，
  能读你家目录的人都能读。名字本身就泄露意图（`ALIYUN_PROD_KEY` 直接告诉攻击者去哪儿找）。
  **不要把秘密写进标签。**
- **擦洗是「固定编码集合上的字面替换」**（raw、base64、urlsafe-base64、百分号编码、hex）。
  值若被换成别的编码形态 —— 加密、跨行拆开、字符位移 —— 可能活下来。
  短于 8 个字符的值仍会被原样擦除，但**不做编码变体扩展**，所以短密钥只被部分覆盖。
- **轮换是提醒，不是强制。** `-r DAYS` 只让 `doctor` 和 MCP 的 `secret_list` 标出逾期条目，
  没有任何自动轮换。
- **注入请求的密钥原则上对同用户进程可见**，与上面同一条边界。

**AI 仍然能做什么。** 它能列出你的条目名、删除条目、用存好的凭据调白名单内的 URL
（并读到响应）、以及存**新**值（包括它自己生成的）。
把 `secret_delete` 和白名单当成需要你复核的东西，而不是设一次就完事的东西。审计日志要读。

keystash 消掉的是明文，不是信任。

### 环境变量

| 变量 | 含义 | 默认 |
| --- | --- | --- |
| `KEYSTASH_META` | 元数据文件路径 | `~/.keystash/entries.json` |
| `KEYSTASH_VAULT` | 旧版 v0.3 vault 路径 —— 只有 `migrate` 会读 | `~/.keystash/vault.json` |

`--meta/-m` 与 `--vault/-V` 可覆盖它们。

### 参与开发

```bash
git clone https://github.com/thu-lawyer/keystash.git
cd keystash
pip install -e ".[dev]"
pytest -q          # 不会碰真实钥匙串
ruff check src tests
```

测试以子进程方式驱动 CLI，并把存储换成内存实现，所以在无钥匙串的 Linux / Windows CI 上也能过。
设 `KEYSTASH_TEST_KEYCHAIN=1` 才会启用唯一那个会碰真实登录钥匙串的测试。

### License

MIT

<!-- mcp-name: io.github.thu-lawyer/keystash -->
