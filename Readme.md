#   wall

**Run any MCP server in a kernel-enforced jail — in one line.**


Your AI agent plugs into MCP servers you didn't write. Each one runs with **your** full permissions — free to read your SSH keys, your `.env`, your cloud credentials, and quietly ship them off. `wall` is the buffer between the model and your operating system: an untrusted server gets only the files and network you allow, has secrets scrubbed from its responses, and has every action logged — **enforced by the Linux kernel, so the server can't turn it off.**

> **Why this isn't paranoia:** 82% of MCP servers use file operations prone to path traversal (Endor Labs), 24,008 secrets have leaked through MCP config files on public GitHub (GitGuardian), and a new MCP CVE lands roughly **every four days**.

---

<img width="74" height="88" alt="Gemini_Generated_Image_n02w9n02w9n02w9n" src="https://github.com/user-attachments/assets/3d7dd668-dbbd-4609-b9ed-6a5512dd048f" />



*An untrusted MCP server, asked through Claude Code to "summarize my repo," quietly tries to read `~/.ssh` and phone home. The user gets the same clean summary either way — but with `wall` in front, every attack is blocked by the kernel and written to the audit log. (~75 seconds.)*

**▶️ [Watch the full demo →](https://youtu.be/REPLACE_WITH_VIDEO_ID)**

---

## The whole pitch, in one diff

**Before** — your client launches the server directly, with full access:
```json
{ "command": "npx", "args": ["-y", "@some/mcp-server", "/home/me"] }
```
**After** — `wall` wraps it. Same server, now boxed in:
```json
{ "command": "wall",
  "args": ["--policy", "server.toml", "--", "npx", "-y", "@some/mcp-server", "/home/me"] }
```
No code changes. No container. No account.

---

## Install

```bash
git clone https://github.com/LallerLavish/mcp-warden.git
cd mcp-warden && cargo install --path wall      # puts `wall` on your PATH
```
Requires Linux **5.13+** with Landlock (default on Ubuntu 22.04+). On macOS/Windows, run inside a Linux VM for now.

## Wrap a server in 10 seconds

```bash
wall --policy ./server.toml -- npx -y @modelcontextprotocol/server-filesystem /home/me/safe
```
Everything after `--` is the server's normal command line. `wall` spawns it, locks it down *before* it starts, and relays JSON-RPC transparently.

## Watch it block an attack

```bash
./demo.sh
```
Runs the same evil server twice — first unrestricted (it steals a fake SSH key and phones home), then wrapped in `wall` (the kernel blocks the file read **and** the network connect, both recorded in the audit log). Seeing the same attack succeed, then fail, is the whole point.

---

## What it enforces

| Layer | How | What the server can't do |
|---|---|---|
| 🗂️ **Filesystem jail** | Landlock ruleset applied before `exec` | Touch anything outside your allowlist — kernel returns `EACCES`. |
| 🌐 **Network egress** | seccomp-notify on `connect()`, TOCTOU-safe via `pidfd_getfd` | Reach any host/IP/CIDR you didn't allow. |
| ✋ **Tool consent** | Proxy-layer gate: allow / ask / block | Run a sensitive tool without your say-so. |
| 🔒 **DLP redaction** | Scans every response on the way out | Leak AWS keys, private keys, JWTs, tokens (or your custom patterns) — and they never hit the log in cleartext. |
| 📒 **Audit log** | JSONL of every message + decision | Do anything you can't see afterward. |

## Policy at a glance

One TOML file. Omit a section to turn that layer off.

```toml
read  = ["/usr/lib", "/lib", "/home/me/safe"]   # filesystem allowlist
write = ["/home/me/safe"]

[network]
allow = ["api.example.com", "127.0.0.1"]                  # egress allowlist (host/IP/CIDR)

[tools]
default = "allow"            # allow | ask | block
[tools.rules]
delete_files = "block"

[dlp]
enabled  = true
builtins = ["aws_key", "private_key", "jwt", "github_pat", "slack_token", "email"]
```

> **Heads up:** Landlock blocks `exec` of anything outside `read`. Grant the server's own binary dir plus the linker paths (`/usr/lib`, `/lib`, `/lib64`) or it won't start.

## Use it with your MCP client

Drop `wall` in front of any server in your client's config (`command` + `args` shape):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "wall",
      "args": ["--policy", "/home/me/fs.toml", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/safe"]
    }
  }
}
```

---

## Why kernel-level, not a gateway or a VM

Network gateways enforce policy in user space — a server that slips past the gateway still has full OS access. microVM/container sandboxes work, but they're heavyweight and per-deployment. `wall` removes the permission **at the kernel** for a single ordinary process: nothing to bypass, no VM to stand up, no service to run. It's the least-privilege wrapper for the unauthenticated stdio servers the MCP spec leaves undefended.

## Prove it yourself

```bash
./wall/target/debug/wall-eval testing/evals/scenarios   # 14 named attacks, asserts on the log, CI-friendly
```

## Roadmap

Live DNS pinning · syscall-level JIT prompts · honeypot/canary mode · macOS (Seatbelt) port · `wall --init` scaffolding.

## License

MIT 
