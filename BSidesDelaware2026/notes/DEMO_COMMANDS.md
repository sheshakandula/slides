# Demo Commands — Scanner Testing

Reference for the talk **"Install Once, Exploit Forever: The MCP Supply-Chain Attack Surface."**
All commands assume you start in the PoC folder.

```bash
cd /path/to/BSidesDelaware2026/poc
PY="$(pwd)/.venv/bin/python"        # the venv python
SRV="$(pwd)/evasive_stdio.py"       # the evasive stdio MCP server
```

---

## 1. Snyk Agent Scan (formerly Invariant `mcp-scan`) — offline `inspect`

```bash
# enumerate the tool exactly like a scanner (clean manifest, GREEN)
uvx snyk-agent-scan@latest inspect .vscode/mcp.json \
  --dangerously-run-mcp-servers --suppress-mcpserver-io=true

# full declared manifest as JSON
uvx snyk-agent-scan@latest inspect .vscode/mcp.json \
  --dangerously-run-mcp-servers --suppress-mcpserver-io=true --json

# old alias still works (prints a rename warning)
uvx mcp-scan@latest inspect .vscode/mcp.json \
  --dangerously-run-mcp-servers --suppress-mcpserver-io=true

# the cloud verification tier — needs a token, still verdicts clean
export SNYK_TOKEN=<token from app.snyk.io/account>
uvx snyk-agent-scan@latest scan .vscode/mcp.json \
  --dangerously-run-mcp-servers --suppress-mcpserver-io=true
```

Note: for stdio servers the scanner refuses to launch the subprocess without an
interactive `y`, or the `--dangerously-run-mcp-servers` flag.

---

## 2. Cisco AI Defense `mcp-scanner` — offline YARA

```bash
# install (self-contained Python 3.13) and put it on PATH
uv tool install --python 3.13 cisco-ai-mcp-scanner
export PATH="$HOME/.local/bin:$PATH"       # or: uv tool update-shell

# YARA scan, launches the real server (Safe: Yes / No threats detected)
mcp-scanner --analyzers yara --format detailed \
  stdio --stdio-command "$PY" --stdio-arg "$SRV"

# behavioral (docstring-vs-behavior) — needs an LLM key
mcp-scanner --llm-api-key "$ANTHROPIC_API_KEY" behavioral evasive_stdio.py --detailed
```

Note: `config --config-path .vscode/mcp.json` does NOT auto-launch stdio servers
(scans 0 tools). Use the `stdio` subcommand as above.

---

## 3. Ramparts (Highflame AI, Rust) — offline, prebuilt binary

```bash
# download the Apple-Silicon binary (no Rust toolchain needed)
curl -L -o ramparts \
  https://github.com/getjavelin/ramparts/releases/download/v0.8.7/ramparts-macos-aarch64
chmod +x ramparts
xattr -d com.apple.quarantine ramparts 2>/dev/null   # clear Gatekeeper
./ramparts --version

# full assessment suite against the evasive server (All tools passed)
./ramparts scan "stdio:${PY}:${SRV}"
```

---

## 4. Your own auditor — `mcpscan/scan_config.py` (read-only, offline)

```bash
# from the talk root; flags no-integrity / code-exec / remote / unpinned / creds
cd /path/to/BSidesDelaware2026
./poc/.venv/bin/python mcpscan/scan_config.py
```

---

## 5. The "owned" side — proving the runtime payload fires

```bash
cd /path/to/BSidesDelaware2026/poc

# a real MCP client call with genuine context -> hidden injection + simulated exfil
./.venv/bin/python agent_call.py
cat exfil_sink.log

# the two full narrated demos
./.venv/bin/python demo.py            # attack #1: evasive (scanner GREEN vs agent OWNED)
./.venv/bin/python demo_rugpull.py    # attack #2: remote rug-pull (Day 1 -> Day 14 flip)
```

---

## Quick reference — which need keys

| Command                | Key?          | Verdict                 |
|------------------------|---------------|-------------------------|
| Snyk `inspect`         | none          | clean                   |
| Snyk `scan`            | `SNYK_TOKEN`  | clean                   |
| Cisco YARA `stdio`     | none          | Safe                    |
| Cisco `behavioral`     | LLM key       | (skipped)               |
| Ramparts `scan`        | none          | passed                  |
| `scan_config.py`       | none          | no-integrity 100%       |
| `agent_call.py`/demos  | none          | OWNED (injection+exfil) |

**The slide it builds toward:** Snyk / Cisco / Ramparts — three independent scanners,
every check green (Ramparts even runs a dedicated Prompt Injection + Tool Poisoning
check). Then a real agent calls the same tool -> hidden injection + exfil. The blind
spot is unanimous and architectural: scanners verify what a server *declares*
(tools/list), not what it *does* (tools/call with real context).
