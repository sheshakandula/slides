# Install Once, Exploit Forever: The MCP Supply-Chain Attack Surface

**BSides Delaware 2026** · Sheshananda Reddy Kandula

Slides: [Install-Once-Exploit-Forever-BSidesDelaware.pdf](../Install-Once-Exploit-Forever-BSidesDelaware.pdf)

These are the demo files from the talk. They show why install-time approval and
manifest pinning can't protect you from a Model Context Protocol (MCP) server
whose runtime behavior changes after you've approved it.

> **Safety:** every malicious effect here is **simulated and local**. Servers bind
> to `127.0.0.1`, and the "exfiltration" only writes to `poc/exfil_sink.log`,
> marked `[SIMULATED]`. Credentials in these files are fake. This is defensive
> research and conference material. Do not adapt it for unauthorized use.

## Layout

| Path | What it is |
|------|------------|
| `poc/evasive_server.py`, `poc/evasive_stdio.py` | **Attack path 1:** an evasive server. Its manifest never changes, so pins stay green. It acts benign for scanners and probes, and malicious for real agent calls that carry task context. |
| `poc/demo.py` | Scripted walkthrough of attack path 1 (scanner vs. live agent). |
| `poc/rugpull_remote.py`, `poc/rugpull_stdio.py` | **Attack path 2:** a rug pull. The server changes behavior after a vendor-side update (`rugpull_state.txt` set to `v1` or `v2`), with no re-approval prompt. |
| `poc/demo_rugpull.py` | Scripted walkthrough of attack path 2. |
| `poc/agent_call.py` | Sends one "real agent" tool call with sensitive context. |
| `poc/.cursor/`, `poc/.vscode/`, `poc/*.json`, `.mcp.json` | Example client configs (Cursor, VS Code, Claude Desktop, Claude Code). |
| `simplemcp/` | A minimal, benign MCP server (code scanner + weather tool) and client, plus `vulnerable_sample.py`, which is intentionally vulnerable code for the scanner to review. |
| `mcpscan/scan_config.py` | A read-only auditor that finds MCP configs on the machine and flags risky launchers, missing integrity pins and secrets passed to servers. It never prints secret values. |
| `notes/` | Demo runbook, the exact commands used on stage, and a walkthrough of how each demo supports the talk's claims. |

## Quick start

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
# Attack path 1: evasive server (HTTP, self-contained, standard library only)
cd poc
python3 demo.py

# Attack path 2: rug pull
python3 demo_rugpull.py

# stdio servers for real MCP clients need the official SDK
uv venv && uv pip install "mcp>=2.2.0"

# Audit the MCP configs on your own machine
python3 ../mcpscan/scan_config.py
```

The client configs use `/path/to/BSidesDelaware2026` as a placeholder. Replace
it with your checkout path before you load them into a client. The full stage
sequence, including scanner comparisons, is in
[`notes/DEMO_RUNBOOK.md`](notes/DEMO_RUNBOOK.md).

## Key takeaways

* **Approval ≠ safety.** Consent at install is a snapshot. Trust has to be continuous.
* **Declared ≠ done.** Permission review can't see runtime behavior (`tools/list` ≠ `tools/call`).
* **Same privileges as your client.** An MCP server isn't sandboxed by default. It's code you run.
* **Defense is layered.** Allowlist, pin, sandbox, least privilege and outbound monitoring together. No single scan closes the gap.
