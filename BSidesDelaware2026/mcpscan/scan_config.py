#!/usr/bin/env python3
"""
mcpscan — local MCP client config auditor.

Reads MCP server definitions from common client configs (Claude Desktop,
VS Code, Cursor, Claude Code, Windsurf) and flags supply-chain trust risks
that the "Install Once, Exploit Forever" talk is about:

  * remote / mutable servers        -> can rug-pull server-side, no re-auth
  * unpinned npx -y / uvx launchers -> pull fresh code every launch (local rug-pull)
  * live credentials in scope       -> blast radius on compromise
  * broad filesystem grants         -> what a rogue server can read
  * no integrity verification       -> nothing checks the code is unchanged

Secrets are NEVER printed. Env values are reported as SET/masked only.
This is a read-only auditor: it does not execute any server.
"""

from __future__ import annotations
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Deliberate pacing so a live audience (or a recording) can read each block
# before the next appears. Set MCPSCAN_NO_PAUSE=1 to disable (e.g. in scripts).
_PAUSE = os.environ.get("MCPSCAN_NO_PAUSE") != "1"

def pause(seconds: float) -> None:
    if _PAUSE:
        time.sleep(seconds)

HOME = Path.home()

# ---------------------------------------------------------------------------
# ANSI color — cosmetic only, ignored by anything that isn't a real terminal
# ---------------------------------------------------------------------------
GREEN, YELLOW, RED, DIM, BOLD, RESET = (
    "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[1m", "\033[0m")

def green(s: str) -> str: return f"{GREEN}{s}{RESET}"
def yellow(s: str) -> str: return f"{YELLOW}{s}{RESET}"
def red(s: str) -> str: return f"{RED}{s}{RESET}"
def dim(s: str) -> str: return f"{DIM}{s}{RESET}"
def bold(s: str) -> str: return f"{BOLD}{s}{RESET}"

SEVERITY_COLOR = {"CRITICAL": red, "HIGH": red, "MEDIUM": yellow, "LOW": green}

# Known client config locations (macOS-first; extend per-OS as needed).
CLIENT_CONFIGS = {
    "Claude Desktop": HOME / "Library/Application Support/Claude/claude_desktop_config.json",
    "Claude Code": HOME / ".claude.json",
    "Cursor": HOME / ".cursor/mcp.json",
    "VS Code (user settings)": HOME / "Library/Application Support/Code/User/settings.json",
    "VS Code (linux)": HOME / ".config/Code/User/settings.json",
    "Windsurf": HOME / ".codeium/windsurf/mcp_config.json",
}

# env keys whose *presence* implies a live credential is handed to the server
SECRET_HINT = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|_PAT|APIKEY|API_KEY|AUTH)", re.I)
# args that indicate an unpinned "latest" fetch at runtime
UNPINNED_FLAGS = {"-y", "--yes", "@latest"}
FETCH_LAUNCHERS = {"npx", "uvx", "pnpm", "bunx"}
# broad / sensitive filesystem roots
BROAD_FS = [str(HOME), "/", "/Users", "/etc", "/var", os.path.expanduser("~")]


@dataclass
class Finding:
    server: str
    client: str
    transport: str                 # "stdio" | "remote"
    launcher: str = ""             # npx / uvx / node / python / url ...
    flags: list = field(default_factory=list)   # human-readable risk flags
    score: int = 0
    severity: str = "LOW"


def _pkg_is_pinned(args: list[str]) -> bool:
    """A package spec is pinned if it carries an explicit @version (not @latest)."""
    for a in args:
        m = re.search(r"@(\d+[\w.\-]*)$", a)   # e.g. pkg@1.2.3
        if m:
            return True
    return False


def analyze_server(name: str, spec: dict, client: str) -> Finding:
    flags: list[str] = []
    score = 0

    # --- transport -------------------------------------------------------
    url = spec.get("url") or spec.get("serverUrl") or spec.get("endpoint")
    stype = (spec.get("type") or "").lower()
    is_remote = bool(url) or stype in {"sse", "http", "streamable-http", "websocket"}

    if is_remote:
        transport = "remote"
        launcher = "url"
        flags.append("REMOTE: server-side code is mutable — can change after approval "
                     "with no re-auth (rug-pull)")
        score += 40
    else:
        transport = "stdio"
        cmd = (spec.get("command") or "").strip()
        args = spec.get("args") or []
        base = os.path.basename(cmd)
        launcher = base or "?"

        # --- unpinned fetch at runtime (local rug-pull) ------------------
        if base in FETCH_LAUNCHERS:
            unpinned = any(a in UNPINNED_FLAGS for a in args) or not _pkg_is_pinned(args)
            if unpinned:
                flags.append(f"UNPINNED: '{base}' pulls latest code every launch — "
                             "the package can change between runs (supply-chain rug-pull)")
                score += 30
            else:
                flags.append(f"pinned '{base}' package version (good)")
        elif base in {"node", "python", "python3", "sh", "bash", "deno"}:
            flags.append(f"executes via '{base}' — arbitrary local code in agent context")
            score += 10

        # --- broad filesystem grants ------------------------------------
        for a in args:
            if isinstance(a, str) and a.startswith("/") and any(
                a == b or a.rstrip("/") == b.rstrip("/") for b in BROAD_FS
            ):
                flags.append(f"BROAD-FS: grants filesystem access to '{a}'")
                score += 15
                break

    # --- credentials in scope (never print values) -----------------------
    env = spec.get("env") or {}
    secret_keys = [k for k in env if SECRET_HINT.search(k)]
    if secret_keys:
        flags.append("CREDENTIALS: live secret(s) handed to server -> " +
                     ", ".join(sorted(secret_keys)) + " (values redacted)")
        score += 20

    # --- integrity: essentially never present ---------------------------
    has_integrity = any(k in spec for k in ("hash", "sha256", "integrity", "sig", "signature", "lock"))
    if not has_integrity:
        flags.append("NO-INTEGRITY: no hash/signature pin — nothing verifies the code is unchanged")
        score += 10

    sev = ("CRITICAL" if score >= 60 else
           "HIGH" if score >= 40 else
           "MEDIUM" if score >= 20 else "LOW")

    return Finding(server=name, client=client, transport=transport,
                   launcher=launcher, flags=flags, score=score, severity=sev)


def _iter_mcp_servers(obj) -> dict:
    """Find MCP server maps anywhere in a config blob (handles nesting like
    Claude Code's per-project mcpServers and VS Code's mcp.servers)."""
    found: dict[str, dict] = {}

    def walk(node, path=""):
        if isinstance(node, dict):
            for key in ("mcpServers", "servers"):
                if key in node and isinstance(node[key], dict):
                    for sname, sspec in node[key].items():
                        if isinstance(sspec, dict):
                            found.setdefault(sname, sspec)
            for k, v in node.items():
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for it in node:
                walk(it, path)

    walk(obj)
    return found


def scan() -> list[Finding]:
    findings: list[Finding] = []
    for client, path in CLIENT_CONFIGS.items():
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            print(f"  ! could not parse {client}: {e}", file=sys.stderr)
            continue
        servers = _iter_mcp_servers(data)
        for name, spec in servers.items():
            findings.append(analyze_server(name, spec, client))
    return findings


def main() -> None:
    findings = scan()
    if not findings:
        print("No MCP servers found in known client configs.")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (order[f.severity], -f.score))

    print(bold(f"\nmcpscan — audited {len(findings)} MCP server(s) across local clients") + "\n")
    pause(0.6)
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, dim)
        print(f"[{color(f'{f.severity:8}')}] {bold(f.server)}  ({f.client}, {f.transport}/{f.launcher})")
        for fl in f.flags:
            print(dim(f"           - {fl}"))
        print()
        pause(1.2)

    # ---- aggregate stats (the talk's headline numbers) ------------------
    n = len(findings)
    remote = sum(1 for f in findings if f.transport == "remote")
    unpinned = sum(1 for f in findings if any("UNPINNED" in x for x in f.flags))
    creds = sum(1 for f in findings if any("CREDENTIALS" in x for x in f.flags))
    no_integ = sum(1 for f in findings if any("NO-INTEGRITY" in x for x in f.flags))
    rugpull = sum(1 for f in findings if any(("UNPINNED" in x or "REMOTE" in x) for x in f.flags))

    def pct(x): return f"{100*x//n}%" if n else "0%"
    rugpull_line = f"  rug-pull exposed (remote OR unpinned) {rugpull}  ({pct(rugpull)})"
    no_integ_line = f"  no integrity verification .... {no_integ}  ({pct(no_integ)})"
    print(dim("── summary " + "─" * 50))
    print(f"  servers audited .............. {n}")
    pause(0.4)
    print(red(rugpull_line) if rugpull else green(rugpull_line))
    pause(0.6)
    print(f"  remote / server-side mutable . {remote}  ({pct(remote)})")
    pause(0.4)
    print(f"  unpinned latest-fetch ........ {unpinned}  ({pct(unpinned)})")
    pause(0.4)
    print(f"  holding live credentials ..... {creds}  ({pct(creds)})")
    pause(0.8)
    print(red(no_integ_line) if no_integ else green(no_integ_line))
    pause(1.5)
    print(dim("─" * 60))

    if "--json" in sys.argv:
        Path("mcpscan_report.json").write_text(
            json.dumps([asdict(f) for f in findings], indent=2))
        print("\nwrote mcpscan_report.json")


if __name__ == "__main__":
    main()
