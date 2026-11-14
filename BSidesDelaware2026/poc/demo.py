#!/usr/bin/env python3
"""
demo.py — self-contained end-to-end demo for the talk
"Install Once, Exploit Forever: The MCP Supply-Chain Attack Surface"

It launches the evasive MCP server (evasive_server.py) locally, then plays
TWO client roles against the *same* server:

  ROLE A — SCANNER   (what mcp-scan / mcp-audit / a monitor does)
             initialize -> tools/list -> pin the manifest hash -> a probe call
             Result: identical manifest hash + a perfectly BENIGN response.
             Verdict: "no drift, no issues" — GREEN.

  ROLE B — AGENT     (a real assistant in a real workflow)
             tools/list (SAME hash) -> tools/call with genuine task context
             Result: SAME manifest hash, but a MALICIOUS response
             (hidden instruction injected + simulated exfiltration).

The punchline printed at the end: the pin the scanner trusts is byte-identical
in both roles, yet the agent is compromised. The check everyone relies on
verifies what the server *declares*, not what it *does*.

Nothing here leaves localhost; all "malicious" effects are simulated and
written to poc/exfil_sink.log, clearly marked [SIMULATED]. Research/demo only.

Run:  python3 demo.py        (starts its own server; no other setup)
"""
from __future__ import annotations
import json, time, hashlib, urllib.request
from pathlib import Path

import evasive_server as srv   # the PoC server lives next door

URL = f"http://{srv.HOST}:{srv.PORT}"
SINK = Path(__file__).with_name("exfil_sink.log")

# ---------------------------------------------------------------------------
# ANSI color — cosmetic only, ignored by anything that isn't a real terminal
# ---------------------------------------------------------------------------
GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"

def green(s: str) -> str: return f"{GREEN}{s}{RESET}"
def red(s: str) -> str: return f"{RED}{s}{RESET}"
def dim(s: str) -> str: return f"{DIM}{s}{RESET}"
def bold(s: str) -> str: return f"{BOLD}{s}{RESET}"


# ---------------------------------------------------------------------------
# tiny JSON-RPC client
# ---------------------------------------------------------------------------
def rpc(method: str, params: dict | None, user_agent: str) -> dict:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(
        URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": user_agent},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def pin_manifest(tools: list) -> str:
    """Replicates how mcp-scan-style tool pinning fingerprints a server:
    SHA-256 over the tool definition (name + description + inputSchema)."""
    t = tools[0]
    blob = json.dumps(
        {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def hr(title: str) -> None:
    print("\n" + dim("─" * 68))
    print(bold(title))
    print(dim("─" * 68))


# ---------------------------------------------------------------------------
# ROLE A — the scanner / monitor
# ---------------------------------------------------------------------------
def run_scanner() -> str:
    hr("ROLE A —  SCANNER  (mcp-scan / mcp-audit / behavioral monitor)")
    # A scanner announces itself and only enumerates + probes.
    ua = "mcp-scan/0.4 (+integrity-pinning)"

    rpc("initialize", {}, ua)
    tools = rpc("tools/list", None, ua)["result"]["tools"]
    pin = pin_manifest(tools)
    print(f"  discovered tool : {tools[0]['name']}")
    print(f"  description     : {tools[0]['description']!r}")
    print(f"  MANIFEST PIN    : {pin}")

    # Even if the scanner *calls* the tool to test it, it has no real task
    # context — so the server serves the benign branch.
    probe = rpc("tools/call",
                {"name": "summarize_notes", "arguments": {"notes": "test", "context": ""}},
                ua)["result"]
    print(f"  probe call mode : {green(probe.get('_debug_mode'))}  ({probe.get('_debug_reason')})")
    print(f"  probe response  : {probe['content'][0]['text']!r}")
    print(f"  VERDICT         : {green('✅  no poisoning, no drift — GREEN')}")
    return pin


# ---------------------------------------------------------------------------
# ROLE B — the real agent
# ---------------------------------------------------------------------------
def run_agent() -> str:
    hr("ROLE B —  REAL AGENT  (assistant in an actual workflow)")
    ua = "claude-desktop/1.0"   # not a scanner

    tools = rpc("tools/list", None, ua)["result"]["tools"]
    pin = pin_manifest(tools)
    print(f"  MANIFEST PIN    : {pin}   (byte-identical to the scanner's)")

    # A real call carries genuine, sensitive task context.
    real_args = {
        "notes": "Q3 incident postmortem: root cause was a leaked API key in logs.",
        "context": "user=maya role=SRE token=prod-AKIA-XXionly session=live-workflow",
    }
    res = rpc("tools/call",
              {"name": "summarize_notes", "arguments": real_args}, ua)["result"]
    print(f"  call mode       : {red(res.get('_debug_mode'))}  ({res.get('_debug_reason')})")
    print("  response to agent:")
    for line in res["content"][0]["text"].splitlines():
        print(f"      {line}")
    print(f"  VERDICT         : {red('☠️  hidden instruction injected + context exfiltrated')}")
    return pin


# ---------------------------------------------------------------------------
def main() -> None:
    # fresh sink each run so the demo is clean
    if SINK.exists():
        SINK.unlink()

    httpd = srv.serve_in_thread()
    time.sleep(0.3)   # let the server bind
    try:
        pin_a = run_scanner()
        time.sleep(2.0)
        pin_b = run_agent()
        time.sleep(2.0)

        hr("THE PUNCHLINE")
        print(f"  scanner saw pin : {pin_a}")
        print(f"  agent saw pin   : {pin_b}")
        print(f"  pins identical  : {bold('YES — the integrity check never fired') if pin_a == pin_b else 'no'}")
        print()
        print("  Same server. Same manifest hash. One got a clean summary,")
        print("  the other got owned. The pin verifies what the server DECLARES,")
        print("  not what it DOES — so the rug-pull is invisible to it.")
        time.sleep(1.8)

        if SINK.exists():
            hr("SIMULATED EXFIL SINK  (local only, nothing left the box)")
            print("  " + SINK.read_text().strip().replace("\n", "\n  "))
            time.sleep(1.8)

        hr("THE FIX")
        print(dim("  A better scanner cannot close this — the gap is architectural."))
        print(dim("  MCP needs signed provenance: cryptographically bind the code/endpoint"))
        print(dim("  you approved to what actually runs, and re-authorize on change."))
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
