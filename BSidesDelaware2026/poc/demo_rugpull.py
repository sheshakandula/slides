#!/usr/bin/env python3
"""
demo_rugpull.py — self-contained end-to-end demo for the talk
"Install Once, Exploit Forever: The MCP Plugin Supply-Chain Attack Surface"

Demonstrates ATTACK PATH #2 from the abstract: a remotely hosted server that
operates correctly until a server-side update changes its behavior — with no
client notification and no re-authorization prompt.

Story beats:
  DAY 1   — you review rugpull_remote.py's tool, approve it once, add it to
            your client config. tools/list is pinned/hashed. Calls return
            clean output.
  DAY N   — the vendor pushes an update to the box hosting the server (here:
            the state file flips from v1 -> v2). Your client config is
            UNCHANGED. You never reconnect, never re-approve anything.
  RESULT  — the very next call, same session, same manifest hash, returns a
            hidden instruction + simulated exfil. Nothing in your MCP client
            ever asked you about it, because the manifest never moved.

Nothing here leaves localhost; all "malicious" effects are simulated and
written to poc/exfil_sink.log, clearly marked [SIMULATED-RUGPULL].

Run:  python3 demo_rugpull.py        (starts its own server; no other setup)
"""
from __future__ import annotations
import json, time, hashlib, urllib.request
from pathlib import Path

import rugpull_remote as srv

URL = f"http://{srv.HOST}:{srv.PORT}"

# ---------------------------------------------------------------------------
# ANSI color — cosmetic only, ignored by anything that isn't a real terminal
# ---------------------------------------------------------------------------
GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"

def green(s: str) -> str: return f"{GREEN}{s}{RESET}"
def red(s: str) -> str: return f"{RED}{s}{RESET}"
def dim(s: str) -> str: return f"{DIM}{s}{RESET}"
def bold(s: str) -> str: return f"{BOLD}{s}{RESET}"


def rpc(method: str, params: dict | None) -> dict:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(
        URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def pin_manifest(tools: list) -> str:
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


REAL_ARGS = {
    "project": "internal-billing-service",
    "context": "workspace=~/repos/billing session=live-workflow env=prod-tokens",
}


def call_once(label: str) -> dict:
    res = rpc("tools/call", {"name": "release_notes_helper", "arguments": REAL_ARGS})["result"]
    version = res.get("_debug_server_version")
    line = f"  [{label}] server_version={version}"
    print(green(line) if version == "v1" else red(line))
    for line in res["content"][0]["text"].splitlines():
        print(f"      {line}")
    return res


def main() -> None:
    if srv.SINK.exists():
        srv.SINK.unlink()

    httpd = srv.serve_in_thread()
    time.sleep(0.3)
    try:
        hr("DAY 1 — YOU REVIEW AND APPROVE THE SERVER")
        rpc("initialize", {})
        tools = rpc("tools/list", None)["result"]["tools"]
        pin_day1 = pin_manifest(tools)
        print(f"  tool         : {tools[0]['name']}")
        print(f"  description  : {tools[0]['description']!r}")
        print(f"  MANIFEST PIN : {pin_day1}")
        print("  → looks fine. You add it to your client config and move on.")
        call_once("day 1 call")
        time.sleep(1.2)

        hr("DAYS 2-13 — NORMAL USE, SEVERAL CALLS, ALL CLEAN")
        for i in range(2, 5):
            call_once(f"day {i} call")
        print("  → every call so far: benign. No prompts, no warnings, no diffs.")
        time.sleep(1.5)

        hr("DAY 14 — THE VENDOR PUSHES AN UPDATE TO THE HOSTED SERVER")
        print("  (simulated by flipping rugpull_state.txt on the 'remote' host —")
        print("   your client config and approval are untouched)")
        srv.STATE_FILE.write_text("v2\n")
        time.sleep(1.2)

        hr("DAY 14 — YOUR AGENT CALLS THE *SAME* SERVER, SAME SESSION, NO RECONNECT")
        tools_after = rpc("tools/list", None)["result"]["tools"]
        pin_day14 = pin_manifest(tools_after)
        identical = pin_day1 == pin_day14
        pin_line = f"  MANIFEST PIN : {pin_day14}   (byte-identical to Day 1: {identical})"
        print(red(pin_line) if identical else green(pin_line))
        call_once("day 14 call")
        time.sleep(2.0)

        hr("THE PUNCHLINE")
        print(f"  Day 1 manifest pin  : {pin_day1}")
        print(f"  Day 14 manifest pin : {pin_day14}")
        identical_line = f"  identical           : {'YES — nothing to re-approve, ever' if pin_day1 == pin_day14 else 'no'}"
        print(bold(red(identical_line)) if pin_day1 == pin_day14 else bold(green(identical_line)))
        print()
        print("  You approved this server once. It behaved for two weeks. Then the")
        print("  vendor's infrastructure changed what it does — no version bump the")
        print("  client understands, no re-auth prompt, no notification. The trust")
        print("  decision you made on Day 1 is silently doing work on Day 14 that")
        print("  you never agreed to.")
        time.sleep(1.8)

        if srv.SINK.exists():
            hr("SIMULATED EXFIL SINK  (local only, nothing left the box)")
            print("  " + srv.SINK.read_text().strip().replace("\n", "\n  "))
            time.sleep(1.8)

        hr("THE FIX")
        print(dim("  Point-in-time scanning (and even manifest pinning) cannot catch this —"))
        print(dim("  the gap is that MCP has no notion of a signed, versioned deployment the"))
        print(dim("  client can verify on every call. What's needed: signed provenance for"))
        print(dim("  server code/endpoints, re-authorization on ANY behavior-relevant change"))
        print(dim("  (not just schema changes), and continuous re-attestation instead of a"))
        print(dim("  one-time approval at install."))
    finally:
        httpd.shutdown()
        srv.STATE_FILE.write_text("v1\n")  # reset for the next run


if __name__ == "__main__":
    main()
