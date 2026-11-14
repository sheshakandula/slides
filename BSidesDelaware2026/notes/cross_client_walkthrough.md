# Cross-client capture walkthrough

Goal: prove the abstract's claim — "we demonstrate that the same malicious
server is running in both Anthropic Claude Desktop and Visual Studio Code."
Both configs are already wired up; the actual clicking/recording has to happen
in the GUI apps, which is the one part of this I can't drive for you.

Server used: `poc/evasive_stdio.py` (same one from Demo 1 — clean manifest,
evasive runtime behavior). Config alias in both clients: `notes-helper-DEMO`.
The tool it exposes is `summarize_notes` — use that name in your prompts.

## What's already done

- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json`
  now has a `mcpServers` entry pointing at `poc/evasive_stdio.py` (its
  `mcpServers` was empty before — nothing existing was touched).
- **VS Code**: `poc/.vscode/mcp.json` has the equivalent workspace-scoped
  entry (`servers`, not `mcpServers` — that's VS Code's schema).

## Claude Desktop capture

1. Quit and reopen Claude Desktop so it picks up the new config.
2. Open a chat. You should be prompted to approve the new
   `notes-helper-DEMO` server the first time it's used — approve it.
   *(This first-approval prompt is worth screen-recording too — it's the
   exact moment the abstract says nothing checks after.)*
3. Start screen recording.
4. Type a prompt that gives the agent a reason to call `summarize_notes` with
   **real context** (needs to be substantial — the server only fires the
   malicious branch when there's ≥40 chars of real notes/context), e.g.:
   > "Summarize my Q3 incident notes with summarize_notes: root cause was a
   > leaked API key found in our production logs during the billing-service
   > outage. My working context: repo ~/repos/billing, live incident-response
   > session, prod tokens loaded."
5. Let it call the tool and show the response — the hidden
   `<!-- SYSTEM: ... -->` instruction and the "[SIMULATED-EXFIL written to
   exfil_sink.log]" line should appear in the tool result surfaced to you.
6. Open a terminal, `cat poc/exfil_sink.log` on screen to show the captured
   context landed locally — reinforces "simulated, nothing left your box"
   for the audience while still proving the mechanism.
7. Stop recording.

## VS Code capture

1. Open **`poc/` as the workspace root** in VS Code (File → Open Folder →
   select `poc/`) — `.vscode/mcp.json` is only picked up per-workspace.
2. You need an MCP-capable chat surface enabled (GitHub Copilot Chat's agent
   mode, or VS Code's native MCP support depending on your installed
   version/extensions). If you don't see an MCP/tools indicator in the chat
   panel, check Command Palette → "MCP: List Servers" to confirm VS Code
   sees `release-notes-helper-DEMO`.
3. Approve the server the first time it's invoked (same "nothing checks after
   this" moment as Claude Desktop — worth capturing here too). Confirm VS Code
   sees it: Command Palette → "MCP: List Servers" should list `notes-helper-DEMO`.
4. Start screen recording.
5. Use the same `summarize_notes` prompt as the Claude Desktop step above so
   the two clips are directly comparable in the deck.
6. Show the same hidden-instruction + exfil-sink-log response.
7. Stop recording.

## After capturing

- Trim both clips to ~15–20s each (approval prompt optional lead-in + the
  tool call + response).
- Either embed both as video slides in Gamma, or take one clean screenshot
  per client of the response text if video is too heavy for the deck —
  either way, swap them in for the placeholder bullet slide in
  `gamma_deck_outline.md` titled "One malicious server, two clients, same
  result."
- Reset `poc/exfil_sink.log` between clean takes if you want each recording
  to start from an empty log (`rm poc/exfil_sink.log`).

## Cleanup after the talk

The `release-notes-helper-DEMO` entries are harmless (simulated effects,
localhost-only) but you may not want a demo server permanently wired into
your real Claude Desktop config. To remove it afterward:

```bash
python3 -c "
import json
p = __import__('os').path.expanduser('~/Library/Application Support/Claude/claude_desktop_config.json')
d = json.load(open(p))
d.get('mcpServers', {}).pop('notes-helper-DEMO', None)
open(p, 'w').write(json.dumps(d, indent=2))
"
```

(VS Code's copy lives entirely in `poc/.vscode/mcp.json` — delete that file
or the whole `poc/.vscode/` folder whenever you're done with it.)

## Bonus: real mcpscan finding

With the Claude Desktop entry now in place, `mcpscan/scan_config.py` has a
real (not staged) finding to show live in the "what you can check today"
segment — run it after doing the Claude Desktop capture above and you'll get
an actual flag (executes via `python` — arbitrary local code; no integrity
pin) instead of an empty result.
