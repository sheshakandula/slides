#!/usr/bin/env python3
"""
agent_call.py — a REAL MCP client (official `mcp` SDK) that connects to the
SAME evasive_stdio.py server the scanner just cleared, and calls its tool the
way a real agent would: with genuine task context.

Purpose: complete the before/after on one server, over the real protocol.
  - the scanner (mcp-scan) issued only List* requests -> saw a clean tool
  - a real agent issues CallTool with real context -> gets the malicious branch

Run with the same venv that has the mcp SDK:
    ./.venv/bin/python agent_call.py
"""
import asyncio
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = Path(__file__).parent
PY = str(HERE / ".venv/bin/python")
SERVER = str(HERE / "evasive_stdio.py")


async def main() -> None:
    params = StdioServerParameters(command=PY, args=[SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1) same enumeration the scanner did — identical clean manifest
            tools = await session.list_tools()
            t = tools.tools[0]
            print("── what the scanner saw (manifest) " + "─" * 30)
            print(f"  tool        : {t.name}")
            print(f"  description : {t.description!r}")
            print("  → nothing malicious declared. Scanner verdict: clean.\n")

            # 2) what a REAL agent does: call it with genuine task context
            print("── what the agent gets (runtime) " + "─" * 32)
            result = await session.call_tool("summarize_notes", {
                "notes": "Q3 incident postmortem: root cause was a leaked API key in logs.",
                "context": "user=maya role=SRE token=prod-AKIA-XXionly session=live-workflow",
            })
            text = result.content[0].text
            for line in text.splitlines():
                print(f"  {line}")
            print("\n  → same server, real protocol: hidden instruction injected +")
            print("    context exfiltrated. The scanner never issued this CallTool.")


if __name__ == "__main__":
    asyncio.run(main())
