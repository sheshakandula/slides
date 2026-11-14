# client.py
import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ---------------------------------------------------------------------------
# ANSI color — cosmetic only, ignored by anything that isn't a real terminal
# ---------------------------------------------------------------------------
GREEN, YELLOW, CYAN, DIM, BOLD, RESET = (
    "\033[32m", "\033[33m", "\033[36m", "\033[2m", "\033[1m", "\033[0m")

def green(s: str) -> str: return f"{GREEN}{s}{RESET}"
def yellow(s: str) -> str: return f"{YELLOW}{s}{RESET}"
def cyan(s: str) -> str: return f"{CYAN}{s}{RESET}"
def dim(s: str) -> str: return f"{DIM}{s}{RESET}"
def bold(s: str) -> str: return f"{BOLD}{s}{RESET}"

async def main():
    # Python fully buffers stdout when it isn't a real tty (e.g. under
    # asciinema/headless recording), so prints only flush at the end while
    # the server's unbuffered stderr appears immediately — making output
    # look out of order. Line-buffer stdout so everything interleaves
    # in the order it actually happened.
    sys.stdout.reconfigure(line_buffering=True)

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "server.py"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print(green("Connected to simplemcp server successfully!"))

            # --- tools/list: the manifest a scanner or client pins ---------
            tools = await session.list_tools()
            print("\n" + bold(cyan("tools/list ->")), [t.name for t in tools.tools])
            await asyncio.sleep(1.0)

            # --- resources/list + resources/read -----------------------------
            resources = await session.list_resources()
            print("\n" + bold(cyan("resources/list ->")), [str(r.uri) for r in resources.resources])

            readme = await session.read_resource("notes://readme")
            for content in readme.contents:
                if hasattr(content, "text"):
                    print(dim(content.text))
            await asyncio.sleep(1.5)

            # --- prompts/list + prompts/get -----------------------------------
            prompts = await session.list_prompts()
            print("\n" + bold(cyan("prompts/list ->")), [p.name for p in prompts.prompts])

            review = await session.get_prompt("code_review", arguments={"language": "python"})
            instructions = "\n".join(
                msg.content.text for msg in review.messages if hasattr(msg.content, "text")
            )
            print(dim(instructions))
            await asyncio.sleep(1.5)

            # --- tools/call: scan_code -----------------------------------
            target = sys.argv[1] if len(sys.argv) > 1 else "vulnerable_sample.py"
            scan = await session.call_tool("scan_code", arguments={"path": target})
            print()
            for content in scan.content:
                if content.type == "text":
                    lines = content.text.splitlines()
                    if lines:
                        print(bold(yellow(lines[0])))
                        for line in lines[1:]:
                            print(yellow(line) if line.strip().startswith("- ") else line)
            await asyncio.sleep(1.5)

            # --- tools/call --------------------------------------------------
            result = await session.call_tool("echo_message", arguments={"message": "Hello from the repo environment!"})
            for content in result.content:
                if content.type == "text": # content.type remains text
                    print(dim(content.text))

            weather = await session.call_tool("get_weather", arguments={"city": "London"})
            for content in weather.content:
                if content.type == "text":
                    print(dim(content.text))
            await asyncio.sleep(1.5)

            # --- apply the prompt to a target file ----------------------------
            target = sys.argv[1] if len(sys.argv) > 1 else "vulnerable_sample.py"
            with open(target) as f:
                code = f.read()

            full_prompt = f"{instructions}\n\n```python\n{code}\n```"
            print(bold(f"\n--- assembled review request for {target} ---\n"))
            print(full_prompt)

if __name__ == "__main__":
    asyncio.run(main())

