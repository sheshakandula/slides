# server.py
import ast
import logging
import re
import sys
import httpx
from mcp.server.mcpserver import MCPServer

# httpx logs each request at INFO with the full URL/query string — noisy for a
# demo. Drop it to WARNING; get_weather prints its own short status line below
# so a network call is still visible, just not two raw request lines.
logging.getLogger("httpx").setLevel(logging.WARNING)

# FastMCP("Simple-MCP-Repo-Server") is now MCPServer
mcp = MCPServer("Simple-MCP-Repo-Server")

@mcp.tool()
def echo_message(message: str) -> str:
    """A simple tool that echoes back the user's message."""
    return f"Server received: {message}"

@mcp.resource("notes://readme")
def project_readme() -> str:
    """The project's README, exposed as an MCP resource."""
    return (
        "# simplemcp\n\n"
        "A minimal MCP server used to demonstrate the core protocol — "
        "tools, resources, and prompts — over stdio.\n"
    )


_SECRET_NAME = re.compile(r"(?i)(api_key|secret|token|password|passwd)")
_TIMING_NAME = re.compile(r"(?i)(token|password|secret|hash|signature)")


def _is_dynamic_string(node: ast.AST) -> bool:
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
    )


def _scan_hardcoded_secrets(tree: ast.AST, findings: list[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and _SECRET_NAME.search(target.id):
                findings.append(f"L{node.lineno}: hardcoded credential in '{target.id}'")


def _dynamic_string_vars(tree: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_dynamic_string(node.value):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _scan_sql_injection(tree: ast.AST, findings: list[str]) -> None:
    dynamic_vars = _dynamic_string_vars(tree)
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
        ):
            continue
        arg = node.args[0]
        is_dynamic = _is_dynamic_string(arg) or (isinstance(arg, ast.Name) and arg.id in dynamic_vars)
        if is_dynamic:
            findings.append(f"L{node.lineno}: possible SQL injection — query built via string concatenation/f-string")


def _scan_command_injection(tree: ast.AST, findings: list[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else None
        if name in ("system", "popen") and node.args and _is_dynamic_string(node.args[0]):
            findings.append(f"L{node.lineno}: possible command injection via unsanitized input to a shell command")


def _scan_insecure_deserialization(tree: ast.AST, findings: list[str]) -> None:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("load", "loads")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        ):
            findings.append(f"L{node.lineno}: insecure deserialization — pickle.{node.func.attr} on untrusted input")


def _scan_xss(tree: ast.AST, findings: list[str]) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        text = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        has_interp = any(isinstance(v, ast.FormattedValue) for v in node.values)
        if has_interp and "<" in text and ">" in text:
            findings.append(f"L{node.lineno}: possible reflected XSS — unescaped value interpolated into HTML")


def _scan_timing_sidechannel(tree: ast.AST, findings: list[str]) -> None:
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)):
            continue
        names = [n.id for n in (node.left, node.comparators[0]) if isinstance(n, ast.Name)]
        if any(_TIMING_NAME.search(n) for n in names):
            findings.append(f"L{node.lineno}: possible timing side-channel — use hmac.compare_digest instead of '=='")


_SCANNERS = (
    _scan_hardcoded_secrets,
    _scan_sql_injection,
    _scan_command_injection,
    _scan_insecure_deserialization,
    _scan_xss,
    _scan_timing_sidechannel,
)


@mcp.tool()
def scan_code(path: str) -> str:
    """Static security scan of a Python file: flags hardcoded secrets, SQL/command injection, insecure deserialization, XSS, and timing side-channels."""
    print(f"  [server] scan_code: scanning {path!r}...", file=sys.stderr, flush=True)
    with open(path) as f:
        source = f.read()
    tree = ast.parse(source, filename=path)

    findings: list[str] = []
    for scanner in _SCANNERS:
        scanner(tree, findings)

    print(f"  [server] scan_code: {len(findings)} finding(s) in {path!r}", file=sys.stderr, flush=True)

    if not findings:
        return f"No issues found in {path}."

    findings.sort(key=lambda line: int(line.split(":", 1)[0][1:]))
    return "\n".join([f"Security scan of {path} — {len(findings)} issue(s) found:", ""] + [f"- {f}" for f in findings])


@mcp.prompt()
def code_review(language: str = "python") -> str:
    """Prompt template for a security-focused code review."""
    return (
        f"You are a senior {language} security reviewer.\n"
        "Review the following code for correctness, security issues, and style.\n"
        "Call out any injection, deserialization, or trust-boundary problems explicitly."
    )


@mcp.tool()
def get_weather(city: str) -> str:
    """Get the current weather for a city, e.g. 'London' or 'San Francisco'."""
    print(f"  [server] fetching live weather for {city!r} via Open-Meteo...", file=sys.stderr, flush=True)
    with httpx.Client(timeout=10) as client:
        geo = client.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": city, "count": 1},
        ).json()
        results = geo.get("results")
        if not results:
            return f"Could not find a location named '{city}'."

        place = results[0]
        lat, lon = place["latitude"], place["longitude"]

        forecast = client.get(
            "https://api.open-meteo.com/v1/forecast",
            params={"latitude": lat, "longitude": lon, "current_weather": True},
        ).json()
        current = forecast["current_weather"]

    label = ", ".join(filter(None, [place.get("name"), place.get("country")]))
    return (
        f"Weather in {label}: {current['temperature']}°C, "
        f"wind {current['windspeed']} km/h"
    )

if __name__ == "__main__":
    mcp.run(transport='stdio')

