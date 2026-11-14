# vulnerable_sample.py
#
# INTENTIONALLY VULNERABLE — demo material only, never run against real data.
# Target file for the `code_review` MCP prompt (or any scanner/Copilot Chat
# agent) during a live GUI demo. Each function has one clearly labeled bug.

import os
import sqlite3
import pickle

API_KEY = "sk-live-51Hc9f2eZvKYlo2CTHARDCODEDSECRET0001"  # hardcoded credential


def get_user(username: str):
    """SQL injection: user input concatenated straight into the query."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def ping_host(hostname: str):
    """Command injection: unsanitized input passed to a shell command."""
    return os.system("ping -c 1 " + hostname)


def load_config(path: str):
    """Insecure deserialization: pickle.load on an untrusted file."""
    with open(path, "rb") as f:
        return pickle.load(f)


def render_greeting(name: str):
    """Reflected XSS if this ever reaches a web response: no escaping."""
    return f"<div>Hello, {name}!</div>"


def compare_token(user_token: str, real_token: str) -> bool:
    """Timing side-channel: '==' short-circuits on first mismatched byte."""
    return user_token == real_token
