"""A deliberately vulnerable WSGI app used only by the test suite.

It mimics a boolean-based blind SQLi: a query string is concatenated into a
tiny in-memory SQL-ish evaluator, and the page says "Welcome back" only when
the (simulated) query returns a row. Nothing here touches a real database or
the network; it exists so the extractor can be tested offline and in CI.
"""

from __future__ import annotations

import re
import urllib.parse

# The "secret" the tests extract.
SECRET = {"version()": "8.0.34-MySQL", "database()": "acme_prod"}


def _evaluate(condition: str) -> bool:
    """Evaluate the conditions blindsqli generates, without a SQL engine."""
    condition = condition.strip()

    m = re.fullmatch(r"(\d+)=(\d+)", condition)
    if m:
        return m.group(1) == m.group(2)

    # LENGTH((<query>))>N  and  ASCII(SUBSTRING((<query>),P,1))>N
    m = re.fullmatch(r"LENGTH\(\((.+?)\)\)>(\d+)", condition)
    if m:
        value = SECRET.get(m.group(1), "")
        return len(value) > int(m.group(2))

    m = re.fullmatch(r"ASCII\(SUBSTRING\(\((.+?)\),(\d+),1\)\)>(\d+)", condition)
    if m:
        value = SECRET.get(m.group(1), "")
        pos = int(m.group(2))
        char = value[pos - 1] if 1 <= pos <= len(value) else "\x00"
        return ord(char) > int(m.group(3))

    return False


def _extract_condition(tracking_id: str) -> str | None:
    # Payload shape: <prefix>' AND (<cond>)-- -
    m = re.search(r"' AND \((.+?)\)-- -", tracking_id)
    return m.group(1) if m else None


def application(environ, start_response):
    qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    tracking = qs.get("id", [""])[0]

    body = "Home"
    cond = _extract_condition(tracking)
    if cond is not None and _evaluate(cond):
        body = "Welcome back"

    data = body.encode()
    start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", str(len(data)))])
    return [data]
