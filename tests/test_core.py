"""Tests for blindsqli, run entirely against a local in-process target."""

from __future__ import annotations

import threading
from wsgiref.simple_server import WSGIServer, make_server

import pytest

from blindsqli.core import (
    CalibrationError,
    Extractor,
    Oracle,
    Target,
    binary_search,
    default_template,
)
from tests.vulnerable_app import SECRET, application


@pytest.fixture(scope="module")
def server():
    httpd = make_server("127.0.0.1", 0, application, server_class=WSGIServer)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def make_oracle(base_url: str) -> Oracle:
    target = Target(url=f"{base_url}/?id=PREFIX{Target.marker if False else '*'}")
    template = default_template("boolean", "mysql")
    oracle = Oracle(target, template, "boolean", true_string="Welcome back")
    oracle.calibrate()
    return oracle


def test_binary_search_pins_a_value():
    asked = []

    def ask(cond: str) -> bool:
        asked.append(cond)
        value = 42
        gt = int(cond.split(">")[1])
        return value > gt

    assert binary_search(ask, "x", 0, 127) == 42
    # 0..127 should take at most 7 comparisons.
    assert len(asked) <= 7


def test_target_requires_exactly_one_marker():
    with pytest.raises(ValueError):
        Target(url="https://example.com/no-marker")
    with pytest.raises(ValueError):
        Target(url="https://example.com/?a=*&b=*")


def test_calibration_detects_true_string(server):
    oracle = make_oracle(server)
    assert "Welcome back" in oracle.rule
    assert oracle.ask("1=1") is True
    assert oracle.ask("1=2") is False


def test_calibration_auto_detects_by_length(server):
    # No --string/--code given: TRUE ("Welcome back") and FALSE ("Home") differ
    # in body length, so calibration should latch onto that on its own.
    target = Target(url=f"{server}/?id=*")
    oracle = Oracle(target, default_template("boolean", "mysql"), "boolean")
    rule = oracle.calibrate()
    assert "length" in rule
    assert oracle.ask("1=1") is True
    assert oracle.ask("1=2") is False


def test_calibration_fails_when_responses_are_identical():
    # A target that never changes its response can't be used as an oracle.
    class DeadTarget(Target):
        def send(self, payload):  # type: ignore[override]
            import requests

            resp = requests.models.Response()
            resp.status_code = 200
            resp._content = b"same"
            return resp

    target = DeadTarget(url="https://example.com/?id=*")
    oracle = Oracle(target, default_template("boolean", "mysql"), "boolean")
    with pytest.raises(CalibrationError):
        oracle.calibrate()


def test_extract_length(server):
    oracle = make_oracle(server)
    extractor = Extractor(oracle, "mysql", threads=4)
    assert extractor.length("version()") == len(SECRET["version()"])


def test_extract_full_value(server):
    oracle = make_oracle(server)
    extractor = Extractor(oracle, "mysql", threads=4)
    assert extractor.extract("version()") == SECRET["version()"]


def test_extract_is_efficient(server):
    oracle = make_oracle(server)
    extractor = Extractor(oracle, "mysql", threads=1)
    extractor.extract("database()")
    # ~7 requests per character for binary search, plus length probing and
    # calibration. A linear scan would be ~95 per char; assert we're well under.
    per_char = oracle.requests / len(SECRET["database()"])
    assert per_char < 20
