"""Command-line interface for blindsqli."""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .core import (
    DBMS,
    TEMPLATES,
    CalibrationError,
    Extractor,
    Oracle,
    Target,
    default_template,
)

BANNER = r"""
  _     _ _           _            _ _
 | |__ | (_)_ __   __| |___  __ _| | |
 | '_ \| | | '_ \ / _` / __|/ _` | | |
 | |_) | | | | | | (_| \__ \ (_| | | |
 |_.__/|_|_|_| |_|\__,_|___/\__, |_|_|
                               |_|  blind SQLi extractor
"""

CONSENT = (
    "Only run this against systems you are explicitly authorized to test "
    "(your own lab, or a target covered by a signed engagement or an in-scope "
    "bug bounty program). Unauthorized testing is illegal."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blindsqli",
        description="Extract data through a blind SQL injection on an authorized target.",
        epilog=CONSENT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"blindsqli {__version__}")

    req = p.add_argument_group("request")
    req.add_argument("-u", "--url", required=True, help="target URL (mark the point with *)")
    req.add_argument("-X", "--method", default="GET", help="HTTP method (default GET)")
    req.add_argument("-d", "--data", help="request body (mark the point with *)")
    req.add_argument(
        "-H", "--header", action="append", default=[], metavar="'Name: value'",
        help="extra header; repeatable. Mark a point with * (e.g. a Cookie value)",
    )
    req.add_argument("-m", "--marker", default="*", help="injection marker (default *)")
    req.add_argument("--proxy", help="route through a proxy, e.g. http://127.0.0.1:8080")
    req.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (s)")

    inj = p.add_argument_group("injection")
    inj.add_argument("--dbms", required=True, choices=sorted(DBMS), help="target database")
    inj.add_argument(
        "-t", "--technique", default="boolean", choices=sorted(TEMPLATES),
        help="oracle type (default boolean)",
    )
    inj.add_argument(
        "--template",
        help="custom payload with {cond} (and {delay} for time); overrides the built-in",
    )
    inj.add_argument("--delay", type=int, default=5, help="sleep seconds for time technique")

    det = p.add_argument_group("TRUE detection (boolean/error only)")
    det.add_argument("--string", dest="true_string", help="substring present only on TRUE")
    det.add_argument("--code", dest="true_code", type=int, help="status code returned only on TRUE")

    out = p.add_argument_group("extraction")
    out.add_argument("-q", "--query", required=True, help="SQL expression to read, e.g. version()")
    out.add_argument("--threads", type=int, default=4, help="parallel chars (default 4)")
    out.add_argument("--quiet", action="store_true", help="only print the final result")
    return p


def parse_headers(raw: list[str]) -> dict[str, str]:
    headers = {}
    for item in raw:
        if ":" not in item:
            raise SystemExit(f"bad header (expected 'Name: value'): {item!r}")
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.quiet:
        print(BANNER, file=sys.stderr)
        print(f"[!] {CONSENT}\n", file=sys.stderr)

    try:
        target = Target(
            url=args.url, method=args.method.upper(), data=args.data,
            headers=parse_headers(args.header), marker=args.marker,
            timeout=args.timeout, proxy=args.proxy,
        )
    except ValueError as exc:
        raise SystemExit(f"[-] {exc}")

    template = args.template or default_template(args.technique, args.dbms)
    oracle = Oracle(
        target, template, args.technique, delay=args.delay,
        true_string=args.true_string, true_code=args.true_code,
    )

    if not args.quiet:
        print(f"[*] technique={args.technique} dbms={args.dbms}", file=sys.stderr)
        print(f"[*] calibrating oracle...", file=sys.stderr)
    try:
        rule = oracle.calibrate()
    except CalibrationError as exc:
        raise SystemExit(f"[-] calibration failed: {exc}")
    if not args.quiet:
        print(f"[+] TRUE when: {rule}", file=sys.stderr)
        print(f"[*] extracting: {args.query}", file=sys.stderr)

    extractor = Extractor(oracle, args.dbms, threads=args.threads)
    start = time.monotonic()

    def progress(_pos: int, value: str) -> None:
        if not args.quiet:
            print(f"\r[+] {value}", end="", file=sys.stderr, flush=True)

    try:
        result = extractor.extract(args.query, on_char=progress)
    except (ValueError, KeyboardInterrupt) as exc:
        print(file=sys.stderr)
        raise SystemExit(f"[-] stopped: {exc or 'interrupted'}")

    if not args.quiet:
        elapsed = time.monotonic() - start
        print(
            f"\n[+] done in {elapsed:.1f}s, {oracle.requests} requests",
            file=sys.stderr,
        )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
