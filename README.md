# blindsqli

A small, readable blind SQL injection **data-extraction** helper for authorized
testing. It turns a confirmed blind injection point into extracted data using a
yes/no oracle and binary search, across boolean-, error- and time-based
techniques.

I built this after automating the PortSwigger blind-SQLi labs by hand. Those
one-off scripts (`' AND SUBSTRING(...)='a'`, one character and one guess at a
time) worked but were slow and lab-specific. `blindsqli` generalises them:
binary search instead of a linear alphabet scan, pluggable DBMS syntax, and an
oracle that calibrates itself instead of hard-coding "Welcome back".

> ⚠️ **Authorized use only.** Run this against your own lab, a target covered by
> a signed engagement, or an in-scope bug bounty asset. Unauthorized testing is
> illegal. The tool prints this reminder on every run.

## Why it's faster

Extracting one character by trying every candidate (`a`, `b`, `c`, …) costs up
to ~95 requests. Binary search on the ASCII code costs **7** (`log2(128)`). For
a 32-character admin hash that's the difference between ~3,000 requests and
~220 — which matters when a program rate-limits you.

## Install

```bash
git clone https://github.com/3MrGad/blindsqli
cd blindsqli
pip install -e .
```

Requires Python 3.9+ and `requests`.

## Usage

Mark the injection point with `*`, tell it the DBMS, and give it the SQL
expression to read:

```bash
# Boolean-based, TRUE detected automatically from the response:
blindsqli -u "https://TARGET/product?id=*" --dbms mysql -q "version()"

# Boolean-based, TRUE identified by a string in the page:
blindsqli -u "https://TARGET/track" \
  -H "Cookie: TrackingId=abc*" --dbms postgres \
  --string "Welcome back" -q "current_user"

# Time-based (no visible difference in the response):
blindsqli -u "https://TARGET/login" -X POST \
  -d "user=admin*&pass=x" --dbms mysql -t time --delay 5 \
  -q "(SELECT password FROM users WHERE username='administrator')"

# Route through Burp to review every request:
blindsqli -u "https://TARGET/?id=*" --dbms mssql \
  -q "db_name()" --proxy http://127.0.0.1:8080
```

Output goes to stdout (just the extracted value, so it pipes cleanly); progress
and the consent notice go to stderr.

### Options

| Flag | Meaning |
|------|---------|
| `-u/--url` | Target URL. Mark the injection point with `*`. |
| `-X/--method`, `-d/--data`, `-H/--header` | Method, body and headers. The `*` can live in any of them (e.g. a cookie value). |
| `--dbms` | `mysql`, `postgres`, `mssql`, `oracle`, `sqlite`. Picks the right `SUBSTRING`/`LENGTH`/`ASCII` syntax. |
| `-t/--technique` | `boolean` (default), `error`, `time`. |
| `--template` | Custom payload with `{cond}` (and `{delay}`) for odd injection contexts. |
| `--string` / `--code` | Force the TRUE signal instead of auto-calibrating. |
| `-q/--query` | The SQL expression to extract. |
| `--threads` | Characters fetched in parallel (boolean/error only). |
| `--proxy`, `--timeout`, `--delay` | Proxy, per-request timeout, time-based sleep. |

## How it works

1. **Target** holds the request and swaps the payload in for the `*` marker,
   URL-encoding it in the URL/body and escaping `;` in headers.
2. **Oracle** turns a SQL condition into a boolean. On start it *calibrates*:
   it sends known-TRUE (`1=1`) and known-FALSE (`1=2`) conditions and finds what
   separates the responses — a status code, a body-length change, a marker
   string, or (time-based) a measurable delay. If it can't tell them apart it
   stops instead of returning garbage.
3. **Extractor** asks the oracle `LENGTH(...) > n` to find the length (doubling,
   then binary search), then binary-searches each character's ASCII code.
4. For boolean/error it runs characters concurrently; time-based stays serial so
   delays don't overlap.

## Testing

Tests run against a tiny in-process WSGI app (`tests/vulnerable_app.py`) that
simulates a boolean-blind endpoint — no real database and no network, so the
suite is safe to run anywhere, including CI.

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
