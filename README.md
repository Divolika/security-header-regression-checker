# security-header-regression

Catch security-header regressions **between two deployments** — for example,
staging vs production — before they ship.

Instead of scanning arbitrary live sites, it compares two saved *snapshots* of
response headers. That makes it deterministic, safe to run anywhere, and a
natural fit for a CI/CD gate: capture headers from your candidate build,
compare against the known-good baseline, fail the pipeline if security posture
regressed.

## What it detects

- Security headers present in the baseline but **missing** in the candidate
  (HSTS, CSP, X-Frame-Options, etc.)
- **HSTS** `max-age` downgrades and loss of `includeSubDomains`
- **CORS** widening (a specific origin changing to `*`)
- **Cookie** flag regressions: loss of `Secure` / `HttpOnly`, or `SameSite`
  weakened from `Strict`/`Lax` to `None`
- CSP changes (flagged for manual review)

Newly *added* security headers are reported as informational and never fail
the build.

## Install

```bash
git clone https://github.com/Divolika/security-header-regression.git
cd security-header-regression
pip install -e .
```

Pure standard library — no runtime dependencies.

## Capturing a snapshot

A snapshot is just a JSON object of headers. Build one from any `curl -sI`
output:

```bash
curl -sI https://app.example.com | header-regression capture -o production.json
curl -sI https://staging.example.com | header-regression capture -o staging.json
```

Or write the JSON by hand (see `samples/production.json`).

## Comparing

```bash
header-regression diff production.json staging.json
```

Example output (from the bundled samples):

```
[HIGH] access-control-allow-origin: CORS widened from `https://app.example.com` to wildcard `*`.
[HIGH] content-security-policy: Security header `content-security-policy` present in baseline but missing in candidate.
[HIGH] set-cookie:session: Cookie `session` lost the Secure flag.
[HIGH] strict-transport-security: HSTS max-age dropped from 63072000 to 300.
[MEDIUM] set-cookie:prefs: Cookie `prefs` SameSite weakened from lax to none.

Summary: 6 differences (4 high, 2 medium)
```

Exit codes: `0` no regression at/above threshold, `1` regression found,
`2` error.

## In CI

```yaml
- name: Capture candidate headers
  run: curl -sI "$STAGING_URL" | header-regression capture -o candidate.json

- name: Check for header regressions
  run: header-regression diff baseline.json candidate.json --fail-on HIGH
```

Commit `baseline.json` to the repo and update it deliberately when you
intend to change headers.

## Running the tests

```bash
pip install pytest
pytest -q
```
