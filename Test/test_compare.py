"""Tests for the security-header regression tester."""

from header_regression.compare import Snapshot, compare
from header_regression.cli import parse_raw_headers


def snap(label, **headers):
    return Snapshot.from_dict(label, headers)


def kinds(diffs):
    return {(d.header, d.kind) for d in diffs}


def test_missing_hsts_is_high():
    base = snap("prod", **{"Strict-Transport-Security": "max-age=100"})
    cand = snap("stg")
    diffs = compare(base, cand)
    assert ("strict-transport-security", "removed") in kinds(diffs)
    assert any(d.severity == "HIGH" for d in diffs)


def test_hsts_max_age_downgrade():
    base = snap("prod", **{"Strict-Transport-Security": "max-age=63072000"})
    cand = snap("stg", **{"Strict-Transport-Security": "max-age=300"})
    diffs = compare(base, cand)
    assert any(d.kind == "weakened" and "max-age" in d.message for d in diffs)


def test_hsts_lost_include_subdomains():
    base = snap("prod", **{"Strict-Transport-Security": "max-age=100; includeSubDomains"})
    cand = snap("stg", **{"Strict-Transport-Security": "max-age=100"})
    diffs = compare(base, cand)
    assert any("includeSubDomains" in d.message for d in diffs)


def test_cors_widened_to_wildcard():
    base = snap("prod", **{"Access-Control-Allow-Origin": "https://x.com"})
    cand = snap("stg", **{"Access-Control-Allow-Origin": "*"})
    diffs = compare(base, cand)
    assert any(d.kind == "cors" and d.severity == "HIGH" for d in diffs)


def test_cookie_lost_secure_flag():
    base = Snapshot.from_dict("prod", {"Set-Cookie": ["s=1; Secure; HttpOnly"]})
    cand = Snapshot.from_dict("stg", {"Set-Cookie": ["s=1; HttpOnly"]})
    diffs = compare(base, cand)
    assert any(d.kind == "cookie" and "Secure" in d.message for d in diffs)


def test_cookie_samesite_weakened():
    base = Snapshot.from_dict("prod", {"Set-Cookie": ["s=1; Secure; SameSite=Strict"]})
    cand = Snapshot.from_dict("stg", {"Set-Cookie": ["s=1; Secure; SameSite=None"]})
    diffs = compare(base, cand)
    assert any("SameSite" in d.message for d in diffs)


def test_identical_snapshots_no_regression():
    headers = {
        "Strict-Transport-Security": "max-age=100; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
    }
    base = Snapshot.from_dict("prod", dict(headers))
    cand = Snapshot.from_dict("stg", dict(headers))
    assert compare(base, cand) == []


def test_added_header_is_info_not_regression():
    base = snap("prod")
    cand = snap("stg", **{"X-Frame-Options": "DENY"})
    diffs = compare(base, cand)
    assert all(d.severity == "INFO" for d in diffs)


def test_parse_raw_headers():
    raw = (
        "HTTP/2 200\r\n"
        "strict-transport-security: max-age=100\r\n"
        "set-cookie: a=1; Secure\r\n"
        "set-cookie: b=2; HttpOnly\r\n"
    )
    parsed = parse_raw_headers(raw)
    assert parsed["strict-transport-security"] == "max-age=100"
    assert isinstance(parsed["Set-Cookie"], list)
    assert len(parsed["Set-Cookie"]) == 2
