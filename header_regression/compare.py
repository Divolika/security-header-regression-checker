"""Compare security-relevant HTTP response headers between two deployments.

The tool operates on *snapshots* — JSON files describing the headers a URL
returned — rather than making live requests. This keeps it deterministic,
CI-friendly, and safe (it never scans arbitrary websites). A snapshot can be
produced from `curl -sI`, a proxy export, or any other source; a small helper
is provided to build one from a raw header dump.

The comparison focuses on regressions that matter for security:
  * a security header present in baseline but missing in candidate
  * a weakened value (e.g. HSTS max-age dropped, CSP loosened)
  * cookie flag regressions (Secure / HttpOnly / SameSite removed)
  * CORS policy widening (e.g. specific origin -> ``*``)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Headers we treat as security-relevant. Comparison is case-insensitive.
SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cache-control",
}

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Diff:
    header: str
    kind: str  # removed | weakened | added | cookie | cors
    severity: str
    baseline: Optional[str]
    candidate: Optional[str]
    message: str

    def sort_key(self):
        return (-SEVERITY_ORDER.get(self.severity, 0), self.header)


@dataclass
class Snapshot:
    """A normalised view of one deployment's response headers."""

    label: str
    headers: Dict[str, str] = field(default_factory=dict)  # lower-case keys
    set_cookies: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, label: str, raw: Dict[str, object]) -> "Snapshot":
        headers: Dict[str, str] = {}
        cookies: List[str] = []
        for key, value in raw.items():
            lk = key.lower().strip()
            if lk == "set-cookie":
                if isinstance(value, list):
                    cookies.extend(str(v) for v in value)
                else:
                    cookies.append(str(value))
            else:
                headers[lk] = str(value).strip()
        return cls(label=label, headers=headers, set_cookies=cookies)


def _hsts_max_age(value: str) -> Optional[int]:
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age"):
            try:
                return int(part.split("=", 1)[1].strip())
            except (IndexError, ValueError):
                return None
    return None


def _cookie_flags(cookie: str) -> Dict[str, object]:
    parts = [p.strip() for p in cookie.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    lower = {p.lower() for p in parts}
    samesite = None
    for p in parts:
        if p.lower().startswith("samesite"):
            samesite = p.split("=", 1)[1].strip().lower() if "=" in p else ""
    return {
        "name": name,
        "secure": "secure" in lower,
        "httponly": "httponly" in lower,
        "samesite": samesite,
    }


def _compare_hsts(base: str, cand: str, out: List[Diff]) -> None:
    b_age, c_age = _hsts_max_age(base), _hsts_max_age(cand)
    if b_age is not None and (c_age is None or c_age < b_age):
        out.append(
            Diff(
                header="strict-transport-security",
                kind="weakened",
                severity="HIGH",
                baseline=base,
                candidate=cand,
                message=f"HSTS max-age dropped from {b_age} to "
                f"{c_age if c_age is not None else 'none'}.",
            )
        )
    if "includesubdomains" in base.lower() and "includesubdomains" not in cand.lower():
        out.append(
            Diff(
                header="strict-transport-security",
                kind="weakened",
                severity="MEDIUM",
                baseline=base,
                candidate=cand,
                message="HSTS lost `includeSubDomains`.",
            )
        )


def _compare_cors(base: str, cand: str, out: List[Diff]) -> None:
    if cand == "*" and base != "*":
        out.append(
            Diff(
                header="access-control-allow-origin",
                kind="cors",
                severity="HIGH",
                baseline=base,
                candidate=cand,
                message=f"CORS widened from `{base}` to wildcard `*`.",
            )
        )


def _compare_cookies(base: Snapshot, cand: Snapshot, out: List[Diff]) -> None:
    base_by_name = {_cookie_flags(c)["name"]: _cookie_flags(c) for c in base.set_cookies}
    cand_by_name = {_cookie_flags(c)["name"]: _cookie_flags(c) for c in cand.set_cookies}
    for name, b in base_by_name.items():
        c = cand_by_name.get(name)
        if c is None:
            continue  # cookie removed entirely is not necessarily a regression
        for flag, sev in (("secure", "HIGH"), ("httponly", "MEDIUM")):
            if b[flag] and not c[flag]:
                out.append(
                    Diff(
                        header=f"set-cookie:{name}",
                        kind="cookie",
                        severity=sev,
                        baseline=f"{flag}=True",
                        candidate=f"{flag}=False",
                        message=f"Cookie `{name}` lost the {flag.title()} flag.",
                    )
                )
        if b["samesite"] in ("strict", "lax") and c["samesite"] in (None, "none"):
            out.append(
                Diff(
                    header=f"set-cookie:{name}",
                    kind="cookie",
                    severity="MEDIUM",
                    baseline=f"samesite={b['samesite']}",
                    candidate=f"samesite={c['samesite']}",
                    message=f"Cookie `{name}` SameSite weakened from "
                    f"{b['samesite']} to {c['samesite']}.",
                )
            )


def compare(baseline: Snapshot, candidate: Snapshot) -> List[Diff]:
    """Return the list of security regressions from ``baseline`` to ``candidate``."""
    out: List[Diff] = []

    for header in SECURITY_HEADERS:
        b = baseline.headers.get(header)
        c = candidate.headers.get(header)
        if b is not None and c is None:
            out.append(
                Diff(
                    header=header,
                    kind="removed",
                    severity="HIGH" if header in {
                        "strict-transport-security",
                        "content-security-policy",
                    } else "MEDIUM",
                    baseline=b,
                    candidate=None,
                    message=f"Security header `{header}` present in "
                    f"{baseline.label} but missing in {candidate.label}.",
                )
            )
        elif b is None and c is not None:
            out.append(
                Diff(
                    header=header,
                    kind="added",
                    severity="INFO",
                    baseline=None,
                    candidate=c,
                    message=f"Security header `{header}` added in "
                    f"{candidate.label} (informational).",
                )
            )
        elif b is not None and c is not None and b != c:
            if header == "strict-transport-security":
                _compare_hsts(b, c, out)
            elif header == "access-control-allow-origin":
                _compare_cors(b, c, out)
            elif header == "content-security-policy":
                out.append(
                    Diff(
                        header=header,
                        kind="weakened",
                        severity="MEDIUM",
                        baseline=b,
                        candidate=c,
                        message="Content-Security-Policy changed; review "
                        "manually for loosened directives.",
                    )
                )

    _compare_cookies(baseline, candidate, out)
    out.sort(key=lambda d: d.sort_key())
    return out
