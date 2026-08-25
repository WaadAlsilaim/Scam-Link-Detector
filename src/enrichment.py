"""
Optional live enrichment checks, run only at prediction time (never during training,
so the core model stays fast/offline). Each check is defensive: if it fails or times
out, it returns None rather than raising, so a network hiccup never breaks a request.

In this sandbox, outbound network is restricted to a small allowlist (pypi, npm,
github, etc.) so WHOIS/SSL/Safe-Browsing calls will not actually reach real hosts.
Wire these up to real services when you deploy outside the sandbox:
  - domain age: python-whois or a WHOIS API
  - SSL: ssl.get_server_certificate((host, 443))
  - reputation: Google Safe Browsing API / VirusTotal API (needs an API key)
"""
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional


def check_ssl(host: str, timeout: float = 3.0) -> Optional[dict]:
    """Returns basic cert info, or None if unreachable/no cert."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return {
            "valid": True,
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "expires": not_after.isoformat(),
            "expired": not_after < datetime.now(timezone.utc),
        }
    except Exception:
        return None


def check_domain_age_days(domain: str) -> Optional[int]:
    """Stub -- plug in python-whois or a WHOIS API in production.
    Returns None here since outbound WHOIS isn't reachable from this sandbox."""
    try:
        import whois  # python-whois, not installed in the sandbox by default
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None


def check_safe_browsing(url: str, api_key: Optional[str] = None) -> Optional[bool]:
    """Stub for Google Safe Browsing lookup API. Returns True if flagged, False if
    clean, None if the check couldn't run (no API key / no network)."""
    if not api_key:
        return None
    try:
        import requests
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "scam-link-detector", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=3,
        )
        return bool(resp.json().get("matches"))
    except Exception:
        return None


def enrich(url: str, host: str, safe_browsing_api_key: Optional[str] = None) -> dict:
    return {
        "ssl": check_ssl(host),
        "domain_age_days": check_domain_age_days(host),
        "flagged_by_safe_browsing": check_safe_browsing(url, safe_browsing_api_key),
    }
