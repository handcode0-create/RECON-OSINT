from __future__ import annotations
from urllib.request import HTTPRedirectHandler, build_opener, Request
from urllib.error import URLError, HTTPError
from .scope import validate_target

class _ScopedRedirect(HTTPRedirectHandler):
    def __init__(self, profile):
        self.profile = profile
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse
        host = urlparse(newurl).hostname or ""
        validate_target(host, self.profile)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch_headers(host: str, profile: dict, timeout: int = 8) -> dict:
    """One GET to / for headers only; redirects are restricted to the same scope."""
    host = validate_target(host, profile)
    if profile.get("active_http_enabled") is not True:
        return {"host": host, "status": "skipped", "reason": "active_http_enabled=false"}
    url = f"https://{host}/"
    req = Request(url, headers={"User-Agent": "RECON-OSINT/4.0 (+authorized-security-inventory)"}, method="GET")
    opener = build_opener(_ScopedRedirect(profile))
    try:
        with opener.open(req, timeout=timeout) as response:
            return {"host": host, "url": url, "status": response.status, "headers": dict(response.headers.items())}
    except HTTPError as exc:
        return {"host": host, "url": url, "status": exc.code, "headers": dict(exc.headers.items()), "error": "HTTP response error"}
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"host": host, "url": url, "status": "error", "error": type(exc).__name__}
