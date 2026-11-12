from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, build_opener, Request
from urllib.error import URLError, HTTPError
from .scope import validate_target, ScopeError

def _assert_public_resolution(host: str, profile: dict | None = None) -> None:
    """Reject private, loopback, link-local and otherwise non-global resolutions."""
    if profile and (profile.get("allow_private_targets") is True or profile.get("unrestricted") is True):
        return
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = {item[4][0] for item in infos}
    if not addresses:
        raise OSError("Aucune adresse DNS exploitable.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ScopeError(f"Résolution DNS non publique bloquée: {address}")

class _ScopedRedirect(HTTPRedirectHandler):
    def __init__(self, profile):
        self.profile = profile

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if self.profile.get("unrestricted") is not True and (parsed.scheme.lower() != "https" or parsed.port not in (None, 443) or parsed.username or parsed.password):
            raise ScopeError("Redirection bloquée: HTTPS standard obligatoire.")
        host = validate_target(parsed.hostname or "", self.profile)
        _assert_public_resolution(host, self.profile)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch_headers(host: str, profile: dict, timeout: int = 8) -> dict:
    """One HEAD request to /; redirects must remain HTTPS and in scope."""
    host = validate_target(host, profile)
    if profile.get("active_http_enabled") is not True:
        return {"host": host, "status": "skipped", "reason": "active_http_enabled=false"}
    try:
        _assert_public_resolution(host, profile)
        url = f"https://{host}/"
        req = Request(url, headers={"User-Agent": "RECON-OSINT/4.0 (+authorized-security-inventory)"}, method="HEAD")
        opener = build_opener(_ScopedRedirect(profile))
        with opener.open(req, timeout=timeout) as response:
            return {"host": host, "url": url, "status": response.status, "headers": dict(response.headers.items()), "method": "HEAD"}
    except HTTPError as exc:
        return {"host": host, "url": f"https://{host}/", "status": exc.code, "headers": dict(exc.headers.items()), "method": "HEAD", "error": "HTTP response error"}
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"host": host, "url": f"https://{host}/", "status": "error", "error": type(exc).__name__}
