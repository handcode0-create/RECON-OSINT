from __future__ import annotations
import socket

def resolve_dns(host: str) -> dict:
    """Resolve A/AAAA using the OS resolver; only for authorized targets."""
    result = {"host": host, "A": [], "AAAA": [], "status": "ok"}
    for family, key in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
            result[key] = sorted({item[4][0] for item in infos})
        except socket.gaierror:
            result[key] = []
        except OSError as exc:
            result.update(status="error", error=type(exc).__name__)
    return result
