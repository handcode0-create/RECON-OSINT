from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse

class ScopeError(ValueError):
    pass

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$")

def normalize_host(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ScopeError("Domaine vide.")
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    if parsed.username or parsed.password:
        raise ScopeError("Les URL avec identifiants intégrés sont refusées.")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host or not _HOST_RE.fullmatch(host):
        raise ScopeError(f"Nom d'hôte invalide: {value!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ScopeError("Les adresses IP ne sont pas acceptées comme domaine racine.")
    return host.encode("idna").decode("ascii")

def validate_target(target: str, profile: dict) -> str:
    root = normalize_host(str(profile.get("root_domain", "")))
    host = normalize_host(target)
    if host != root and not (profile.get("include_subdomains") is True and host.endswith("." + root)):
        raise ScopeError(f"Hors périmètre: {host}. Racine autorisée: {root}; sous-domaines: {bool(profile.get('include_subdomains'))}.")
    return host

def is_in_scope(host: str, profile: dict) -> bool:
    try:
        validate_target(host, profile)
        return True
    except ScopeError:
        return False
