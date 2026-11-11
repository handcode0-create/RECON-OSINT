from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse


class ScopeError(ValueError):
    pass


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\\.?$")


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_host(value: str) -> str:
    """Normalize a hostname or IP literal; URL inputs are accepted as well."""
    raw = str(value).strip()
    if not raw:
        raise ScopeError("Cible vide.")

    # urlparse needs brackets around a bare IPv6 literal.
    candidate = raw
    if "://" not in candidate and candidate.count(":") > 1 and not candidate.startswith("["):
        candidate = f"[{candidate}]"
    parsed = urlparse(candidate if "://" in candidate or candidate.startswith("//") else f"//{candidate}")
    if parsed.username or parsed.password:
        raise ScopeError("Les URL avec identifiants intégrés sont refusées.")
    try:
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError as exc:
        raise ScopeError("Cible ou port invalide.") from exc
    if not host:
        raise ScopeError(f"Nom d'hôte invalide: {value!r}")
    if port not in (None, 80, 443):
        raise ScopeError("Seuls les ports HTTP/HTTPS standards (80 et 443) sont acceptés.")

    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        if not _HOST_RE.fullmatch(host):
            raise ScopeError(f"Nom d'hôte invalide: {value!r}")
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeError(f"Nom d'hôte invalide: {value!r}") from exc


def parse_target_input(value: str, *, https_only: bool = True) -> tuple[str, str]:
    """Return (normalized host/IP, safe seed URL). Query and fragment are omitted."""
    raw = str(value).strip()
    if not raw:
        raise ScopeError("Cible vide.")

    candidate = raw
    if "://" not in candidate and candidate.count(":") > 1 and not candidate.startswith("["):
        candidate = f"[{candidate}]"
    parsed = urlparse(candidate if "://" in candidate or candidate.startswith("//") else f"//{candidate}")

    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ScopeError("Seules les URL HTTP et HTTPS sont acceptées.")
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    if https_only and scheme != "https":
        raise ScopeError("Ce profil impose HTTPS : indique une URL https://.")
    if parsed.username or parsed.password:
        raise ScopeError("Les URL avec identifiants intégrés sont refusées.")
    try:
        port = parsed.port
        raw_host = parsed.hostname or ""
    except ValueError as exc:
        raise ScopeError("Cible ou port invalide.") from exc
    if port not in (None, 80, 443):
        raise ScopeError("Seuls les ports HTTP/HTTPS standards (80 et 443) sont acceptés.")

    host = normalize_host(raw_host)
    netloc_host = f"[{host}]" if ":" in host else host
    netloc = f"{netloc_host}:{port}" if port else netloc_host
    path = parsed.path or "/"
    # Do not carry query strings/fragments into scan inputs or reports.
    seed_url = urlunparse((scheme, netloc, path, "", "", ""))
    return host, seed_url


def validate_target(target: str, profile: dict) -> str:
    root = normalize_host(str(profile.get("root_domain", "")))
    host = normalize_host(str(target))

    root_is_ip = is_ip_address(root)
    host_is_ip = is_ip_address(host)
    if root_is_ip or host_is_ip:
        if root_is_ip and host_is_ip and host == root:
            return host
        raise ScopeError(f"Hors périmètre: {host}. Une cible IP est limitée à cette adresse exacte: {root}.")

    if host != root and not (profile.get("include_subdomains") is True and host.endswith("." + root)):
        raise ScopeError(
            f"Hors périmètre: {host}. Racine autorisée: {root}; "
            f"sous-domaines: {bool(profile.get('include_subdomains'))}."
        )
    return host


def is_in_scope(host: str, profile: dict) -> bool:
    try:
        validate_target(host, profile)
        return True
    except ScopeError:
        return False
