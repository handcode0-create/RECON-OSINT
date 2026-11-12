from __future__ import annotations

"""Détection passive de pare-feu applicatif (WAF).

Ce module ne cherche jamais à contourner un WAF : il observe des indices
publics (en-têtes de réponse, cookies, code de statut, bannière de page de
blocage) pour signaler sa présence et, si possible, son éditeur probable.
Une seule requête supplémentaire, avec une chaîne de test générique et
inoffensive, sert uniquement à vérifier si une règle générique se déclenche
sur ce paramètre — aucune tentative d'injection, de payload actif ni de
bypass n'est envoyée. Les résultats sont des indices, pas des certitudes :
à vérifier manuellement avant tout rapport.
"""

import ipaddress
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, build_opener

from ..core.scope import ScopeError, validate_target
from .headers import SECURITY_HEADERS  # noqa: F401  (réutilisé par d'autres rapports)

# Signatures publiques, par éditeur : en-tête/valeur ou cookie observés sur une
# réponse normale. Ce ne sont pas des méthodes de contournement, seulement des
# marqueurs d'identification documentés par les éditeurs eux-mêmes ou visibles
# dans n'importe quel navigateur.
_SIGNATURES: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("Cloudflare", (("header", "cf-ray"), ("header", "server:cloudflare"), ("cookie", "__cfduid"), ("cookie", "cf_clearance"))),
    ("Akamai", (("header", "akamai-ghost"), ("header", "x-akamai-transformed"), ("cookie", "ak_bmsc"))),
    ("AWS WAF / CloudFront", (("header", "x-amzn-requestid"), ("header", "x-amz-cf-id"), ("header", "server:cloudfront"))),
    ("Imperva Incapsula", (("cookie", "incap_ses"), ("cookie", "visid_incap"), ("header", "x-iinfo"))),
    ("Sucuri", (("header", "server:sucuri/cloudproxy"), ("header", "x-sucuri-id"), ("header", "x-sucuri-cache"))),
    ("F5 BIG-IP ASM", (("cookie", "ts="), ("cookie", "bigipserver"), ("header", "x-cnection"))),
    ("Barracuda", (("cookie", "barra_counter_session"),)),
    ("Fortinet FortiWeb", (("header", "fortiwafsid"), ("cookie", "fortiwafsid"))),
    ("Citrix NetScaler AppFirewall", (("cookie", "ns_af="), ("cookie", "citrix_ns_id"))),
    ("Azure Front Door / App Gateway", (("header", "x-azure-ref"), ("header", "x-fd-"))),
    ("ModSecurity (générique)", (("header", "server:mod_security"), ("header", "x-mod-security-message"))),
)

# Chaîne de test générique et inoffensive : un motif commun à des milliers de
# scanners inoffensifs, jamais une charge d'exploitation. Elle ne contient ni
# requête SQL, ni script, ni commande système.
_PROBE_QUERY = "waf_probe_check=1%27%22%3E%3Cscript%3Ealert(1)%3C/script%3E"


def _host_header_value(headers: dict[str, str], name: str) -> str | None:
    return headers.get(name.lower())


def _match_signatures(headers: dict[str, str], cookies: list[str]) -> list[str]:
    hay_headers = {k.lower(): str(v).lower() for k, v in headers.items()}
    hay_cookies = " ; ".join(cookies).lower()
    hits: list[str] = []
    for vendor, markers in _SIGNATURES:
        for kind, needle in markers:
            if kind == "header":
                if ":" in needle:
                    name, value = needle.split(":", 1)
                    if value in hay_headers.get(name, ""):
                        hits.append(vendor)
                        break
                elif needle in hay_headers:
                    hits.append(vendor)
                    break
            elif kind == "cookie" and needle in hay_cookies:
                hits.append(vendor)
                break
    return hits


def _request(url: str, timeout: int) -> dict:
    req = Request(url, headers={"User-Agent": "RECON-OSINT/4.0 (waf-detection, passive)"}, method="GET")
    opener = build_opener()
    try:
        with opener.open(req, timeout=timeout) as response:
            headers = {str(k): str(v) for k, v in response.headers.items()}
            return {"status": response.status, "headers": headers}
    except HTTPError as exc:
        return {"status": exc.code, "headers": {str(k): str(v) for k, v in exc.headers.items()}}
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": "error", "error": type(exc).__name__}


def _assert_resolves_public(host: str, profile: dict) -> None:
    if profile.get("allow_private_targets") is True or profile.get("unrestricted") is True:
        return
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    for item in {entry[4][0] for entry in infos}:
        if not ipaddress.ip_address(item).is_global:
            raise ScopeError(f"Résolution DNS non publique bloquée: {item}")


def detect_waf(seed_url: str, profile: dict, timeout: int = 10) -> dict:
    """Détection passive : une requête normale, puis une requête avec un
    paramètre de test inoffensif, pour voir si une règle générique bloque
    la deuxième sans bloquer la première (signal typique d'un WAF actif).

    Ne lance jamais de payload d'exploitation. Les résultats sont des
    indices d'identification, pas une confirmation ni une méthode de
    contournement.
    """
    parsed = urlsplit(seed_url)
    if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
        return {"status": "skipped", "reason": "URL de cible invalide pour la détection WAF."}
    host = validate_target(parsed.hostname or "", profile)
    if profile.get("active_http_enabled") is not True:
        return {"status": "skipped", "reason": "active_http_enabled=false"}
    try:
        _assert_resolves_public(host, profile)
    except ScopeError as exc:
        return {"status": "skipped", "reason": str(exc)}

    baseline = _request(seed_url, timeout)
    probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", _PROBE_QUERY, ""))
    probed = _request(probe_url, timeout)

    base_headers = baseline.get("headers") or {}
    probe_headers = probed.get("headers") or {}
    base_cookies = [v for k, v in base_headers.items() if k.lower() == "set-cookie"]
    probe_cookies = [v for k, v in probe_headers.items() if k.lower() == "set-cookie"]

    vendors = sorted(set(_match_signatures(base_headers, base_cookies) + _match_signatures(probe_headers, probe_cookies)))

    behavior_flag = False
    reason = None
    if isinstance(baseline.get("status"), int) and isinstance(probed.get("status"), int):
        if baseline["status"] < 400 <= probed["status"] and probed["status"] in (403, 406, 419, 429, 503):
            behavior_flag = True
            reason = f"Requête normale acceptée ({baseline['status']}) mais la requête-test a été bloquée ({probed['status']})."

    present = bool(vendors) or behavior_flag
    return {
        "host": host,
        "status": "ok",
        "waf_detected": present,
        "likely_vendors": vendors or (["Inconnu / générique"] if behavior_flag else []),
        "evidence": {
            "baseline_status": baseline.get("status"),
            "probe_status": probed.get("status"),
            "behavioral_signal": reason,
            "signature_hits": vendors,
        },
        "note": "Indice de détection, pas une confirmation. Aucun payload d'exploitation n'a été envoyé ; seule une chaîne de test générique a été utilisée pour observer le comportement du filtre.",
    }
