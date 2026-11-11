from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse

URL_RE = re.compile(r'''["'`]((?:https?://[^"'`\s<>]+)|(?:/[A-Za-z0-9_./?=&%${}-]*))["'`]''')
PARAM_RE = re.compile(r"(?:[?&])([A-Za-z_][A-Za-z0-9_.-]{0,80})=")
SECRET_PATTERNS = {
    "private_key_marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_token_assignment": re.compile(r"""(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_./+=-]{16,}['"]"""),
}

def analyze_javascript(source: str, base_url: str = "") -> dict:
    """Offline-only static extraction; values are never used as credentials."""
    endpoints = set()
    for match in URL_RE.finditer(source):
        raw = match.group(1)
        if raw.startswith("/") and base_url:
            candidate = urljoin(base_url, raw)
        else:
            candidate = raw
        parsed = urlparse(candidate)
        if parsed.scheme in ("http", "https") or (raw.startswith("/") and not parsed.scheme):
            endpoints.add(candidate[:1000])
    params = sorted(set(PARAM_RE.findall(source)))
    indicators = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(source):
            indicators.append({"type": name, "offset": match.start(), "note": "Indice à examiner manuellement; aucune valeur secrète n'est reproduite."})
    return {"endpoints": sorted(endpoints), "parameters": params, "secret_indicators": indicators,
            "counts": {"endpoints": len(endpoints), "parameters": len(params), "secret_indicators": len(indicators)}}
