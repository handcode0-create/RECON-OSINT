from __future__ import annotations
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from ..core.scope import normalize_host

def crtsh_passive(root: str, limit: int = 500, timeout: int = 12) -> dict:
    """Passive Certificate Transparency lookup. Requires explicit profile opt-in."""
    root = normalize_host(root)
    url = f"https://crt.sh/?q=%25.{root}&output=json"
    req = Request(url, headers={"User-Agent": "RECON-OSINT/4.0 (passive asset inventory)"})
    try:
        with urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read(5_000_000).decode("utf-8", "replace"))
        names = set()
        for row in payload if isinstance(payload, list) else []:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if name == root or name.endswith("." + root):
                    names.add(name)
        return {"source": "crt.sh", "status": "ok", "root": root, "subdomains": sorted(names)[:limit], "count": min(len(names), limit)}
    except (URLError, HTTPError, TimeoutError, OSError, ValueError) as exc:
        return {"source": "crt.sh", "status": "error", "root": root, "error": type(exc).__name__, "subdomains": []}
