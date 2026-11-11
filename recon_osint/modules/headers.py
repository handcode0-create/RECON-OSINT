SECURITY_HEADERS = {
    "strict-transport-security": "HSTS absent",
    "content-security-policy": "CSP absent",
    "x-content-type-options": "X-Content-Type-Options absent",
    "referrer-policy": "Referrer-Policy absent",
    "permissions-policy": "Permissions-Policy absent",
}

def analyze_headers(response: dict) -> dict:
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    findings = []
    for name, message in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append({"id": f"missing-{name}", "severity": "low", "title": message, "evidence": "Header non observé dans la réponse."})
    server = headers.get("server")
    if server:
        findings.append({"id": "server-banner", "severity": "info", "title": "Bannière serveur exposée", "evidence": server[:200]})
    return {"host": response.get("host"), "findings": findings, "count": len(findings)}
