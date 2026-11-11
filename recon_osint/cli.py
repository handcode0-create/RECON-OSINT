from __future__ import annotations
import argparse
from pathlib import Path
from .core.config import load_config, get_profile
from .core.scope import validate_target, normalize_host, ScopeError
from .core.http_safe import fetch_headers
from .core.report import write_report
from .modules.subdomains import crtsh_passive
from .modules.dns import resolve_dns
from .modules.headers import analyze_headers
from .modules.javascript import analyze_javascript

def build_parser():
    p = argparse.ArgumentParser(prog="recon-osint", description="RECON OSINT V4 — reconnaissance encadrée et analyse locale")
    p.add_argument("--config", default="config.json")
    p.add_argument("--profile", required=True)
    p.add_argument("--domain", help="Cible dans le périmètre du profil")
    p.add_argument("--out", default="reports")
    p.add_argument("--js", action="append", default=[], help="Fichier JavaScript local à analyser (analyse hors ligne)")
    p.add_argument("--modules", default="all", help="Liste séparée par virgules: ct,dns,headers,js ou all")
    p.add_argument("--confirm-authorized", action="store_true", help="Confirme que tu es autorisé à effectuer les requêtes actives configurées")
    return p

def run(args=None):
    ns = build_parser().parse_args(args)
    cfg = load_config(ns.config); profile = get_profile(cfg, ns.profile)
    root = normalize_host(ns.domain or profile.get("root_domain", ""))
    validate_target(root, profile)
    modules = {x.strip().lower() for x in ns.modules.split(",")}
    if "all" in modules: modules = {"ct", "dns", "headers", "js"}
    unknown = modules - {"ct", "dns", "headers", "js"}
    if unknown: raise SystemExit(f"Modules inconnus: {', '.join(sorted(unknown))}")
    if profile.get("mode") == "passive_only":
        modules -= {"dns", "headers"}
    results = {}; discovered = [root]
    if "ct" in modules:
        if "crtsh" in profile.get("allowed_sources", []):
            ct = crtsh_passive(root, limit=int(profile.get("max_results", 500)))
            results["subdomains"] = ct; discovered = sorted(set(discovered + ct.get("subdomains", [])))
        else:
            results["subdomains"] = {"status": "skipped", "reason": "crtsh absent de allowed_sources"}
    if "dns" in modules:
        if profile.get("dns_enabled") is True and ns.confirm_authorized:
            results["dns"] = [resolve_dns(host) for host in discovered[:int(profile.get("max_hosts", 30))]]
        else: results["dns"] = {"status": "skipped", "reason": "dns_enabled et --confirm-authorized requis"}
    if "headers" in modules:
        if profile.get("active_http_enabled") is True and ns.confirm_authorized:
            raw = fetch_headers(root, profile, timeout=int(profile.get("timeout_seconds", 8)))
            results["headers"] = {"response": raw, "analysis": analyze_headers(raw)}
        else: results["headers"] = {"status": "skipped", "reason": "active_http_enabled et --confirm-authorized requis"}
    if "js" in modules:
        local = []
        for filename in ns.js:
            path = Path(filename)
            try: source = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc: local.append({"file": filename, "error": type(exc).__name__}); continue
            local.append({"file": filename, "analysis": analyze_javascript(source, f"https://{root}/")})
        results["javascript"] = local
    summary = {
        "sous-domaines CT": len(results.get("subdomains", {}).get("subdomains", [])) if isinstance(results.get("subdomains"), dict) else 0,
        "hôtes DNS examinés": len(results.get("dns", [])) if isinstance(results.get("dns"), list) else 0,
        "indicateurs JavaScript": sum(x.get("analysis", {}).get("counts", {}).get("secret_indicators", 0) for x in results.get("javascript", [])),
    }
    report = {"version": "4.0.0", "profile": ns.profile, "root_domain": root, "mode": profile.get("mode", "unknown"), "modules_requested": sorted(modules), "summary": summary, "results": results,
              "safety": {"no_exploitation": True, "no_fuzzing": True, "javascript_analysis": "local_only", "http_headers": "single root HEAD only when explicitly enabled and confirmed"}}
    jp, mp = write_report(report, ns.out, f"{ns.profile}_{root.replace('.', '_')}")
    print(f"[+] JSON : {jp}\n[+] Markdown : {mp}")
    return report

if __name__ == "__main__":
    try: run()
    except (ValueError, ScopeError) as exc: raise SystemExit(f"[!] {exc}")
