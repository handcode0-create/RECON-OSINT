from __future__ import annotations
import argparse
from pathlib import Path
from urllib.parse import urlparse
from .core.config import load_config, get_profile
from .core.scope import validate_target, normalize_host, parse_target_input, is_ip_address, ScopeError
from .core.http_safe import fetch_headers
from .core.report import write_report
from .modules.subdomains import crtsh_passive
from .modules.dns import resolve_dns
from .modules.headers import analyze_headers
from .modules.javascript import analyze_javascript
from .integrations.orchestrator import check_tools, run_pipeline
import json

def _validate_js_base_url(value: str, profile: dict) -> str:
    parsed = urlparse(value)
    if parsed.scheme.lower() not in ({"https"} if profile.get("https_only") else {"http", "https"}):
        raise ScopeError("L'URL de base JS doit respecter le schéma autorisé par le profil.")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ScopeError("URL de base JS invalide ou contenant des identifiants.")
    validate_target(parsed.hostname, profile)
    allowed_port = int(profile.get("target_port", 443))
    effective_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if effective_port != allowed_port:
        raise ScopeError("L'URL de base JS doit rester sur le port de la cible fournie.")
    return value

def build_parser():
    p = argparse.ArgumentParser(prog="recon-osint", description="RECON OSINT V4.2 — scanner universel à cible saisie à chaque exécution")
    p.add_argument("--config", default="config.json")
    p.add_argument("--profile", default="lab", help="Profil d’exécution (lab par défaut ; meesho_root reste verrouillé)")
    p.add_argument("--target", "--domain", dest="target", help="Domaine, URL HTTP(S), IPv4 ou IPv6. Demandé interactivement si absent.")
    p.add_argument("--include-subdomains", action="store_true", help="Inclut les sous-domaines du domaine saisi dans ce lancement.")
    p.add_argument("--allow-private-target", action="store_true", help="Autorise explicitement une IP privée/de laboratoire pour ce lancement.")
    p.add_argument("--out", default="reports")
    p.add_argument("--js", action="append", default=[], help="Fichier JavaScript local à analyser (analyse hors ligne)")
    p.add_argument("--js-base-url", help="URL de base explicite, dans le périmètre, pour résoudre les chemins relatifs du JS")
    p.add_argument("--modules", default="all", help="Liste séparée par virgules: ct,dns,headers,js ou all")
    p.add_argument("--confirm-authorized", action="store_true", help="Confirme que tu es autorisé à lancer les outils externes configurés")
    p.add_argument("--run-integrations", action="store_true", help="Lance uniquement les intégrations explicitement activées dans le profil")
    p.add_argument("--check-tools", action="store_true", help="Vérifie la présence des outils externes sans lancer de scan")
    p.add_argument("--source-dir", help="Dossier de code local à analyser avec Semgrep ou Gitleaks")
    p.add_argument("--semgrep-config", help="Fichier ou dossier local de règles Semgrep")
    return p

def run(args=None):
    ns = build_parser().parse_args(args)
    if ns.check_tools:
        print(json.dumps(check_tools(), ensure_ascii=False, indent=2))
        if not ns.run_integrations:
            return {"tool_checks": check_tools()}

    cfg = load_config(ns.config)
    profile = get_profile(cfg, ns.profile)

    target_value = ns.target or input("Cible (domaine, URL HTTP(S), IPv4 ou IPv6) : ").strip()
    root, seed_url, target_port = parse_target_input(target_value, https_only=bool(profile.get("https_only", False)))

    # Meesho remains tied to its fixed, locked profile. Lab targets are per-run.
    if profile.get("integrations_disabled") is True:
        validate_target(root, profile)
        run_profile = dict(profile)
    else:
        run_profile = dict(profile)
        run_profile["root_domain"] = root
        run_profile["include_subdomains"] = bool(ns.include_subdomains)
        run_profile["target_port"] = target_port
        run_profile["https_only"] = seed_url.lower().startswith("https://")
        run_profile["allow_private_targets"] = bool(ns.allow_private_target)

    if ns.run_integrations and not ns.confirm_authorized:
        answer = input("Confirmez-vous que vous êtes autorisé à tester cette cible et ce périmètre ? (oui/non) : ").strip().lower()
        if answer not in {"oui", "o", "yes", "y"}:
            raise SystemExit("Autorisation non confirmée : aucune intégration réseau lancée.")
        ns.confirm_authorized = True

    js_base_url = _validate_js_base_url(ns.js_base_url, run_profile) if ns.js_base_url else ""
    modules = {x.strip().lower() for x in ns.modules.split(",")}
    if "all" in modules: modules = {"ct", "dns", "headers", "js"}
    unknown = modules - {"ct", "dns", "headers", "js"}
    if unknown: raise SystemExit(f"Modules inconnus: {', '.join(sorted(unknown))}")
    if run_profile.get("mode") == "passive_only":
        modules -= {"dns", "headers"}
    results = {}; discovered = [root]
    if "ct" in modules:
        if is_ip_address(root):
            results["subdomains"] = {"status": "skipped", "reason": "Les certificats CT sont recherchés à partir d'un nom de domaine, pas d'une IP."}
        elif "crtsh" in run_profile.get("allowed_sources", []):
            ct = crtsh_passive(root, limit=int(run_profile.get("max_results", 500)))
            results["subdomains"] = ct; discovered = sorted(set(discovered + ct.get("subdomains", [])))
        else:
            results["subdomains"] = {"status": "skipped", "reason": "crtsh absent de allowed_sources"}
    if "dns" in modules:
        if is_ip_address(root):
            results["dns"] = {"status": "skipped", "reason": "Le module DNS A/AAAA est prévu pour un nom de domaine, pas une IP."}
        elif run_profile.get("dns_enabled") is True and ns.confirm_authorized:
            results["dns"] = [resolve_dns(host) for host in discovered[:int(run_profile.get("max_hosts", 30))]]
        else: results["dns"] = {"status": "skipped", "reason": "dns_enabled et confirmation d'autorisation requis"}
    if "headers" in modules:
        if run_profile.get("active_http_enabled") is True and ns.confirm_authorized and seed_url.lower().startswith("https://") and target_port == 443:
            raw = fetch_headers(root, run_profile, timeout=int(run_profile.get("timeout_seconds", 8)))
            results["headers"] = {"response": raw, "analysis": analyze_headers(raw)}
        else: results["headers"] = {"status": "skipped", "reason": "Ce contrôle HEAD est limité à HTTPS/443 ; utilisez l'intégration HTTPX pour les autres schémas/ports."}
    if "js" in modules:
        local = []
        for filename in ns.js:
            path = Path(filename)
            try: source = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc: local.append({"file": filename, "error": type(exc).__name__}); continue
            local.append({"file": filename, "base_url": js_base_url or None, "analysis": analyze_javascript(source, js_base_url)})
        results["javascript"] = local
    summary = {
        "sous-domaines CT": len(results.get("subdomains", {}).get("subdomains", [])) if isinstance(results.get("subdomains"), dict) else 0,
        "hôtes DNS examinés": len(results.get("dns", [])) if isinstance(results.get("dns"), list) else 0,
        "indicateurs JavaScript": sum(x.get("analysis", {}).get("counts", {}).get("secret_indicators", 0) for x in results.get("javascript", [])),
    }
    report = {"version": "4.2.0", "profile": ns.profile, "target": root, "seed_url": seed_url, "mode": run_profile.get("mode", "unknown"), "modules_requested": sorted(modules), "summary": summary, "results": results,
              "safety": {"no_exploitation": True, "no_fuzzing": True, "javascript_analysis": "local_only", "network_integrations_require_per_run_authorization": True}}
    if ns.run_integrations:
        report["integrations"] = run_pipeline(
            run_profile, root, Path(ns.out) / "integrations",
            confirm_authorized=ns.confirm_authorized,
            source_dir=ns.source_dir,
            semgrep_config=ns.semgrep_config,
            seed_url=seed_url,
        )
    safe_name = root.replace(".", "_").replace(":", "_")
    jp, mp = write_report(report, ns.out, f"{ns.profile}_{safe_name}")
    print(f"[+] JSON : {jp}\n[+] Markdown : {mp}")
    return report

if __name__ == "__main__":
    try: run()
    except (ValueError, ScopeError) as exc: raise SystemExit(f"[!] {exc}")
