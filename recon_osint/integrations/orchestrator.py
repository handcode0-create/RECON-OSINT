from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

from ..core.scope import validate_target, ScopeError

SUPPORTED_TOOLS = ("subfinder", "gau", "dnsx", "httpx", "katana", "semgrep")
ACTIVE_TOOLS = {"dnsx", "httpx", "katana"}
PASSIVE_TOOLS = {"subfinder", "gau"}

def check_tools() -> dict[str, dict[str, str]]:
    """Return executable availability without running any scan."""
    found = {}
    for name in SUPPORTED_TOOLS:
        path = shutil.which(name)
        found[name] = {"status": "installed" if path else "missing", "path": path or ""}
    return found

def _lines(text: str, limit: int) -> list[str]:
    out = []
    seen = set()
    for raw in text.splitlines():
        value = raw.strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
        if len(out) >= limit:
            break
    return out

def _jsonl(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows

def _execute(tool: str, args: list[str], out_dir: Path, timeout: int) -> dict[str, Any]:
    binary = shutil.which(tool)
    if not binary:
        return {"tool": tool, "status": "missing", "reason": f"Exécutable introuvable dans PATH: {tool}"}
    try:
        completed = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"tool": tool, "status": "timeout", "timeout_seconds": timeout}
    except OSError as exc:
        return {"tool": tool, "status": "error", "reason": type(exc).__name__}

    output_file = out_dir / f"{tool}.txt"
    output_file.write_text(completed.stdout or "", encoding="utf-8")
    error_file = out_dir / f"{tool}.stderr.txt"
    if completed.stderr:
        error_file.write_text(completed.stderr[-12000:], encoding="utf-8")
    return {
        "tool": tool,
        "status": "ok" if completed.returncode == 0 else "completed_with_errors",
        "exit_code": completed.returncode,
        "output_file": str(output_file),
        "stderr_file": str(error_file) if completed.stderr else None,
        "stdout": completed.stdout,
    }

def _host_from_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        return parsed.hostname
    except ValueError:
        return None

def _scope_filter_hosts(values: list[str], profile: dict, limit: int) -> list[str]:
    accepted = set()
    for value in values:
        try:
            accepted.add(validate_target(value, profile))
        except ScopeError:
            continue
        if len(accepted) >= limit:
            break
    return sorted(accepted)

def _scope_filter_urls(values: list[str], profile: dict, limit: int) -> list[str]:
    accepted = []
    seen = set()
    for value in values:
        host = _host_from_url(value)
        if not host:
            continue
        try:
            validate_target(host, profile)
        except ScopeError:
            continue
        if value not in seen:
            seen.add(value)
            accepted.append(value)
        if len(accepted) >= limit:
            break
    return accepted

def run_pipeline(
    profile: dict,
    target: str,
    out_dir: str | Path,
    confirm_authorized: bool = False,
    source_dir: str | Path | None = None,
    semgrep_config: str | Path | None = None,
) -> dict[str, Any]:
    """Run only explicitly enabled adapters, with strict scope and low-rate defaults."""
    root = validate_target(target, profile)
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    enabled = set(profile.get("enabled_tools", []))
    unknown = enabled - set(SUPPORTED_TOOLS)
    if unknown:
        raise ValueError("Outils inconnus dans enabled_tools: " + ", ".join(sorted(unknown)))

    report: dict[str, Any] = {
        "target": root,
        "mode": profile.get("mode", "unknown"),
        "enabled_tools": sorted(enabled),
        "tool_checks": check_tools(),
        "stages": {},
        "scope_filtered": {"hosts": [], "urls": []},
        "policy": {
            "active_confirmation_received": bool(confirm_authorized),
            "active_tools_require_confirmation": True,
            "max_rate": "1 request/second for HTTP crawler/prober defaults",
        },
    }

    def skipped(name: str, reason: str) -> None:
        report["stages"][name] = {"tool": name, "status": "skipped", "reason": reason}

    hosts = [root]
    # Passive source collection is opt-in per profile, with no target HTTP requests.
    if "subfinder" in enabled:
        result = _execute("subfinder", ["-d", root, "-silent", "-max-time", "3", "-timeout", "10"], directory, 75)
        stdout = result.pop("stdout", "")
        names = _scope_filter_hosts(_lines(stdout, int(profile.get("max_results", 100))), profile, int(profile.get("max_hosts", 50)))
        result["count"] = len(names)
        result["hosts_file"] = str(directory / "subfinder-hosts.txt")
        (directory / "subfinder-hosts.txt").write_text("\n".join(names), encoding="utf-8")
        report["stages"]["subfinder"] = result
        hosts = sorted(set(hosts + names))
    elif "subfinder" not in enabled:
        skipped("subfinder", "subfinder absent de profile.enabled_tools")

    if "gau" in enabled:
        providers = profile.get("gau_providers", ["wayback"])
        if not providers or not all(p in {"wayback", "commoncrawl", "otx", "urlscan"} for p in providers):
            skipped("gau", "Liste gau_providers invalide.")
        else:
            args = ["--threads", "1", "--timeout", "10", "--retries", "0", "--providers", ",".join(providers), root]
            if profile.get("include_subdomains") is True:
                args.insert(-1, "--subs")
            result = _execute("gau", args, directory, 90)
            stdout = result.pop("stdout", "")
            urls = _scope_filter_urls(_lines(stdout, int(profile.get("max_urls", 500))), profile, int(profile.get("max_urls", 500)))
            result["count"] = len(urls)
            result["urls_file"] = str(directory / "gau-urls.txt")
            (directory / "gau-urls.txt").write_text("\n".join(urls), encoding="utf-8")
            report["stages"]["gau"] = result
            report["scope_filtered"]["urls"] = urls
    else:
        skipped("gau", "gau absent de profile.enabled_tools")

    active_allowed = profile.get("mode") != "passive_only" and confirm_authorized
    if "dnsx" in enabled:
        if not active_allowed or profile.get("dns_enabled") is not True:
            skipped("dnsx", "Requiert mode non passif, dns_enabled=true et --confirm-authorized.")
        else:
            host_file = directory / "dns-input.txt"
            host_file.write_text("\n".join(hosts[:int(profile.get("max_hosts", 50))]), encoding="utf-8")
            args = ["-l", str(host_file), "-a", "-aaaa", "-cname", "-j", "-silent", "-t", "1", "-rl", "1"]
            result = _execute("dnsx", args, directory, 60)
            stdout = result.pop("stdout", "")
            rows = _jsonl(stdout)
            result["records"] = rows[:int(profile.get("max_results", 100))]
            result["count"] = len(rows)
            report["stages"]["dnsx"] = result
    else:
        skipped("dnsx", "dnsx absent de profile.enabled_tools")

    alive_urls: list[str] = []
    if "httpx" in enabled:
        if not active_allowed or profile.get("active_http_enabled") is not True:
            skipped("httpx", "Requiert mode non passif, active_http_enabled=true et --confirm-authorized.")
        else:
            host_file = directory / "httpx-input.txt"
            host_file.write_text("\n".join(hosts[:int(profile.get("max_hosts", 20))]), encoding="utf-8")
            args = [
                "-l", str(host_file), "-json", "-silent", "-sc", "-title", "-td", "-server", "-ip", "-cname",
                "-rl", "1", "-threads", "1", "-timeout", "5", "-retries", "0", "-no-fallback",
            ]
            result = _execute("httpx", args, directory, int(profile.get("httpx_timeout_seconds", 120)))
            stdout = result.pop("stdout", "")
            rows = _jsonl(stdout)
            for row in rows:
                url = row.get("url")
                if isinstance(url, str):
                    alive_urls.append(url)
            alive_urls = _scope_filter_urls(alive_urls, profile, int(profile.get("max_web_targets", 5)))
            result["records"] = rows[:int(profile.get("max_results", 100))]
            result["count"] = len(rows)
            result["in_scope_urls"] = alive_urls
            report["stages"]["httpx"] = result
    else:
        skipped("httpx", "httpx absent de profile.enabled_tools")

    if "katana" in enabled:
        if not active_allowed or profile.get("active_crawl_enabled") is not True:
            skipped("katana", "Requiert mode non passif, active_crawl_enabled=true et --confirm-authorized.")
        elif not alive_urls:
            skipped("katana", "Aucune URL HTTP(S) validée fournie par httpx.")
        else:
            url_file = directory / "katana-input.txt"
            url_file.write_text("\n".join(alive_urls), encoding="utf-8")
            args = [
                "-list", str(url_file), "-jsonl", "-silent", "-d", "2", "-c", "1", "-p", "1",
                "-rl", "1", "-rlm", "30", "-jc", "-fs", "fqdn", "-ct", "30s",
            ]
            result = _execute("katana", args, directory, int(profile.get("katana_timeout_seconds", 90)))
            stdout = result.pop("stdout", "")
            rows = _jsonl(stdout)
            report["stages"]["katana"] = {**result, "count": len(rows), "records": rows[:int(profile.get("max_results", 100))]}
    else:
        skipped("katana", "katana absent de profile.enabled_tools")

    if "semgrep" in enabled:
        if not source_dir:
            skipped("semgrep", "Fournir --source-dir pour analyser du code local.")
        elif not semgrep_config:
            skipped("semgrep", "Fournir --semgrep-config avec un fichier de règles local.")
        else:
            path = Path(source_dir).resolve()
            rules = Path(semgrep_config).resolve()
            if not path.is_dir() or not rules.is_file():
                skipped("semgrep", "Le dossier source ou le fichier de règles local est introuvable.")
            else:
                report_path = directory / "semgrep.json"
                args = ["scan", "--config", str(rules), "--json", "--output", str(report_path), str(path)]
                result = _execute("semgrep", args, directory, int(profile.get("semgrep_timeout_seconds", 180)))
                # Semgrep writes its JSON report to --output; stdout is not the findings payload.
                try:
                    payload = json.loads(report_path.read_text(encoding="utf-8"))
                    result["findings_count"] = len(payload.get("results", []))
                    result["report_file"] = str(report_path)
                except (OSError, json.JSONDecodeError):
                    result["findings_count"] = None
                result.pop("stdout", None)
                report["stages"]["semgrep"] = result
    else:
        skipped("semgrep", "semgrep absent de profile.enabled_tools")

    report["scope_filtered"]["hosts"] = hosts
    report["summary"] = {
        "hosts_in_scope": len(hosts),
        "archived_urls": len(report.get("scope_filtered", {}).get("urls", [])),
        "live_web_urls": len(alive_urls),
        "semgrep_findings": report.get("stages", {}).get("semgrep", {}).get("findings_count"),
    }
    return report
