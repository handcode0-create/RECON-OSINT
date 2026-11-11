from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

def write_report(data: dict, out_dir: str | Path, stem: str = "recon") -> tuple[Path, Path]:
    directory = Path(out_dir); directory.mkdir(parents=True, exist_ok=True)
    data.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    jp = directory / f"{stem}.json"
    mp = directory / f"{stem}.md"
    jp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# RECON OSINT V4", "", f"- Profil : `{data.get('profile')}`", f"- Cible : `{data.get('root_domain')}`", f"- Mode : `{data.get('mode')}`", f"- Généré : `{data['generated_at']}`", "", "## Résumé", ""]
    for key, value in (data.get("summary") or {}).items(): lines.append(f"- {key} : **{value}**")
    lines += ["", "## Résultats", "", "```json", json.dumps(data.get("results", {}), ensure_ascii=False, indent=2), "```", ""]
    mp.write_text("\n".join(lines), encoding="utf-8")
    return jp, mp
