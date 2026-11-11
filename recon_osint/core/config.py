from __future__ import annotations
import json
from pathlib import Path
from typing import Any

class ConfigError(ValueError):
    pass

def load_config(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration introuvable: {p}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"JSON invalide ({exc.lineno}:{exc.colno}): {exc.msg}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), dict):
        raise ConfigError("Le fichier doit contenir un objet 'profiles'.")
    return data

def get_profile(config: dict[str, Any], name: str) -> dict[str, Any]:
    try:
        profile = config["profiles"][name]
    except KeyError as exc:
        raise ConfigError(f"Profil inconnu: {name}") from exc
    if not isinstance(profile, dict):
        raise ConfigError(f"Profil invalide: {name}")
    return profile
