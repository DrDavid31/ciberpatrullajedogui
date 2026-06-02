# -*- coding: utf-8 -*-
"""
Cliente/analizador simple para reglas Sigma.
Valida y lista metadatos de reglas YAML sin depender obligatoriamente de pySigma.
"""

from pathlib import Path


def _load_yaml(path):
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("Instala PyYAML o ejecuta pip install -r requirements.txt") from exc
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return yaml.safe_load(fh) or {}


def load_rules(rules_path, limit=50):
    root = Path(str(rules_path or "")).expanduser()
    if not root.exists():
        raise ValueError("Configura una ruta valida al repositorio/reglas Sigma")
    files = [root] if root.is_file() else list(root.rglob("*.yml")) + list(root.rglob("*.yaml"))
    rules = []
    errors = []
    for path in files[: int(limit or 50)]:
        try:
            data = _load_yaml(path)
            rules.append({
                "path": str(path),
                "title": data.get("title") or path.stem,
                "id": data.get("id", ""),
                "status": data.get("status", ""),
                "level": data.get("level", ""),
                "description": data.get("description", ""),
                "logsource": data.get("logsource", {}),
            })
        except Exception as exc:
            errors.append({"path": str(path), "error": str(exc)})
    return {"status": "ok", "rules": rules, "errors": errors, "count": len(rules)}


def test_rules(rules_path, limit=5):
    data = load_rules(rules_path, limit)
    return {
        "status": "ok",
        "message": "Reglas Sigma cargadas",
        "count": data["count"],
        "errors": len(data["errors"]),
    }
