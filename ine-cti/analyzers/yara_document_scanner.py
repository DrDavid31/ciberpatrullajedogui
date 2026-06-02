# -*- coding: utf-8 -*-
"""
Escaner YARA para documentos/rutas locales autorizadas.
Usa yara-python si esta disponible; si no, intenta usar el binario `yara`.
"""

import json
import shutil
import subprocess
from pathlib import Path


def _iter_targets(target_path, recursive=True, max_files=200):
    root = Path(str(target_path or "")).expanduser()
    if not root.exists():
        raise ValueError("Configura una ruta valida de documentos")
    if root.is_file():
        return [root]
    pattern = "**/*" if recursive else "*"
    files = [p for p in root.glob(pattern) if p.is_file()]
    return files[: int(max_files or 200)]


def scan_with_python_yara(rules_path, target_path, recursive=True, max_files=200):
    try:
        import yara
    except ImportError as exc:
        raise RuntimeError("yara-python no esta instalado") from exc
    rules = yara.compile(filepath=str(Path(rules_path).expanduser()))
    matches = []
    for path in _iter_targets(target_path, recursive, max_files):
        for match in rules.match(str(path)):
            matches.append({
                "file": str(path),
                "rule": str(match.rule),
                "namespace": str(match.namespace),
                "tags": list(match.tags),
                "meta": dict(match.meta),
            })
    return matches


def scan_with_binary(rules_path, target_path, recursive=True):
    if not shutil.which("yara"):
        raise RuntimeError("No se encontro yara-python ni binario yara en PATH")
    cmd = ["yara"]
    if recursive:
        cmd.append("-r")
    cmd += [str(Path(rules_path).expanduser()), str(Path(target_path).expanduser())]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240, encoding="utf-8", errors="replace")
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr[:220])
    matches = []
    for line in proc.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            matches.append({"rule": parts[0], "file": parts[1], "tags": [], "meta": {}})
    return matches


def scan_documents(rules_path, target_path, recursive=True, max_files=200):
    if not str(rules_path or "").strip():
        raise ValueError("Configura ruta a reglas YARA")
    if not str(target_path or "").strip():
        raise ValueError("Configura ruta de documentos")
    try:
        matches = scan_with_python_yara(rules_path, target_path, recursive, max_files)
        engine = "yara-python"
    except Exception:
        matches = scan_with_binary(rules_path, target_path, recursive)
        engine = "yara"
    return {"status": "ok", "engine": engine, "matches": matches, "count": len(matches)}


def test_scanner(rules_path):
    rules_path = Path(str(rules_path or "")).expanduser()
    if not rules_path.exists():
        raise ValueError("Configura ruta valida a reglas YARA")
    if shutil.which("yara"):
        return {"status": "ok", "message": "Binario yara disponible"}
    try:
        import yara  # noqa: F401
        return {"status": "ok", "message": "yara-python disponible"}
    except ImportError:
        raise RuntimeError("Instala yara-python o el binario yara")
