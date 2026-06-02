# -*- coding: utf-8 -*-
"""
Wrappers defensivos para ProjectDiscovery: subfinder, httpx, naabu y nuclei.
Requiere instalar los binarios y tenerlos en PATH.
"""

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime


PD_TIMEOUT = 240


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def _missing(tool):
    return [{
        "source": tool,
        "source_id": tool,
        "title": f"{tool} no instalado",
        "url": f"https://github.com/projectdiscovery/{tool}",
        "category": "Sistema",
        "category_class": "cat-repo",
        "risk": "BAJO",
        "risk_class": "risk-low",
        "detail": f"Instala {tool} y asegúrate de que esté en PATH",
        "detected": _ts(),
        "is_system": True,
        "is_negative": True,
    }]


def _run(cmd, timeout=PD_TIMEOUT, input_text=None):
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )


def _json_lines(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            yield {"raw": line}


def scan_subfinder(domain, limit=50, timeout=PD_TIMEOUT):
    if not shutil.which("subfinder"):
        return _missing("subfinder")
    domain = str(domain or "").strip()
    if not domain:
        return []
    proc = _run(["subfinder", "-d", domain, "-silent", "-oJ"], int(timeout or PD_TIMEOUT))
    findings = []
    for item in _json_lines(proc.stdout):
        host = item.get("host") or item.get("raw")
        if not host:
            continue
        findings.append({
            "source": "subfinder",
            "source_id": "subfinder",
            "title": f"Subdominio detectado: {host}",
            "url": f"https://{host}",
            "category": "Superficie Expuesta",
            "category_class": "cat-repo",
            "risk": "MEDIO",
            "risk_class": "risk-medium",
            "detail": f"Fuente: {item.get('source', 'passive')}",
            "detected": _ts(),
            "is_dork": False,
        })
        if len(findings) >= int(limit or 50):
            break
    if not findings and proc.stderr:
        return [_tool_notice("subfinder", proc.stderr)]
    return findings


def scan_httpx(target, limit=50, timeout=PD_TIMEOUT):
    if not shutil.which("httpx"):
        return _missing("httpx")
    target = str(target or "").strip()
    if not target:
        return []
    proc = _run(["httpx", "-u", target, "-json", "-silent"], int(timeout or PD_TIMEOUT))
    findings = []
    for item in _json_lines(proc.stdout):
        url = item.get("url") or item.get("input") or item.get("raw")
        if not url:
            continue
        status = item.get("status_code") or item.get("status-code") or ""
        title = item.get("title") or url
        tech = item.get("tech") or item.get("webserver") or ""
        findings.append({
            "source": "httpx",
            "source_id": "httpx",
            "title": f"Servicio HTTP activo: {title}",
            "url": url if str(url).startswith(("http://", "https://")) else f"https://{url}",
            "category": "Servicio Expuesto",
            "category_class": "cat-cloud",
            "risk": "MEDIO" if status else "BAJO",
            "risk_class": "risk-medium",
            "detail": f"HTTP {status}" + (f" | Tech: {tech}" if tech else ""),
            "detected": _ts(),
            "is_dork": False,
        })
        if len(findings) >= int(limit or 50):
            break
    if not findings and proc.stderr:
        return [_tool_notice("httpx", proc.stderr)]
    return findings


def scan_naabu(host, ports="", limit=50, timeout=PD_TIMEOUT):
    if not shutil.which("naabu"):
        return _missing("naabu")
    host = str(host or "").strip()
    if not host:
        return []
    cmd = ["naabu", "-host", host, "-json", "-silent"]
    if ports:
        cmd += ["-p", str(ports)]
    proc = _run(cmd, int(timeout or PD_TIMEOUT))
    findings = []
    for item in _json_lines(proc.stdout):
        target = item.get("host") or item.get("ip") or host
        port = item.get("port") or item.get("raw")
        if not port:
            continue
        findings.append({
            "source": "naabu",
            "source_id": "naabu",
            "title": f"Puerto abierto: {target}:{port}",
            "url": f"{target}:{port}",
            "category": "Servicio Expuesto",
            "category_class": "cat-cloud",
            "risk": "ALTO" if str(port) in ("21", "22", "23", "3389", "5900") else "MEDIO",
            "risk_class": "risk-high",
            "detail": f"Host: {target} | Puerto: {port}",
            "detected": _ts(),
            "is_dork": False,
        })
        if len(findings) >= int(limit or 50):
            break
    if not findings and proc.stderr:
        return [_tool_notice("naabu", proc.stderr)]
    return findings


def scan_nuclei(target, templates="", severity="", tags="", limit=50, timeout=PD_TIMEOUT):
    if not shutil.which("nuclei"):
        return _missing("nuclei")
    target = str(target or "").strip()
    if not target:
        return []
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
    if templates:
        cmd += ["-t", str(templates)]
    if severity:
        cmd += ["-severity", str(severity)]
    if tags:
        cmd += ["-tags", str(tags)]
    proc = _run(cmd, int(timeout or PD_TIMEOUT))
    findings = []
    for item in _json_lines(proc.stdout):
        info = item.get("info") or {}
        name = info.get("name") or item.get("template-id") or "Nuclei finding"
        sev = str(info.get("severity") or item.get("severity") or "info").upper()
        risk = {"CRITICAL": "CRÍTICO", "HIGH": "ALTO", "MEDIUM": "MEDIO", "LOW": "BAJO"}.get(sev, "BAJO")
        matched = item.get("matched-at") or item.get("host") or target
        findings.append({
            "source": "nuclei",
            "source_id": "nuclei",
            "title": f"Nuclei: {name}",
            "url": matched,
            "category": "Vulnerabilidad",
            "category_class": "cat-leak",
            "risk": risk,
            "risk_class": "risk-high" if risk in ("ALTO", "CRÍTICO") else "risk-medium",
            "detail": f"Template: {item.get('template-id', '')} | Severity: {sev}",
            "detected": _ts(),
            "is_dork": False,
            "raw": item,
        })
        if len(findings) >= int(limit or 50):
            break
    if not findings and proc.stderr:
        return [_tool_notice("nuclei", proc.stderr)]
    return findings


def _tool_notice(tool, stderr):
    return {
        "source": tool,
        "source_id": tool,
        "title": f"{tool}: sin hallazgos parseables",
        "url": f"https://github.com/projectdiscovery/{tool}",
        "category": "Sistema",
        "category_class": "cat-repo",
        "risk": "BAJO",
        "risk_class": "risk-low",
        "detail": str(stderr)[:180],
        "detected": _ts(),
        "is_system": True,
        "is_negative": True,
    }
