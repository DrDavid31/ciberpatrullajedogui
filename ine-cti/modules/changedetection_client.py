# -*- coding: utf-8 -*-
"""
Cliente minimo para changedetection.io.
Permite probar conexion, leer watches y crear monitores desde hallazgos.
"""

from datetime import datetime
from urllib.parse import urlparse

import requests


def _base_api(base_url):
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("Configura la URL de changedetection.io")
    if not base.endswith("/api/v1"):
        base = f"{base}/api/v1"
    return base


def _headers(api_key):
    api_key = str(api_key or "").strip()
    if not api_key:
        raise ValueError("Configura la API key de changedetection.io")
    return {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _request(method, base_url, api_key, path, verify_tls=True, **kwargs):
    url = f"{_base_api(base_url)}/{path.lstrip('/')}"
    resp = requests.request(
        method,
        url,
        headers=_headers(api_key),
        timeout=20,
        verify=verify_tls,
        **kwargs,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"changedetection.io {resp.status_code}: {resp.text[:220]}")
    if "application/json" in resp.headers.get("content-type", ""):
        return resp.json()
    return {"status": "ok", "text": resp.text[:500]}


def test_connection(base_url, api_key, verify_tls=True):
    data = _request("GET", base_url, api_key, "systeminfo", verify_tls=verify_tls)
    return {
        "status": "ok",
        "message": "Conexion changedetection.io correcta",
        "system": data,
    }


def list_watches(base_url, api_key, tag=None, recheck=False, verify_tls=True):
    params = {}
    if tag:
        params["tag"] = tag
    if recheck:
        params["recheck_all"] = "1"
    data = _request("GET", base_url, api_key, "watch", verify_tls=verify_tls, params=params)
    if isinstance(data, dict):
        watches = data.get("data") or data.get("watch") or data
    else:
        watches = data
    return watches


def create_watch(base_url, api_key, url, title=None, tag=None, verify_tls=True):
    parsed = urlparse(str(url or ""))
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL no monitoreable por changedetection.io: {url}")
    payload = {"url": url}
    if title:
        payload["title"] = str(title)[:180]
    if tag:
        payload["tag"] = str(tag)[:80]
    return _request("POST", base_url, api_key, "watch", verify_tls=verify_tls, json=payload)


def export_findings_as_watches(base_url, api_key, findings, tag="ine-cti", limit=20, verify_tls=True):
    exported = []
    errors = []
    for finding in (findings or [])[: int(limit or 20)]:
        url = finding.get("url", "")
        try:
            result = create_watch(
                base_url,
                api_key,
                url,
                finding.get("title") or finding.get("source"),
                tag,
                verify_tls,
            )
            exported.append({"url": url, "result": result})
        except Exception as exc:
            errors.append({"url": url, "error": str(exc)})
    return {"status": "ok", "exported": exported, "errors": errors}


def scan_watches(base_url, api_key, tag=None, recheck=False, limit=20, verify_tls=True):
    if not str(base_url or "").strip() or not str(api_key or "").strip():
        return [{
            "source": "changedetection.io",
            "source_id": "changedetection",
            "title": "changedetection.io no configurado",
            "url": "https://github.com/dgtlmoon/changedetection.io",
            "category": "Sistema",
            "category_class": "cat-repo",
            "risk": "BAJO",
            "risk_class": "risk-low",
            "detail": "Configura URL y API key para consultar watches reales",
            "detected": datetime.now().strftime("%H:%M:%S"),
            "is_system": True,
            "is_negative": True,
        }]
    watches = list_watches(base_url, api_key, tag, recheck, verify_tls)
    items = watches.values() if isinstance(watches, dict) else watches
    findings = []
    for i, item in enumerate(items):
        if i >= int(limit or 20):
            break
        if not isinstance(item, dict):
            continue
        url = item.get("url") or item.get("link") or item.get("uri") or ""
        title = item.get("title") or item.get("last_checked") or url or "Watch changedetection.io"
        last_changed = item.get("last_changed") or item.get("last_viewed") or ""
        last_error = item.get("last_error") or item.get("error") or ""
        risk = "ALTO" if last_error else ("MEDIO" if last_changed else "BAJO")
        detail = []
        if last_changed:
            detail.append(f"Ultimo cambio: {last_changed}")
        if last_error:
            detail.append(f"Error: {last_error}")
        if item.get("uuid"):
            detail.append(f"UUID: {item.get('uuid')}")
        findings.append({
            "source": "changedetection.io",
            "source_id": "changedetection",
            "title": f"Monitor web: {title}",
            "url": url or _base_api(base_url),
            "category": "Monitoreo de Cambios",
            "category_class": "cat-repo",
            "risk": risk,
            "risk_class": "risk-medium" if risk == "MEDIO" else "risk-low",
            "detail": " | ".join(detail) or "Watch registrado sin cambios recientes",
            "detected": datetime.now().strftime("%H:%M:%S"),
            "is_dork": False,
        })
    return findings
