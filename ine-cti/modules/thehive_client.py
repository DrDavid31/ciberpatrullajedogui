# -*- coding: utf-8 -*-
"""
Cliente minimo para TheHive.
Crea alertas desde hallazgos y prueba conectividad con variantes de API comunes.
"""

from datetime import datetime

import requests


def _base(base_url):
    url = str(base_url or "").strip().rstrip("/")
    if not url:
        raise ValueError("Configura la URL de TheHive")
    return url


def _headers(api_key, org=None):
    api_key = str(api_key or "").strip()
    if not api_key:
        raise ValueError("Configura la API key de TheHive")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if org:
        headers["X-Organisation"] = str(org).strip()
    return headers


def _request(method, base_url, api_key, path, org=None, verify_tls=True, **kwargs):
    resp = requests.request(
        method,
        f"{_base(base_url)}/{path.lstrip('/')}",
        headers=_headers(api_key, org),
        timeout=25,
        verify=verify_tls,
        **kwargs,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"TheHive {resp.status_code}: {resp.text[:220]}")
    if "application/json" in resp.headers.get("content-type", ""):
        return resp.json()
    return {"status": "ok", "text": resp.text[:500]}


def test_connection(base_url, api_key, org=None, verify_tls=True):
    errors = []
    for path in ("api/v1/status", "api/status"):
        try:
            data = _request("GET", base_url, api_key, path, org, verify_tls)
            return {"status": "ok", "message": "Conexion TheHive correcta", "data": data}
        except Exception as exc:
            errors.append(str(exc))
    raise RuntimeError("No se pudo consultar TheHive: " + " | ".join(errors))


def _observable_from_finding(finding):
    url = finding.get("url", "")
    if url.startswith(("http://", "https://")):
        return {"dataType": "url", "data": url, "message": finding.get("title", "")}
    raw = finding.get("raw") or finding.get("title") or finding.get("source")
    return {"dataType": "other", "data": str(raw)[:500], "message": finding.get("detail", "")}


def _severity_from_risk(risk):
    value = str(risk or "").strip().upper().replace("Í", "I")
    if value in ("CRITICO", "CRITICAL"):
        return 3
    if value in ("ALTO", "HIGH"):
        return 2
    return 1


def create_alert(base_url, api_key, finding, org=None, verify_tls=True):
    title = finding.get("title") or "Dogui Ciberpatrullaje finding"
    severity = _severity_from_risk(finding.get("risk"))
    payload = {
        "title": title[:512],
        "description": finding.get("detail") or title,
        "type": "external",
        "source": "ine-cti-monitor",
        "sourceRef": f"ine-cti-{abs(hash((title, finding.get('url', ''))))}",
        "severity": severity,
        "date": int(datetime.utcnow().timestamp() * 1000),
        "tags": ["ine-cti", str(finding.get("source_id") or finding.get("source") or "osint")],
        "observables": [_observable_from_finding(finding)],
    }
    errors = []
    for path in ("api/v1/alert", "api/alert"):
        try:
            return _request("POST", base_url, api_key, path, org, verify_tls, json=payload)
        except Exception as exc:
            errors.append(str(exc))
    raise RuntimeError("No se pudo crear alerta TheHive: " + " | ".join(errors))


def export_findings(base_url, api_key, findings, org=None, limit=20, verify_tls=True):
    exported = []
    errors = []
    for finding in (findings or [])[: int(limit or 20)]:
        try:
            exported.append({
                "url": finding.get("url"),
                "result": create_alert(base_url, api_key, finding, org, verify_tls),
            })
        except Exception as exc:
            errors.append({"url": finding.get("url"), "error": str(exc)})
    return {"status": "ok", "exported": exported, "errors": errors}
