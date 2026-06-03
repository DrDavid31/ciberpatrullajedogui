# -*- coding: utf-8 -*-
"""
Cliente minimo para MISP.
MISP corre como plataforma externa; este monitor solo usa su API REST.
"""

from datetime import date
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 20


def _clean_base_url(base_url):
    base_url = (base_url or "").strip()
    if not base_url:
        raise ValueError("MISP URL no configurada")
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    return base_url.rstrip("/") + "/"


def _headers(api_key):
    api_key = (api_key or "").strip()
    if not api_key:
        raise ValueError("MISP API key no configurada")
    return {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _request(method, base_url, api_key, path, payload=None, verify_tls=False):
    if not verify_tls:
        requests.packages.urllib3.disable_warnings()
    url = urljoin(_clean_base_url(base_url), path.lstrip("/"))
    response = requests.request(
        method,
        url,
        headers=_headers(api_key),
        json=payload,
        timeout=TIMEOUT,
        verify=verify_tls,
    )
    try:
        data = response.json()
    except ValueError:
        data = {"raw": response.text[:500]}
    if response.status_code >= 400:
        reason = data.get("message") or data.get("name") or response.text[:160]
        raise RuntimeError(f"MISP {response.status_code}: {reason}")
    return data


def split_tags(raw_tags):
    if isinstance(raw_tags, list):
        return [str(tag).strip() for tag in raw_tags if str(tag).strip()]
    raw_tags = str(raw_tags or "")
    return [tag.strip() for tag in raw_tags.replace("\n", ",").split(",") if tag.strip()]


def as_int(value, default, allowed=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if allowed and parsed not in allowed:
        return default
    return parsed


def risk_to_threat_level(findings):
    risks = {str(f.get("risk", "")).upper() for f in findings}
    if "CRÍTICO" in risks or "CRITICO" in risks or "ALTO" in risks:
        return 1
    if "MEDIO" in risks:
        return 2
    if "BAJO" in risks:
        return 3
    return 4


def test_connection(base_url, api_key, verify_tls=False):
    try:
        data = _request("GET", base_url, api_key, "servers/getVersion", verify_tls=verify_tls)
    except Exception:
        data = _request("GET", base_url, api_key, "users/view/me", verify_tls=verify_tls)
    version = data.get("version") or data.get("Version") or data.get("raw") or "desconocida"
    return {"status": "ok", "message": "Conexion MISP correcta", "version": version}


def _finding_comment(finding):
    parts = [
        f"Fuente: {finding.get('source', '')}",
        f"Riesgo: {finding.get('risk', '')}",
        f"Categoria: {finding.get('category', '')}",
        f"Detectado: {finding.get('detected', '')}",
    ]
    detail = finding.get("detail")
    if detail:
        parts.append(f"Detalle: {detail}")
    return " | ".join(parts)[:65535]


def _attributes_for_finding(finding):
    title = str(finding.get("title") or "Hallazgo Dogui Ciberpatrullaje").strip()
    url = str(finding.get("url") or "").strip()
    raw = str(finding.get("raw") or "").strip()
    comment = _finding_comment(finding)
    attributes = [{
        "type": "text",
        "category": "External analysis",
        "value": title[:65535],
        "comment": comment,
        "to_ids": False,
    }]

    if url and url != "#":
        attributes.append({
            "type": "url",
            "category": "Network activity",
            "value": url[:65535],
            "comment": comment,
            "to_ids": False,
        })
        parsed = urlparse(url)
        if parsed.hostname:
            attributes.append({
                "type": "domain",
                "category": "Network activity",
                "value": parsed.hostname[:255],
                "comment": f"Dominio extraido de {url}"[:65535],
                "to_ids": False,
            })
    elif raw and raw != "#":
        attributes.append({
            "type": "text",
            "category": "External analysis",
            "value": raw[:65535],
            "comment": comment,
            "to_ids": False,
        })

    return attributes


def build_event(findings, info, distribution, threat_level_id, analysis, tags):
    filtered = [
        finding for finding in findings
        if not finding.get("is_system") and not finding.get("is_negative")
    ]
    attributes = []
    seen = set()
    for finding in filtered:
        for attribute in _attributes_for_finding(finding):
            key = (attribute["type"], attribute["value"])
            if key in seen:
                continue
            seen.add(key)
            attributes.append(attribute)
            if len(attributes) >= 200:
                break
        if len(attributes) >= 200:
            break

    if not attributes:
        raise ValueError("No hay hallazgos exportables para MISP")

    event = {
        "info": info,
        "date": date.today().isoformat(),
        "distribution": str(distribution),
        "threat_level_id": str(threat_level_id),
        "analysis": str(analysis),
        "Attribute": attributes,
    }
    tags = split_tags(tags)
    if tags:
        event["Tag"] = [{"name": tag} for tag in tags]
    return {"Event": event}, filtered


def export_findings(
    base_url,
    api_key,
    findings,
    info=None,
    distribution=0,
    threat_level_id=None,
    analysis=0,
    tags=None,
    publish=False,
    verify_tls=False,
):
    filtered = [
        finding for finding in findings
        if not finding.get("is_system") and not finding.get("is_negative")
    ]
    if threat_level_id in (None, ""):
        threat_level_id = risk_to_threat_level(filtered)
    else:
        threat_level_id = as_int(threat_level_id, 2, {1, 2, 3, 4})

    distribution = as_int(distribution, 0, {0, 1, 2, 3, 4, 5})
    analysis = as_int(analysis, 0, {0, 1, 2})
    info = (info or f"Dogui Ciberpatrullaje - {date.today().isoformat()}").strip()

    payload, filtered = build_event(
        filtered,
        info,
        distribution,
        threat_level_id,
        analysis,
        tags,
    )
    data = _request("POST", base_url, api_key, "events/add", payload, verify_tls=verify_tls)
    event = data.get("Event", data)
    event_id = event.get("id")

    publish_result = None
    if publish and event_id:
        publish_result = _request(
            "POST",
            base_url,
            api_key,
            f"events/publish/{event_id}",
            verify_tls=verify_tls,
        )

    return {
        "status": "ok",
        "event_id": event_id,
        "event_uuid": event.get("uuid"),
        "attributes": len(payload["Event"]["Attribute"]),
        "findings": len(filtered),
        "published": bool(publish_result),
    }
