# -*- coding: utf-8 -*-
"""
Cliente minimo para AIL Framework.
AIL corre como plataforma externa; este monitor solo usa su API REST.
"""

import json
from urllib.parse import urljoin

import requests

TIMEOUT = 20


def _clean_base_url(base_url):
    base_url = (base_url or "").strip()
    if not base_url:
        raise ValueError("AIL URL no configurada")
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    return base_url.rstrip("/") + "/"


def _headers(api_key):
    api_key = (api_key or "").strip()
    if not api_key:
        raise ValueError("AIL API key no configurada")
    return {
        "Authorization": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
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
        reason = data.get("reason") or data.get("message") or response.text[:160]
        raise RuntimeError(f"AIL {response.status_code}: {reason}")
    return data


def split_tags(raw_tags):
    if isinstance(raw_tags, list):
        return [str(tag).strip() for tag in raw_tags if str(tag).strip()]
    raw_tags = str(raw_tags or "")
    return [tag.strip() for tag in raw_tags.replace("\n", ",").split(",") if tag.strip()]


def test_connection(base_url, api_key, verify_tls=False):
    data = _request("GET", base_url, api_key, "api/v1/get/tag/all", verify_tls=verify_tls)
    return {
        "status": "ok",
        "message": "Conexion AIL correcta",
        "tags_count": len(data.get("tags", [])),
    }


def format_finding_text(finding, index):
    payload = {
        "source": finding.get("source", ""),
        "title": finding.get("title", ""),
        "category": finding.get("category", ""),
        "risk": finding.get("risk", ""),
        "url": finding.get("url", ""),
        "detail": finding.get("detail", ""),
        "detected": finding.get("detected", ""),
        "raw": finding.get("raw", ""),
    }
    return (
        "INE CTI Monitor finding\n"
        f"Finding: {index}\n"
        f"Source: {payload['source']}\n"
        f"Risk: {payload['risk']}\n"
        f"Category: {payload['category']}\n"
        f"Title: {payload['title']}\n"
        f"URL: {payload['url']}\n"
        f"Detected: {payload['detected']}\n"
        f"Detail: {payload['detail']}\n\n"
        "JSON:\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )


def export_findings(base_url, api_key, findings, tags=None, verify_tls=False):
    tags = split_tags(tags)
    exported = []
    errors = []

    filtered = [
        finding for finding in findings
        if not finding.get("is_system") and not finding.get("is_negative")
    ]

    for index, finding in enumerate(filtered, 1):
        payload = {
            "type": "text",
            "text": format_finding_text(finding, index),
            "default_tags": True,
        }
        if tags:
            payload["tags"] = tags
        try:
            data = _request(
                "POST",
                base_url,
                api_key,
                "api/v1/import/item",
                payload,
                verify_tls=verify_tls,
            )
            exported.append({
                "source": finding.get("source", ""),
                "title": finding.get("title", ""),
                "uuid": data.get("uuid"),
            })
        except Exception as exc:
            errors.append({
                "source": finding.get("source", ""),
                "title": finding.get("title", ""),
                "error": str(exc),
            })

    return {
        "status": "ok" if not errors else "partial",
        "exported": exported,
        "errors": errors,
        "total": len(filtered),
    }


def create_tracker(base_url, api_key, term, tracker_type="word", tags=None, verify_tls=False):
    term = (term or "").strip()
    if not term:
        raise ValueError("Termino tracker no configurado")

    tracker_type = (tracker_type or "word").strip().lower()
    if tracker_type not in ("word", "set", "regex"):
        tracker_type = "word"

    payload = {
        "term": term,
        "type": tracker_type,
        "level": 1,
        "description": "Creado desde INE CTI Monitor",
    }
    if tracker_type == "set":
        payload["nb_words"] = 2
    tags = split_tags(tags)
    if tags:
        payload["tags"] = tags

    data = _request(
        "POST",
        base_url,
        api_key,
        "api/v1/add/tracker",
        payload,
        verify_tls=verify_tls,
    )
    return {
        "status": "ok",
        "uuid": data.get("uuid"),
        "term": term,
        "type": tracker_type,
    }
