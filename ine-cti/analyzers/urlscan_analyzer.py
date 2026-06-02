# -*- coding: utf-8 -*-
"""
Analizador urlscan.io para enviar URLs y consultar resultados.
"""

import json
import time

import requests


def submit_url(api_key, url, visibility="unlisted", tags=None, country=None):
    api_key = str(api_key or "").strip()
    if not api_key:
        raise ValueError("Configura la API key de urlscan.io")
    url = str(url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("urlscan.io requiere una URL http/https")
    payload = {"url": url, "visibility": visibility or "unlisted"}
    clean_tags = [t.strip() for t in str(tags or "ine-cti").replace(",", " ").split() if t.strip()]
    if clean_tags:
        payload["tags"] = clean_tags[:10]
    if country:
        payload["country"] = str(country).strip().lower()
    resp = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers={"API-Key": api_key, "Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=25,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"urlscan.io {resp.status_code}: {resp.text[:220]}")
    return resp.json()


def get_result(result_api_url, api_key=None):
    headers = {}
    if api_key:
        headers["API-Key"] = str(api_key).strip()
    resp = requests.get(result_api_url, headers=headers, timeout=25)
    if resp.status_code == 404:
        return {"status": "pending", "message": "Resultado aun no disponible"}
    if resp.status_code >= 400:
        raise RuntimeError(f"urlscan.io result {resp.status_code}: {resp.text[:220]}")
    return {"status": "ok", "result": resp.json()}


def submit_many(api_key, findings, visibility="unlisted", tags="ine-cti", limit=10):
    submitted = []
    errors = []
    for finding in (findings or [])[: int(limit or 10)]:
        url = finding.get("url", "")
        try:
            submitted.append({"url": url, "result": submit_url(api_key, url, visibility, tags)})
            time.sleep(1)
        except Exception as exc:
            errors.append({"url": url, "error": str(exc)})
    return {"status": "ok", "submitted": submitted, "errors": errors}


def test_connection(api_key):
    api_key = str(api_key or "").strip()
    if not api_key:
        raise ValueError("Configura la API key de urlscan.io")
    resp = requests.get(
        "https://urlscan.io/user/quotas/",
        headers={"API-Key": api_key, "Content-Type": "application/json"},
        timeout=20,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"urlscan.io {resp.status_code}: {resp.text[:220]}")
    return {"status": "ok", "message": "Conexion urlscan.io correcta", "quotas": resp.json()}
