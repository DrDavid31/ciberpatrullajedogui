# -*- coding: utf-8 -*-
"""
Cliente ligero para Aleph/OpenAleph.
Usa la API /api/2/entities para consultar entidades/documentos.
"""

from datetime import datetime

import requests


def _base_api(base_url):
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("Configura la URL de Aleph")
    if not base.endswith("/api/2"):
        base = f"{base}/api/2"
    return base


def _headers(api_key=None):
    headers = {"Accept": "application/json"}
    api_key = str(api_key or "").strip()
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    return headers


def _request(base_url, path, api_key=None, verify_tls=True, **kwargs):
    url = f"{_base_api(base_url)}/{path.lstrip('/')}"
    resp = requests.get(url, headers=_headers(api_key), timeout=25, verify=verify_tls, **kwargs)
    if resp.status_code >= 400:
        raise RuntimeError(f"Aleph {resp.status_code}: {resp.text[:220]}")
    return resp.json()


def search_entities(base_url, query, api_key=None, schemata=None, limit=10, verify_tls=True):
    params = {"q": query or "*", "limit": int(limit or 10)}
    if schemata:
        params["filter:schemata"] = schemata
    data = _request(base_url, "entities", api_key, verify_tls, params=params)
    results = data.get("results") or data.get("data") or []
    findings = []
    for item in results[: int(limit or 10)]:
        schema = item.get("schema") or item.get("schemata") or "Entity"
        title = item.get("caption") or item.get("name") or item.get("id") or "Entidad Aleph"
        entity_id = item.get("id") or item.get("entity_id") or ""
        url = f"{str(base_url).rstrip('/')}/entities/{entity_id}" if entity_id else str(base_url).rstrip("/")
        collection = item.get("collection") or item.get("dataset") or {}
        if isinstance(collection, dict):
            collection_label = collection.get("label") or collection.get("name") or collection.get("foreign_id") or ""
        else:
            collection_label = str(collection or "")
        findings.append({
            "source": "Aleph",
            "source_id": "aleph",
            "title": f"Aleph: {title}",
            "url": url,
            "category": "Investigacion Documental",
            "category_class": "cat-repo",
            "risk": "MEDIO",
            "risk_class": "risk-medium",
            "detail": f"Schema: {schema}" + (f" | Dataset: {collection_label}" if collection_label else ""),
            "detected": datetime.now().strftime("%H:%M:%S"),
            "is_dork": False,
            "raw": item,
        })
    return findings


def test_connection(base_url, api_key=None, verify_tls=True):
    findings = search_entities(base_url, "INE", api_key, limit=1, verify_tls=verify_tls)
    return {
        "status": "ok",
        "message": "Conexion Aleph correcta",
        "sample_results": len(findings),
    }
