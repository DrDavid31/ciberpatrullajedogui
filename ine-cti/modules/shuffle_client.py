# -*- coding: utf-8 -*-
"""
Cliente minimo para Shuffle Webhook Trigger.
"""

from datetime import datetime

import requests


def _headers(token=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    token = str(token or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def send_event(webhook_url, payload, token=None, verify_tls=True):
    url = str(webhook_url or "").strip()
    if not url:
        raise ValueError("Configura la URL del webhook de Shuffle")
    body = {
        "source": "ine-cti-monitor",
        "sent_at": datetime.utcnow().isoformat() + "Z",
        **(payload or {}),
    }
    resp = requests.post(url, json=body, headers=_headers(token), timeout=25, verify=verify_tls)
    if resp.status_code >= 400:
        raise RuntimeError(f"Shuffle webhook {resp.status_code}: {resp.text[:220]}")
    try:
        data = resp.json()
    except Exception:
        data = {"text": resp.text[:500]}
    return {"status": "ok", "status_code": resp.status_code, "response": data}


def test_connection(webhook_url, token=None, verify_tls=True):
    return send_event(
        webhook_url,
        {"event_type": "ine_cti.test", "message": "Prueba Shuffle correcta"},
        token,
        verify_tls,
    )


def export_findings(webhook_url, findings, token=None, limit=20, verify_tls=True):
    sent = []
    errors = []
    for finding in (findings or [])[: int(limit or 20)]:
        try:
            sent.append({
                "url": finding.get("url"),
                "result": send_event(
                    webhook_url,
                    {"event_type": "ine_cti.finding", "finding": finding},
                    token,
                    verify_tls,
                ),
            })
        except Exception as exc:
            errors.append({"url": finding.get("url"), "error": str(exc)})
    return {"status": "ok", "sent": sent, "errors": errors}
