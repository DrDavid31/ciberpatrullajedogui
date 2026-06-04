# -*- coding: utf-8 -*-
"""
Cliente minimo para Huginn Webhook Agent.
Envia eventos JSON a un Webhook Agent configurado por URL completa.
"""

from datetime import datetime

import requests


def _require_url(webhook_url):
    url = str(webhook_url or "").strip()
    if not url:
        raise ValueError("Configura la URL completa del Webhook Agent de Huginn")
    return url


def send_event(webhook_url, event_type, payload, verify_tls=True):
    url = _require_url(webhook_url)
    body = {
        "event_type": event_type,
        "source": "ine-cti-monitor",
        "sent_at": datetime.utcnow().isoformat() + "Z",
        "payload": payload or {},
    }
    resp = requests.post(url, json=body, timeout=20, verify=verify_tls)
    if resp.status_code >= 400:
        raise RuntimeError(f"Huginn webhook {resp.status_code}: {resp.text[:220]}")
    return {
        "status": "ok",
        "status_code": resp.status_code,
        "message": "Evento enviado a Huginn",
    }


def test_connection(webhook_url, verify_tls=True):
    return send_event(
        webhook_url,
        "ine_cti.test",
        {"message": "Prueba de integracion Huginn correcta"},
        verify_tls,
    )


def export_findings(webhook_url, findings, term="", domain="", limit=20, verify_tls=True):
    sent = []
    errors = []
    for finding in (findings or [])[: int(limit or 20)]:
        try:
            result = send_event(
                webhook_url,
                "ine_cti.finding",
                {
                    "term": term,
                    "domain": domain,
                    "finding": finding,
                },
                verify_tls,
            )
            sent.append({"url": finding.get("url"), "result": result})
        except Exception as exc:
            errors.append({"url": finding.get("url"), "error": str(exc)})
    return {"status": "ok", "sent": sent, "errors": errors}
