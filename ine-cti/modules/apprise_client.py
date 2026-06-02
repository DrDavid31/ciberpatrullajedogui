# -*- coding: utf-8 -*-
"""
Cliente minimo para Apprise.
Apprise permite enviar notificaciones a multiples servicios usando URLs.
"""


def split_urls(raw_urls):
    if isinstance(raw_urls, list):
        return [str(url).strip() for url in raw_urls if str(url).strip()]
    raw_urls = str(raw_urls or "")
    urls = []
    for line in raw_urls.replace(",", "\n").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def send_notification(raw_urls, title, body, notify_type="info"):
    urls = split_urls(raw_urls)
    if not urls:
        raise ValueError("No hay URLs Apprise configuradas")

    try:
        import apprise
    except ImportError as exc:
        raise RuntimeError("Apprise no esta instalado; ejecuta pip install -r requirements.txt") from exc

    app = apprise.Apprise()
    added = 0
    for url in urls:
        if app.add(url):
            added += 1
    if not added:
        raise ValueError("Ninguna URL Apprise fue valida")

    notify_map = {
        "info": apprise.NotifyType.INFO,
        "success": apprise.NotifyType.SUCCESS,
        "warning": apprise.NotifyType.WARNING,
        "failure": apprise.NotifyType.FAILURE,
    }
    ok = app.notify(
        title=title[:250],
        body=body[:4000],
        notify_type=notify_map.get(str(notify_type).lower(), apprise.NotifyType.INFO),
    )
    return {
        "status": "ok" if ok else "partial",
        "sent": bool(ok),
        "targets": added,
    }


def test_connection(raw_urls):
    return send_notification(
        raw_urls,
        "INE CTI Monitor - prueba Apprise",
        "La integracion Apprise esta funcionando correctamente.",
        "success",
    )
