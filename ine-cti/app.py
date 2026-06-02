# -*- coding: utf-8 -*-
"""
INE CTI Monitor — Backend Flask
Ejecutar: python app.py
Acceder:  http://localhost:5000
"""

import json
import os
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Agregar path del proyecto
import sys
sys.path.insert(0, os.path.dirname(__file__))
from modules.scanner import (
    scan_github, scan_pastebin, scan_s3, scan_azure,
    scan_gcs, scan_googledrive, scan_file_repos,
    scan_ahmia, scan_darksearch, scan_leakix,
    scan_hibp, scan_intelx, scan_onionsearch,
    scan_trufflehog, scan_gitleaks, scan_social_analyzer
)
from modules.ail_client import (
    create_tracker as ail_create_tracker,
    export_findings as ail_export_findings,
    test_connection as ail_test_connection,
)
from modules.misp_client import (
    export_findings as misp_export_findings,
    test_connection as misp_test_connection,
)
from modules.apprise_client import (
    send_notification as apprise_send_notification,
    test_connection as apprise_test_connection,
)

app = Flask(__name__, static_folder="static")
CORS(app)

# ── Estado global del escaneo ──
scan_state = {
    "running": False,
    "progress": 0,
    "current_module": "",
    "log": [],
    "findings": [],
    "stats": {
        "sources_scanned": 0,
        "total_findings": 0,
        "high_critical": 0,
        "repos": 0,
        "cloud": 0,
        "darkweb": 0,
        "leaks": 0,
    },
    "started_at": None,
    "finished_at": None,
}

RESULTS_FILE = os.path.join(os.path.dirname(__file__), "results", "findings.json")
os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)


def as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on", "si")


def ail_config(data):
    keys = data.get("api_keys", data)
    return {
        "base_url": keys.get("ail_url", ""),
        "api_key": keys.get("ail_key", ""),
        "tags": keys.get("ail_tags", ""),
        "tracker_type": keys.get("ail_tracker_type", "word"),
        "verify_tls": as_bool(keys.get("ail_verify_tls")),
    }


def misp_config(data):
    keys = data.get("api_keys", data)
    return {
        "base_url": keys.get("misp_url", ""),
        "api_key": keys.get("misp_key", ""),
        "tags": keys.get("misp_tags", ""),
        "distribution": keys.get("misp_distribution", 0),
        "threat_level_id": keys.get("misp_threat_level", ""),
        "analysis": keys.get("misp_analysis", 0),
        "publish": as_bool(keys.get("misp_publish")),
        "verify_tls": as_bool(keys.get("misp_verify_tls")),
    }


def apprise_config(data):
    keys = data.get("api_keys", data)
    return {
        "urls": keys.get("apprise_urls", ""),
        "on_complete": as_bool(keys.get("apprise_on_complete")),
        "on_high": as_bool(keys.get("apprise_on_high")),
    }


def scan_summary_text(term="INE", domain="ine.mx"):
    stats = scan_state.get("stats", {})
    lines = [
        f"Termino: {term}",
        f"Dominio: {domain}",
        f"Fuentes escaneadas: {stats.get('sources_scanned', 0)}",
        f"Hallazgos totales: {stats.get('total_findings', 0)}",
        f"Alto/Critico: {stats.get('high_critical', 0)}",
        f"Repositorios: {stats.get('repos', 0)}",
        f"Cloud: {stats.get('cloud', 0)}",
        f"Dark Web: {stats.get('darkweb', 0)}",
        f"Leaks: {stats.get('leaks', 0)}",
    ]
    top = [
        finding for finding in scan_state.get("findings", [])
        if finding.get("risk") in ("CRÍTICO", "CRITICO", "ALTO")
        and not finding.get("is_system")
        and not finding.get("is_negative")
    ][:5]
    if top:
        lines.append("")
        lines.append("Top hallazgos:")
        for finding in top:
            lines.append(f"- [{finding.get('risk')}] {finding.get('source')}: {finding.get('title')}")
    return "\n".join(lines)


def maybe_send_apprise_summary(term, domain, api_keys):
    cfg = apprise_config(api_keys)
    if not cfg["urls"]:
        return
    high_count = scan_state["stats"].get("high_critical", 0)
    should_send = cfg["on_complete"] or (cfg["on_high"] and high_count > 0)
    if not should_send:
        return

    notify_type = "warning" if high_count > 0 else "success"
    title = f"INE CTI Monitor - {scan_state['stats'].get('total_findings', 0)} hallazgo(s)"
    try:
        result = apprise_send_notification(cfg["urls"], title, scan_summary_text(term, domain), notify_type)
        log(f"Apprise notificacion enviada a {result.get('targets')} destino(s)", "ok")
    except Exception as e:
        log(f"Apprise error: {e}", "error")


def log(msg, level="info"):
    entry = {"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
    scan_state["log"].append(entry)
    # Mantener solo los últimos 200 logs en memoria
    if len(scan_state["log"]) > 200:
        scan_state["log"] = scan_state["log"][-200:]
    print(f"[{entry['ts']}] [{level.upper()}] {msg}")


def add_findings(new_findings, module_type="repo"):
    for f in new_findings:
        if f.get("is_system"):
            continue
        scan_state["findings"].append(f)
        scan_state["stats"]["total_findings"] += 1
        if f.get("risk") in ("ALTO", "CRÍTICO"):
            scan_state["stats"]["high_critical"] += 1
        cat = f.get("category", "")
        if "Repositorio" in cat or "Código" in cat:
            scan_state["stats"]["repos"] += 1
        if "Cloud" in cat or "Expuesto" in cat:
            scan_state["stats"]["cloud"] += 1
        if "Dark Web" in cat:
            scan_state["stats"]["darkweb"] += 1
        if "Credencial" in cat or "Leak" in cat or "Filtrada" in cat:
            scan_state["stats"]["leaks"] += 1


def run_scan(term, domain, active_modules, api_keys):
    scan_state["running"] = True
    scan_state["progress"] = 0
    scan_state["log"] = []
    scan_state["findings"] = []
    scan_state["started_at"] = datetime.now().isoformat()
    scan_state["finished_at"] = None
    for k in scan_state["stats"]:
        scan_state["stats"][k] = 0

    log(f"Iniciando escaneo CTI — término: '{term}' | dominio: '{domain}'", "info")
    log(f"Módulos activos: {', '.join(active_modules)}", "info")

    modules = [
        ("github",      "GitHub / GitLab",         lambda: scan_github(term, api_keys.get("github"))),
        ("pastebin",    "Pastebin",                 lambda: scan_pastebin(term)),
        ("googledrive", "Google Drive / Docs",      lambda: scan_googledrive(term)),
        ("filerepos",   "Dropbox / OneDrive / MEGA",lambda: scan_file_repos(term)),
        ("aws",         "AWS S3 Buckets",           lambda: scan_s3(term)),
        ("azure",       "Azure Blob Storage",       lambda: scan_azure(term)),
        ("gcloud",      "Google Cloud Storage",     lambda: scan_gcs(term)),
        ("ahmia",       "Ahmia (Dark Web)",         lambda: scan_ahmia(term)),
        ("darksearch",  "DarkSearch.io",            lambda: scan_darksearch(term)),
        ("onionsearch", "OnionSearch",              lambda: scan_onionsearch(
            term,
            api_keys.get("onion_proxy"),
            api_keys.get("onion_limit", 1),
            api_keys.get("onion_engines")
        )),
        ("trufflehog",  "TruffleHog",               lambda: scan_trufflehog(
            api_keys.get("trufflehog_target"),
            api_keys.get("trufflehog_mode", "git"),
            api_keys.get("trufflehog_results", "verified,unknown"),
            api_keys.get("github"),
            as_bool(api_keys.get("trufflehog_comments")),
            api_keys.get("trufflehog_limit", 20),
        )),
        ("gitleaks",    "Gitleaks",                 lambda: scan_gitleaks(
            api_keys.get("gitleaks_target", "."),
            api_keys.get("gitleaks_mode", "dir"),
            api_keys.get("gitleaks_config"),
            api_keys.get("gitleaks_baseline"),
            api_keys.get("gitleaks_limit", 20),
            api_keys.get("gitleaks_max_mb"),
            api_keys.get("gitleaks_log_opts"),
        )),
        ("socialanalyzer", "Social Analyzer",       lambda: scan_social_analyzer(
            api_keys.get("social_username") or term,
            api_keys.get("social_websites"),
            api_keys.get("social_top", 100),
            api_keys.get("social_mode", "fast"),
            api_keys.get("social_method", "find"),
            api_keys.get("social_filter", "good"),
            api_keys.get("social_profiles", "detected"),
            as_bool(api_keys.get("social_metadata")),
            as_bool(api_keys.get("social_extract")),
            api_keys.get("social_countries"),
            api_keys.get("social_type"),
            api_keys.get("social_timeout", 10),
            api_keys.get("social_limit", 30),
        )),
        ("leakix",      "LeakIX",                   lambda: scan_leakix(term, api_keys.get("leakix"))),
        ("hibp",        "HaveIBeenPwned",           lambda: scan_hibp(domain, api_keys.get("hibp"))),
        ("intelx",      "Intelligence X",           lambda: scan_intelx(term, api_keys.get("intelx"))),
    ]

    active = [(mid, mlabel, mfn) for mid, mlabel, mfn in modules if mid in active_modules]
    total = len(active)

    for i, (mid, mlabel, mfn) in enumerate(active):
        scan_state["current_module"] = mlabel
        scan_state["progress"] = int((i / total) * 100)
        scan_state["stats"]["sources_scanned"] = i + 1
        log(f"[{i+1}/{total}] Escaneando: {mlabel}...", "info")

        try:
            results = mfn()
            real = [r for r in results if not r.get("is_system") and not r.get("is_negative")]
            add_findings(results)
            if real:
                log(f"✔ {mlabel} → {len(real)} hallazgo(s)", "warn")
            else:
                log(f"✔ {mlabel} → sin hallazgos relevantes", "ok")
        except Exception as e:
            log(f"✘ {mlabel} → error: {str(e)[:60]}", "error")

        time.sleep(0.5)

    scan_state["progress"] = 100
    scan_state["current_module"] = "Completado"
    scan_state["running"] = False
    scan_state["finished_at"] = datetime.now().isoformat()
    log(f"Escaneo finalizado — {scan_state['stats']['total_findings']} hallazgos totales", "ok")

    # Guardar resultados en disco
    try:
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "meta": {
                    "term": term,
                    "domain": domain,
                    "started_at": scan_state["started_at"],
                    "finished_at": scan_state["finished_at"],
                    "stats": scan_state["stats"],
                },
                "findings": scan_state["findings"],
            }, f, ensure_ascii=False, indent=2)
        log("Resultados guardados en results/findings.json", "info")
    except Exception as e:
        log(f"Error guardando resultados: {e}", "error")

    maybe_send_apprise_summary(term, domain, api_keys)


# ── API ROUTES ──

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    if scan_state["running"]:
        return jsonify({"error": "Ya hay un escaneo en curso"}), 409

    data = request.json or {}
    term           = data.get("term", "INE").strip() or "INE"
    domain         = data.get("domain", "ine.mx").strip() or "ine.mx"
    active_modules = data.get("modules", ["github","pastebin","googledrive",
                                           "filerepos","aws","azure","gcloud",
                                           "ahmia","darksearch","onionsearch",
                                           "trufflehog","gitleaks",
                                           "socialanalyzer","leakix","hibp","intelx"])
    api_keys       = data.get("api_keys", {})

    t = threading.Thread(target=run_scan, args=(term, domain, active_modules, api_keys), daemon=True)
    t.start()
    return jsonify({"status": "started", "term": term, "domain": domain})


@app.route("/api/scan/status")
def scan_status():
    return jsonify({
        "running":         scan_state["running"],
        "progress":        scan_state["progress"],
        "current_module":  scan_state["current_module"],
        "stats":           scan_state["stats"],
        "log":             scan_state["log"][-30:],
        "started_at":      scan_state["started_at"],
        "finished_at":     scan_state["finished_at"],
    })


@app.route("/api/scan/findings")
def get_findings():
    risk_filter = request.args.get("risk", "all")
    findings = scan_state["findings"]
    if risk_filter != "all":
        findings = [f for f in findings if f.get("risk") == risk_filter]
    return jsonify({"findings": findings, "total": len(findings)})


@app.route("/api/scan/stop", methods=["POST"])
def stop_scan():
    scan_state["running"] = False
    log("Escaneo detenido manualmente", "warn")
    return jsonify({"status": "stopped"})


@app.route("/api/export/json")
def export_json():
    from flask import Response
    payload = json.dumps({
        "meta": {
            "term": "INE",
            "started_at": scan_state["started_at"],
            "stats": scan_state["stats"],
        },
        "findings": scan_state["findings"],
    }, ensure_ascii=False, indent=2)
    return Response(payload, mimetype="application/json",
                    headers={"Content-Disposition": "attachment;filename=cti-ine-findings.json"})


@app.route("/api/export/csv")
def export_csv():
    from flask import Response
    import csv, io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["#", "Fuente", "Título", "Categoría", "Riesgo", "URL", "Detalle", "Detectado"])
    for i, f in enumerate(scan_state["findings"], 1):
        writer.writerow([i, f.get("source",""), f.get("title",""),
                         f.get("category",""), f.get("risk",""),
                         f.get("url",""), f.get("detail",""), f.get("detected","")])
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=cti-ine-findings.csv"})


@app.route("/api/ail/test", methods=["POST"])
def ail_test():
    data = request.json or {}
    cfg = ail_config(data)
    try:
        result = ail_test_connection(cfg["base_url"], cfg["api_key"], cfg["verify_tls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/ail/export", methods=["POST"])
def ail_export():
    data = request.json or {}
    cfg = ail_config(data)
    findings = data.get("findings") or scan_state["findings"]
    try:
        result = ail_export_findings(
            cfg["base_url"],
            cfg["api_key"],
            findings,
            cfg["tags"],
            cfg["verify_tls"],
        )
        exported = len(result.get("exported", []))
        errors = len(result.get("errors", []))
        level = "ok" if errors == 0 else "warn"
        log(f"AIL export: {exported} enviado(s), {errors} error(es)", level)
        return jsonify(result)
    except Exception as e:
        log(f"AIL export error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/ail/tracker", methods=["POST"])
def ail_tracker():
    data = request.json or {}
    cfg = ail_config(data)
    term = data.get("term", "INE")
    try:
        result = ail_create_tracker(
            cfg["base_url"],
            cfg["api_key"],
            term,
            cfg["tracker_type"],
            cfg["tags"],
            cfg["verify_tls"],
        )
        log(f"AIL tracker creado: {result.get('uuid')} ({term})", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"AIL tracker error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/misp/test", methods=["POST"])
def misp_test():
    data = request.json or {}
    cfg = misp_config(data)
    try:
        result = misp_test_connection(cfg["base_url"], cfg["api_key"], cfg["verify_tls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/misp/export", methods=["POST"])
def misp_export():
    data = request.json or {}
    cfg = misp_config(data)
    findings = data.get("findings") or scan_state["findings"]
    info = data.get("info") or f"INE CTI Monitor - {datetime.now().strftime('%Y-%m-%d')}"
    try:
        result = misp_export_findings(
            cfg["base_url"],
            cfg["api_key"],
            findings,
            info,
            cfg["distribution"],
            cfg["threat_level_id"],
            cfg["analysis"],
            cfg["tags"],
            cfg["publish"],
            cfg["verify_tls"],
        )
        log(f"MISP export: evento {result.get('event_id')} con {result.get('attributes')} atributo(s)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"MISP export error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/apprise/test", methods=["POST"])
def apprise_test():
    data = request.json or {}
    cfg = apprise_config(data)
    try:
        result = apprise_test_connection(cfg["urls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/apprise/notify", methods=["POST"])
def apprise_notify():
    data = request.json or {}
    cfg = apprise_config(data)
    title = data.get("title") or "INE CTI Monitor - resumen"
    body = data.get("body") or scan_summary_text(
        data.get("term", "INE"),
        data.get("domain", "ine.mx"),
    )
    notify_type = data.get("type") or (
        "warning" if scan_state["stats"].get("high_critical", 0) else "info"
    )
    try:
        result = apprise_send_notification(cfg["urls"], title, body, notify_type)
        log(f"Apprise notificacion manual enviada a {result.get('targets')} destino(s)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"Apprise notify error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "2.6",
        "client": "INE",
        "onionsearch": True,
        "trufflehog": True,
        "gitleaks": True,
        "socialanalyzer": True,
        "apprise": True,
        "ail": True,
        "misp": True,
    })


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  INE CTI MONITOR — Backend iniciado")
    print("  URL: http://localhost:5000")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
