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
    scan_hibp, scan_intelx
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
                                           "ahmia","darksearch","leakix","hibp","intelx"])
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


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "2.0", "client": "INE"})


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  INE CTI MONITOR — Backend iniciado")
    print("  URL: http://localhost:5000")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
