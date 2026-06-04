# -*- coding: utf-8 -*-
"""
Dogui Ciberpatrullaje — Backend Flask
Ejecutar: python app.py
Acceder:  http://localhost:5000
"""

import json
import os
import re
import threading
import time
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, jsonify, request, send_from_directory, Response
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
from modules.changedetection_client import (
    export_findings_as_watches as changedetection_export_findings,
    scan_watches as changedetection_scan_watches,
    test_connection as changedetection_test_connection,
)
from modules.huginn_client import (
    export_findings as huginn_export_findings,
    test_connection as huginn_test_connection,
)
from modules.aleph_client import (
    search_entities as aleph_search_entities,
    test_connection as aleph_test_connection,
)
from modules.followthemoney_client import (
    normalize_findings as ftm_normalize_findings,
    test_normalizer as ftm_test_normalizer,
)
from modules.thehive_client import (
    export_findings as thehive_export_findings,
    test_connection as thehive_test_connection,
)
from modules.shuffle_client import (
    export_findings as shuffle_export_findings,
    test_connection as shuffle_test_connection,
)
from modules.projectdiscovery_client import (
    scan_httpx as pd_scan_httpx,
    scan_naabu as pd_scan_naabu,
    scan_nuclei as pd_scan_nuclei,
    scan_subfinder as pd_scan_subfinder,
)
from modules.sigma_client import (
    load_rules as sigma_load_rules,
    test_rules as sigma_test_rules,
)
from analyzers.urlscan_analyzer import (
    submit_many as urlscan_submit_many,
    test_connection as urlscan_test_connection,
)
from analyzers.yara_document_scanner import (
    scan_documents as yara_scan_documents,
    test_scanner as yara_test_scanner,
)
from modules.intelligence import (
    DEFAULT_FP_RULES,
    DEFAULT_WATCHLIST,
    analyze_file_text,
    analyze_typosquatting,
    apply_false_positive_rules,
    build_dashboard,
    deduplicate_findings,
    export_stix,
    export_xlsx,
    finding_signature,
    load_json,
    read_file_for_analysis,
    render_pdf,
    report_lines,
    save_json,
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
    "term": "",
    "domain": "",
    "date_from": "",
    "date_to": "",
}

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
RESULTS_FILE = os.path.join(RESULTS_DIR, "findings.json")
WATCHLIST_FILE = os.path.join(RESULTS_DIR, "watchlist.json")
FP_RULES_FILE = os.path.join(RESULTS_DIR, "false_positive_rules.json")
os.makedirs(RESULTS_DIR, exist_ok=True)


KNOWN_TARGET_DOMAINS = {
    "ine": "ine.mx",
    "instituto nacional electoral": "ine.mx",
    "banobras": "banobras.gob.mx",
    "banco nacional de obras": "banobras.gob.mx",
    "imss": "imss.gob.mx",
    "issste": "issste.gob.mx",
    "cfe": "cfe.mx",
    "comision federal de electricidad": "cfe.mx",
    "sat": "sat.gob.mx",
    "servicio de administracion tributaria": "sat.gob.mx",
    "unam": "unam.mx",
    "ipn": "ipn.mx",
}


def normalize_search_term(value):
    return str(value or "").strip().strip("\"'")


def normalize_domain(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "@" in text and "://" not in text:
        text = text.rsplit("@", 1)[-1]
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.netloc or parsed.path.split("/")[0]
    text = text.split("@")[-1].split("/")[0].split(":")[0].strip(".")
    text = re.sub(r"[^a-z0-9.-]", "", text)
    return text[4:] if text.startswith("www.") else text


def looks_like_domain(value):
    return bool(re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", normalize_domain(value)))


def infer_domain_from_term(term):
    text = normalize_search_term(term)
    low = text.lower()
    if not low:
        return ""
    if "@" in low or looks_like_domain(low):
        return normalize_domain(low)
    plain = (
        low.replace("á", "a").replace("é", "e").replace("í", "i")
        .replace("ó", "o").replace("ú", "u").replace("ü", "u")
    )
    for needle, domain in KNOWN_TARGET_DOMAINS.items():
        if re.search(rf"\b{re.escape(needle)}\b", plain):
            return domain
    return ""


def normalize_date(value):
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", text)
    if not match:
        return ""
    try:
        datetime.strptime(match.group(1), "%Y-%m-%d")
        return match.group(1)
    except ValueError:
        return ""


def finding_publication_date(finding):
    for key in ("published_at", "indexed_at", "source_date", "updated_at"):
        value = normalize_date(finding.get(key))
        if value:
            return value
    return ""


def finding_publication_label(finding):
    published = finding_publication_date(finding)
    if published:
        return published
    start = normalize_date(finding.get("date_range_from"))
    end = normalize_date(finding.get("date_range_to"))
    if start or end:
        return f"Rango aplicado: {start or 'sin inicio'} a {end or 'sin fin'}"
    return "No disponible"


def finding_in_date_range(finding, date_from="", date_to=""):
    pub_date = finding_publication_date(finding)
    if not pub_date:
        return True
    if date_from and pub_date < date_from:
        return False
    if date_to and pub_date > date_to:
        return False
    return True


def filter_findings_by_date(findings, date_from="", date_to=""):
    if not date_from and not date_to:
        return findings
    return [finding for finding in findings or [] if finding_in_date_range(finding, date_from, date_to)]


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


def changedetection_config(data):
    keys = data.get("api_keys", data)
    return {
        "base_url": keys.get("changedetection_url", ""),
        "api_key": keys.get("changedetection_key", ""),
        "tag": keys.get("changedetection_tag", "ine-cti"),
        "limit": keys.get("changedetection_limit", 20),
        "recheck": as_bool(keys.get("changedetection_recheck")),
        "verify_tls": as_bool(keys.get("changedetection_verify_tls")),
    }


def huginn_config(data):
    keys = data.get("api_keys", data)
    return {
        "webhook_url": keys.get("huginn_webhook_url", ""),
        "limit": keys.get("huginn_limit", 20),
        "verify_tls": as_bool(keys.get("huginn_verify_tls")),
    }


def aleph_config(data):
    keys = data.get("api_keys", data)
    return {
        "base_url": keys.get("aleph_url", "https://aleph.occrp.org"),
        "api_key": keys.get("aleph_key", ""),
        "schemata": keys.get("aleph_schemata", ""),
        "limit": keys.get("aleph_limit", 10),
        "verify_tls": as_bool(keys.get("aleph_verify_tls")),
    }


def ftm_config(data):
    keys = data.get("api_keys", data)
    return {
        "dataset": keys.get("ftm_dataset", "ine-cti-monitor"),
        "limit": keys.get("ftm_limit", 100),
    }


def thehive_config(data):
    keys = data.get("api_keys", data)
    return {
        "base_url": keys.get("thehive_url", ""),
        "api_key": keys.get("thehive_key", ""),
        "org": keys.get("thehive_org", ""),
        "limit": keys.get("thehive_limit", 20),
        "verify_tls": as_bool(keys.get("thehive_verify_tls")),
    }


def shuffle_config(data):
    keys = data.get("api_keys", data)
    return {
        "webhook_url": keys.get("shuffle_webhook_url", ""),
        "token": keys.get("shuffle_token", ""),
        "limit": keys.get("shuffle_limit", 20),
        "verify_tls": as_bool(keys.get("shuffle_verify_tls")),
    }


def projectdiscovery_config(data):
    keys = data.get("api_keys", data)
    return {
        "target": keys.get("pd_target", ""),
        "limit": keys.get("pd_limit", 50),
        "ports": keys.get("pd_ports", ""),
        "nuclei_templates": keys.get("nuclei_templates", ""),
        "nuclei_severity": keys.get("nuclei_severity", ""),
        "nuclei_tags": keys.get("nuclei_tags", ""),
        "timeout": keys.get("pd_timeout", 240),
    }


def urlscan_config(data):
    keys = data.get("api_keys", data)
    return {
        "api_key": keys.get("urlscan_key", ""),
        "visibility": keys.get("urlscan_visibility", "unlisted"),
        "tags": keys.get("urlscan_tags", "ine-cti"),
        "limit": keys.get("urlscan_limit", 10),
    }


def sigma_config(data):
    keys = data.get("api_keys", data)
    return {
        "rules_path": keys.get("sigma_rules_path", ""),
        "limit": keys.get("sigma_limit", 50),
    }


def yara_config(data):
    keys = data.get("api_keys", data)
    return {
        "rules_path": keys.get("yara_rules_path", ""),
        "target_path": keys.get("yara_target_path", ""),
        "recursive": as_bool(keys.get("yara_recursive")),
        "max_files": keys.get("yara_max_files", 200),
    }


def scan_summary_text(term="", domain=""):
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
    title = f"Dogui Ciberpatrullaje - {scan_state['stats'].get('total_findings', 0)} hallazgo(s)"
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
        key = f.get("dedupe_key") or finding_signature(f)
        f["dedupe_key"] = key
        existing = next((item for item in scan_state["findings"] if item.get("dedupe_key") == key), None)
        if existing:
            existing["duplicate_count"] = int(existing.get("duplicate_count") or 1) + 1
            existing["last_detected"] = f.get("detected") or datetime.now().isoformat()
            sources = set(existing.get("sources_seen") or [existing.get("source", "")])
            if f.get("source"):
                sources.add(f.get("source"))
            existing["sources_seen"] = sorted(s for s in sources if s)
            log("Hallazgo ya existente. Se actualizo ultima fecha de deteccion.", "info")
            continue
        f.setdefault("duplicate_count", 1)
        f.setdefault("first_detected", f.get("detected") or datetime.now().isoformat())
        f.setdefault("last_detected", f.get("detected") or f["first_detected"])
        f.setdefault("sources_seen", [f.get("source", "")] if f.get("source") else [])
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


def run_scan(term, domain, active_modules, api_keys, date_from="", date_to=""):
    scan_state["running"] = True
    scan_state["progress"] = 0
    scan_state["log"] = []
    scan_state["findings"] = []
    scan_state["started_at"] = datetime.now().isoformat()
    scan_state["finished_at"] = None
    scan_state["term"] = term
    scan_state["domain"] = domain
    scan_state["date_from"] = date_from
    scan_state["date_to"] = date_to
    for k in scan_state["stats"]:
        scan_state["stats"][k] = 0

    log(f"Iniciando escaneo CTI — término: '{term}' | dominio: '{domain}'", "info")
    log(f"Módulos activos: {', '.join(active_modules)}", "info")

    if date_from or date_to:
        log(f"Filtro temporal: {date_from or 'sin inicio'} a {date_to or 'sin fin'}", "info")

    modules = [
        ("github",      "GitHub / GitLab",         lambda: scan_github(term, api_keys.get("github"), date_from, date_to)),
        ("pastebin",    "Pastebin",                 lambda: scan_pastebin(term, date_from, date_to)),
        ("googledrive", "Google Drive / Docs",      lambda: scan_googledrive(term, date_from, date_to)),
        ("filerepos",   "Dropbox / OneDrive / MEGA",lambda: scan_file_repos(term, date_from, date_to)),
        ("aws",         "AWS S3 Buckets",           lambda: scan_s3(term)),
        ("azure",       "Azure Blob Storage",       lambda: scan_azure(term, date_from, date_to)),
        ("gcloud",      "Google Cloud Storage",     lambda: scan_gcs(term, date_from, date_to)),
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
        ("changedetection", "changedetection.io",   lambda: changedetection_scan_watches(
            changedetection_config(api_keys)["base_url"],
            changedetection_config(api_keys)["api_key"],
            changedetection_config(api_keys)["tag"],
            changedetection_config(api_keys)["recheck"],
            changedetection_config(api_keys)["limit"],
            changedetection_config(api_keys)["verify_tls"],
        )),
        ("aleph",       "Aleph",                    lambda: aleph_search_entities(
            aleph_config(api_keys)["base_url"],
            term,
            aleph_config(api_keys)["api_key"],
            aleph_config(api_keys)["schemata"],
            aleph_config(api_keys)["limit"],
            aleph_config(api_keys)["verify_tls"],
        )),
        ("subfinder",   "ProjectDiscovery subfinder", lambda: pd_scan_subfinder(
            projectdiscovery_config(api_keys)["target"] or domain,
            projectdiscovery_config(api_keys)["limit"],
            projectdiscovery_config(api_keys)["timeout"],
        )),
        ("httpx",       "ProjectDiscovery httpx", lambda: pd_scan_httpx(
            projectdiscovery_config(api_keys)["target"] or domain,
            projectdiscovery_config(api_keys)["limit"],
            projectdiscovery_config(api_keys)["timeout"],
        )),
        ("naabu",       "ProjectDiscovery naabu", lambda: pd_scan_naabu(
            projectdiscovery_config(api_keys)["target"] or domain,
            projectdiscovery_config(api_keys)["ports"],
            projectdiscovery_config(api_keys)["limit"],
            projectdiscovery_config(api_keys)["timeout"],
        )),
        ("nuclei",      "ProjectDiscovery nuclei", lambda: pd_scan_nuclei(
            projectdiscovery_config(api_keys)["target"] or domain,
            projectdiscovery_config(api_keys)["nuclei_templates"],
            projectdiscovery_config(api_keys)["nuclei_severity"],
            projectdiscovery_config(api_keys)["nuclei_tags"],
            projectdiscovery_config(api_keys)["limit"],
            projectdiscovery_config(api_keys)["timeout"],
        )),
        ("leakix",      "LeakIX",                   lambda: scan_leakix(term, api_keys.get("leakix"), date_from, date_to)),
        ("hibp",        "HaveIBeenPwned",           lambda: scan_hibp(domain, api_keys.get("hibp"))),
        ("intelx",      "Intelligence X",           lambda: scan_intelx(term, api_keys.get("intelx"), date_from, date_to)),
    ]

    active = [(mid, mlabel, mfn) for mid, mlabel, mfn in modules if mid in active_modules]
    total = len(active)

    for i, (mid, mlabel, mfn) in enumerate(active):
        scan_state["current_module"] = mlabel
        scan_state["progress"] = int((i / total) * 100)
        scan_state["stats"]["sources_scanned"] = i + 1
        log(f"[{i+1}/{total}] Escaneando: {mlabel}...", "info")

        try:
            results = filter_findings_by_date(mfn(), date_from, date_to)
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
                    "date_from": date_from,
                    "date_to": date_to,
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
    term           = normalize_search_term(data.get("term"))
    if not term:
        return jsonify({"error": "Termino de busqueda requerido"}), 400
    domain         = normalize_domain(data.get("domain")) or infer_domain_from_term(term)
    date_from      = normalize_date(data.get("date_from"))
    date_to        = normalize_date(data.get("date_to"))
    if date_from and date_to and date_from > date_to:
        return jsonify({"error": "Rango de fechas invalido: date_from no puede ser mayor que date_to"}), 400
    active_modules = data.get("modules", ["github","pastebin","googledrive",
                                           "filerepos","aws","azure","gcloud",
                                           "ahmia","darksearch","onionsearch",
                                           "trufflehog","gitleaks",
                                           "socialanalyzer","changedetection",
                                           "aleph","subfinder","httpx",
                                           "naabu","nuclei","leakix","hibp","intelx"])
    api_keys       = data.get("api_keys", {})

    t = threading.Thread(target=run_scan, args=(term, domain, active_modules, api_keys, date_from, date_to), daemon=True)
    t.start()
    return jsonify({"status": "started", "term": term, "domain": domain, "date_from": date_from, "date_to": date_to})


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
        "date_from":       scan_state.get("date_from", ""),
        "date_to":         scan_state.get("date_to", ""),
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
            "term": scan_state.get("term", ""),
            "domain": scan_state.get("domain", ""),
            "date_from": scan_state.get("date_from", ""),
            "date_to": scan_state.get("date_to", ""),
            "started_at": scan_state["started_at"],
            "stats": scan_state["stats"],
        },
        "findings": scan_state["findings"],
    }, ensure_ascii=False, indent=2)
    return Response(payload, mimetype="application/json",
                    headers={"Content-Disposition": "attachment;filename=dogui-ciberpatrullaje-findings.json"})


@app.route("/api/export/csv")
def export_csv():
    from flask import Response
    import csv, io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["#", "Fuente", "Titulo", "Categoria", "Riesgo", "Publicado/Indexado", "Fuente fecha", "URL", "Detalle", "Detectado"])
    for i, f in enumerate(scan_state["findings"], 1):
        writer.writerow([i, f.get("source",""), f.get("title",""),
                         f.get("category",""), f.get("risk",""),
                         finding_publication_label(f),
                         f.get("date_source","") or f.get("date_status",""),
                         f.get("url",""), f.get("detail",""), f.get("detected","")])
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=dogui-ciberpatrullaje-findings.csv"})


@app.route("/api/export/excel", methods=["GET", "POST"])
def export_excel():
    data = request.json or {} if request.method == "POST" else {}
    findings = data.get("findings") or scan_state["findings"]
    payload = export_xlsx(findings)
    return Response(
        payload,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment;filename=dogui-ciberpatrullaje-findings.xlsx"},
    )


@app.route("/api/export/stix", methods=["GET", "POST"])
def export_stix_bundle():
    data = request.json or {} if request.method == "POST" else {}
    findings = data.get("findings") or scan_state["findings"]
    payload = json.dumps(export_stix(findings), ensure_ascii=False, indent=2)
    return Response(
        payload,
        mimetype="application/stix+json",
        headers={"Content-Disposition": "attachment;filename=dogui-ciberpatrullaje-stix-bundle.json"},
    )


@app.route("/api/report/pdf", methods=["POST"])
def report_pdf():
    data = request.json or {}
    if not data.get("findings"):
        data["findings"] = scan_state["findings"]
    if not data.get("stats"):
        data["stats"] = scan_state["stats"]
    payload = render_pdf(report_lines(data))
    return Response(
        payload,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment;filename=dogui-ciberpatrullaje-reporte-ejecutivo.pdf"},
    )


@app.route("/api/intel/dashboard", methods=["GET", "POST"])
def intel_dashboard():
    data = request.json or {} if request.method == "POST" else {}
    findings = data.get("findings") or scan_state["findings"]
    stats = data.get("stats") or scan_state["stats"]
    watchlist = data.get("watchlist") or load_json(WATCHLIST_FILE, DEFAULT_WATCHLIST)
    rules = data.get("false_positive_rules") or load_json(FP_RULES_FILE, DEFAULT_FP_RULES)
    reviewed = apply_false_positive_rules(findings, rules)
    official_domain = normalize_domain(data.get("domain")) or scan_state.get("domain", "")
    dashboard = build_dashboard(reviewed["findings"], stats, data.get("validated"), watchlist, rules, official_domain=official_domain)
    dashboard["false_positives"] = {
        "count": reviewed["count"],
        "matches": reviewed["matches"],
        "rules": rules,
    }
    return jsonify(dashboard)


@app.route("/api/intel/deduplicate", methods=["POST"])
def intel_deduplicate():
    data = request.json or {}
    findings = data.get("findings") or scan_state["findings"]
    return jsonify(deduplicate_findings(findings))


@app.route("/api/intel/false-positives/apply", methods=["POST"])
def intel_false_positives():
    data = request.json or {}
    findings = data.get("findings") or scan_state["findings"]
    rules = data.get("rules") or load_json(FP_RULES_FILE, DEFAULT_FP_RULES)
    return jsonify(apply_false_positive_rules(findings, rules))


@app.route("/api/watchlist", methods=["GET", "POST"])
def watchlist_api():
    if request.method == "POST":
        data = request.json or {}
        watchlist = data.get("watchlist") or DEFAULT_WATCHLIST
        return jsonify({"status": "ok", "watchlist": save_json(WATCHLIST_FILE, watchlist)})
    return jsonify({"watchlist": load_json(WATCHLIST_FILE, DEFAULT_WATCHLIST)})


@app.route("/api/false-positive-rules", methods=["GET", "POST"])
def false_positive_rules_api():
    if request.method == "POST":
        data = request.json or {}
        rules = data.get("rules") or DEFAULT_FP_RULES
        return jsonify({"status": "ok", "rules": save_json(FP_RULES_FILE, rules)})
    return jsonify({"rules": load_json(FP_RULES_FILE, DEFAULT_FP_RULES)})


@app.route("/api/typosquatting/analyze", methods=["POST"])
def typosquatting_api():
    data = request.json or {}
    target = normalize_domain(data.get("target")) or infer_domain_from_term(data.get("term", ""))
    if not target:
        return jsonify({"error": "Dominio base requerido para typosquatting"}), 400
    candidates = data.get("domains") or []
    if isinstance(candidates, str):
        candidates = [x.strip() for x in candidates.replace("\r", "\n").split("\n") if x.strip()]
    return jsonify({"target": target, "results": analyze_typosquatting(target, candidates)})


@app.route("/api/files/analyze", methods=["POST"])
def files_analyze_api():
    data = request.json or {}
    if data.get("path"):
        text = read_file_for_analysis(data["path"])
        result = analyze_file_text(os.path.basename(data["path"]), text)
        return jsonify(result)
    name = data.get("name") or "archivo.txt"
    text = data.get("text") or ""
    return jsonify(analyze_file_text(name, text))


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
    term = normalize_search_term(data.get("term"))
    if not term:
        return jsonify({"status": "error", "error": "Termino requerido para crear tracker"}), 400
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
    info = data.get("info") or f"Dogui Ciberpatrullaje - {datetime.now().strftime('%Y-%m-%d')}"
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
    title = data.get("title") or "Dogui Ciberpatrullaje - resumen"
    term = normalize_search_term(data.get("term")) or scan_state.get("term", "")
    domain = normalize_domain(data.get("domain")) or scan_state.get("domain", "") or infer_domain_from_term(term)
    body = data.get("body") or scan_summary_text(
        term,
        domain,
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


@app.route("/api/changedetection/test", methods=["POST"])
def changedetection_test():
    data = request.json or {}
    cfg = changedetection_config(data)
    try:
        result = changedetection_test_connection(cfg["base_url"], cfg["api_key"], cfg["verify_tls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/changedetection/export", methods=["POST"])
def changedetection_export():
    data = request.json or {}
    cfg = changedetection_config(data)
    findings = data.get("findings") or scan_state["findings"]
    try:
        result = changedetection_export_findings(
            cfg["base_url"],
            cfg["api_key"],
            findings,
            cfg["tag"],
            cfg["limit"],
            cfg["verify_tls"],
        )
        log(f"changedetection.io export: {len(result.get('exported', []))} watch(es)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"changedetection.io export error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/huginn/test", methods=["POST"])
def huginn_test():
    data = request.json or {}
    cfg = huginn_config(data)
    try:
        result = huginn_test_connection(cfg["webhook_url"], cfg["verify_tls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/huginn/export", methods=["POST"])
def huginn_export():
    data = request.json or {}
    cfg = huginn_config(data)
    findings = data.get("findings") or scan_state["findings"]
    term = normalize_search_term(data.get("term")) or scan_state.get("term", "")
    domain = normalize_domain(data.get("domain")) or scan_state.get("domain", "") or infer_domain_from_term(term)
    try:
        result = huginn_export_findings(
            cfg["webhook_url"],
            findings,
            term,
            domain,
            cfg["limit"],
            cfg["verify_tls"],
        )
        log(f"Huginn export: {len(result.get('sent', []))} evento(s)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"Huginn export error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/aleph/test", methods=["POST"])
def aleph_test():
    data = request.json or {}
    cfg = aleph_config(data)
    try:
        result = aleph_test_connection(cfg["base_url"], cfg["api_key"], cfg["verify_tls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/aleph/search", methods=["POST"])
def aleph_search():
    data = request.json or {}
    cfg = aleph_config(data)
    query = normalize_search_term(data.get("term") or data.get("query"))
    if not query:
        return jsonify({"status": "error", "error": "Termino requerido para buscar en Aleph"}), 400
    try:
        findings = aleph_search_entities(
            cfg["base_url"],
            query,
            cfg["api_key"],
            cfg["schemata"],
            cfg["limit"],
            cfg["verify_tls"],
        )
        return jsonify({"status": "ok", "findings": findings, "total": len(findings)})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/followthemoney/test", methods=["POST"])
def followthemoney_test():
    try:
        return jsonify(ftm_test_normalizer())
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/followthemoney/export", methods=["POST"])
def followthemoney_export():
    data = request.json or {}
    cfg = ftm_config(data)
    findings = data.get("findings") or scan_state["findings"]
    try:
        result = ftm_normalize_findings(findings, cfg["dataset"], cfg["limit"])
        log(f"FollowTheMoney export: {result.get('count', 0)} entidad(es)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"FollowTheMoney export error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/thehive/test", methods=["POST"])
def thehive_test():
    data = request.json or {}
    cfg = thehive_config(data)
    try:
        result = thehive_test_connection(cfg["base_url"], cfg["api_key"], cfg["org"], cfg["verify_tls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/thehive/export", methods=["POST"])
def thehive_export():
    data = request.json or {}
    cfg = thehive_config(data)
    findings = data.get("findings") or scan_state["findings"]
    try:
        result = thehive_export_findings(
            cfg["base_url"],
            cfg["api_key"],
            findings,
            cfg["org"],
            cfg["limit"],
            cfg["verify_tls"],
        )
        log(f"TheHive export: {len(result.get('exported', []))} alerta(s)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"TheHive export error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/shuffle/test", methods=["POST"])
def shuffle_test():
    data = request.json or {}
    cfg = shuffle_config(data)
    try:
        result = shuffle_test_connection(cfg["webhook_url"], cfg["token"], cfg["verify_tls"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/shuffle/export", methods=["POST"])
def shuffle_export():
    data = request.json or {}
    cfg = shuffle_config(data)
    findings = data.get("findings") or scan_state["findings"]
    try:
        result = shuffle_export_findings(
            cfg["webhook_url"],
            findings,
            cfg["token"],
            cfg["limit"],
            cfg["verify_tls"],
        )
        log(f"Shuffle export: {len(result.get('sent', []))} evento(s)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"Shuffle export error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/urlscan/test", methods=["POST"])
def urlscan_test():
    data = request.json or {}
    cfg = urlscan_config(data)
    try:
        result = urlscan_test_connection(cfg["api_key"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/urlscan/submit", methods=["POST"])
def urlscan_submit():
    data = request.json or {}
    cfg = urlscan_config(data)
    findings = data.get("findings") or scan_state["findings"]
    try:
        result = urlscan_submit_many(
            cfg["api_key"],
            findings,
            cfg["visibility"],
            cfg["tags"],
            cfg["limit"],
        )
        log(f"urlscan.io submit: {len(result.get('submitted', []))} URL(s)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"urlscan.io submit error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/sigma/test", methods=["POST"])
def sigma_test():
    data = request.json or {}
    cfg = sigma_config(data)
    try:
        result = sigma_test_rules(cfg["rules_path"], min(int(cfg["limit"] or 5), 5))
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/sigma/rules", methods=["POST"])
def sigma_rules():
    data = request.json or {}
    cfg = sigma_config(data)
    try:
        result = sigma_load_rules(cfg["rules_path"], cfg["limit"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/yara/test", methods=["POST"])
def yara_test():
    data = request.json or {}
    cfg = yara_config(data)
    try:
        result = yara_test_scanner(cfg["rules_path"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/yara/scan", methods=["POST"])
def yara_scan():
    data = request.json or {}
    cfg = yara_config(data)
    try:
        result = yara_scan_documents(
            cfg["rules_path"],
            cfg["target_path"],
            cfg["recursive"],
            cfg["max_files"],
        )
        log(f"YARA scan: {result.get('count', 0)} match(es)", "ok")
        return jsonify(result)
    except Exception as e:
        log(f"YARA scan error: {e}", "error")
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "3.1",
        "client": "DOGUI",
        "executive_dashboard": True,
        "report_generator": True,
        "excel_export": True,
        "stix_export": True,
        "watchlist": True,
        "typosquatting": True,
        "file_analysis": True,
        "deduplication": True,
        "false_positive_rules": True,
        "onionsearch": True,
        "trufflehog": True,
        "gitleaks": True,
        "socialanalyzer": True,
        "apprise": True,
        "changedetection": True,
        "huginn": True,
        "aleph": True,
        "followthemoney": True,
        "thehive": True,
        "shuffle": True,
        "subfinder": True,
        "httpx": True,
        "naabu": True,
        "nuclei": True,
        "urlscan": True,
        "sigma": True,
        "yara": True,
        "ail": True,
        "misp": True,
    })


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  DOGUI CIBERPATRULLAJE — Backend iniciado")
    print("  URL: http://localhost:5000")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
