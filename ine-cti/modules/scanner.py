# -*- coding: utf-8 -*-
"""
INE CTI Scanner — Módulos de búsqueda adaptados de SpiderFoot + DarkSearch
Uso: monitoreo OSINT defensivo de información del INE expuesta públicamente
"""

import csv
import os
import requests
import shutil
import subprocess
import sys
import tempfile
import time
import json
import re
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import quote

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Accept-Language": "es-MX,es;q=0.9,en;q=0.8",
}

TIMEOUT = 12
ONIONSEARCH_TIMEOUT = 90
TRUFFLEHOG_TIMEOUT = 180
GITLEAKS_TIMEOUT = 180
SOCIAL_ANALYZER_TIMEOUT = 180


def ts():
    return datetime.now().strftime("%H:%M:%S")


# ─────────────────────────────────────────────
# MÓDULO 1 — GitHub Search
# ─────────────────────────────────────────────
def scan_github(term, token=None):
    results = []
    headers = HEADERS.copy()
    if token:
        headers["Authorization"] = f"token {token}"

    url = f"https://api.github.com/search/code?q={quote(term)}&per_page=10"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", []):
                results.append({
                    "source": "GitHub",
                    "source_id": "github",
                    "title": f"{item.get('name','archivo')} en {item.get('repository',{}).get('full_name','')}",
                    "url": item.get("html_url", "#"),
                    "category": "Código/Repositorio",
                    "category_class": "cat-repo",
                    "risk": "ALTO",
                    "risk_class": "risk-high",
                    "raw": item.get("html_url", ""),
                    "detail": f"Archivo: {item.get('path','')} | Repo: {item.get('repository',{}).get('full_name','')}",
                    "detected": ts(),
                })
        elif r.status_code == 403:
            results.append(_rate_limit_notice("GitHub"))
        elif r.status_code == 422:
            # Sin token solo permite búsquedas limitadas
            results.append(_fallback_dork("GitHub", term,
                f"https://github.com/search?q={quote(term)}&type=code"))
    except Exception as e:
        results.append(_error_notice("GitHub", str(e)))
    return results


# ─────────────────────────────────────────────
# MÓDULO 2 — Pastebin (vía búsqueda pública)
# ─────────────────────────────────────────────
def scan_pastebin(term):
    results = []
    # Pastebin bloquea scraping directo; usamos Google dork como fallback verificable
    url = (f"https://www.google.com/search?q=site%3Apastebin.com+"
           f"%22{quote(term)}%22&num=10")
    results.append({
        "source": "Pastebin",
        "source_id": "pastebin",
        "title": f'Búsqueda Google Dork: pastebin.com + "{term}"',
        "url": url,
        "category": "Pastebin/Leak",
        "category_class": "cat-paste",
        "risk": "CRÍTICO",
        "risk_class": "risk-critical",
        "raw": url,
        "detail": "Verificar manualmente — dork lista pastes públicos que contienen el término",
        "detected": ts(),
        "is_dork": True,
    })
    return results


# ─────────────────────────────────────────────
# MÓDULO 3 — AWS S3 Buckets públicos
# ─────────────────────────────────────────────
def scan_s3(term):
    results = []
    # Variantes comunes de nombres de bucket relacionados al término
    variants = [
        term.lower().replace(" ", "-"),
        term.lower().replace(" ", ""),
        f"{term.lower()}-backup",
        f"{term.lower()}-data",
        f"{term.lower()}-files",
        f"backup-{term.lower()}",
    ]
    for bucket in variants:
        bucket = re.sub(r'[^a-z0-9\-]', '', bucket)
        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            r = requests.get(url, timeout=6, headers=HEADERS)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                results.append({
                    "source": "AWS S3",
                    "source_id": "aws",
                    "title": f"Bucket S3 PÚBLICO encontrado: {bucket}",
                    "url": url,
                    "category": "Cloud Storage",
                    "category_class": "cat-cloud",
                    "risk": "CRÍTICO",
                    "risk_class": "risk-critical",
                    "raw": url,
                    "detail": f"Bucket {bucket} responde con listado público — verificar contenido inmediatamente",
                    "detected": ts(),
                })
            elif r.status_code == 403:
                # Existe pero está protegido — relevante como hallazgo menor
                results.append({
                    "source": "AWS S3",
                    "source_id": "aws",
                    "title": f"Bucket S3 existe (acceso restringido): {bucket}",
                    "url": url,
                    "category": "Cloud Storage",
                    "category_class": "cat-cloud",
                    "risk": "BAJO",
                    "risk_class": "risk-low",
                    "raw": url,
                    "detail": f"Bucket {bucket} existe pero tiene ACL restrictiva — monitorear cambios",
                    "detected": ts(),
                })
        except Exception:
            pass
        time.sleep(0.3)
    return results


# ─────────────────────────────────────────────
# MÓDULO 4 — Azure Blob Storage
# ─────────────────────────────────────────────
def scan_azure(term):
    results = []
    variants = [
        term.lower().replace(" ", ""),
        term.lower().replace(" ", "-"),
        f"{term.lower()}storage",
        f"{term.lower()}backup",
    ]
    for account in variants:
        account = re.sub(r'[^a-z0-9]', '', account)[:24]
        for container in ["public", "data", "files", "backup", "documentos"]:
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                r = requests.get(url, timeout=5, headers=HEADERS)
                if r.status_code == 200 and "EnumerationResults" in r.text:
                    results.append({
                        "source": "Azure Blob Storage",
                        "source_id": "azure",
                        "title": f"Container Azure PÚBLICO: {account}/{container}",
                        "url": url,
                        "category": "Cloud Storage",
                        "category_class": "cat-cloud",
                        "risk": "CRÍTICO",
                        "risk_class": "risk-critical",
                        "raw": url,
                        "detail": f"Container {container} en cuenta {account} es accesible públicamente",
                        "detected": ts(),
                    })
            except Exception:
                pass
        time.sleep(0.2)

    # Dork complementario
    dork_url = f"https://www.google.com/search?q=site%3Ablob.core.windows.net+%22{quote(term)}%22"
    results.append({
        "source": "Azure Blob Storage",
        "source_id": "azure",
        "title": f'Google Dork: Azure Blob + "{term}"',
        "url": dork_url,
        "category": "Cloud Storage",
        "category_class": "cat-cloud",
        "risk": "ALTO",
        "risk_class": "risk-high",
        "raw": dork_url,
        "detail": "Verificar manualmente resultados del dork en Google",
        "detected": ts(),
        "is_dork": True,
    })
    return results


# ─────────────────────────────────────────────
# MÓDULO 5 — Google Cloud Storage
# ─────────────────────────────────────────────
def scan_gcs(term):
    results = []
    dork_url = f"https://www.google.com/search?q=site%3Astorage.googleapis.com+%22{quote(term)}%22"
    results.append({
        "source": "Google Cloud Storage",
        "source_id": "gcloud",
        "title": f'Google Dork: GCS Bucket + "{term}"',
        "url": dork_url,
        "category": "Cloud Storage",
        "category_class": "cat-cloud",
        "risk": "ALTO",
        "risk_class": "risk-high",
        "raw": dork_url,
        "detail": "Verificar manualmente — busca buckets GCS públicos que contienen el término",
        "detected": ts(),
        "is_dork": True,
    })

    # Intento directo en bucket común
    bucket_name = re.sub(r'[^a-z0-9\-]', '', term.lower().replace(" ", "-"))
    url = f"https://storage.googleapis.com/{bucket_name}/"
    try:
        r = requests.get(url, timeout=6, headers=HEADERS)
        if r.status_code == 200:
            results.append({
                "source": "Google Cloud Storage",
                "source_id": "gcloud",
                "title": f"GCS Bucket público encontrado: {bucket_name}",
                "url": url,
                "category": "Cloud Storage",
                "category_class": "cat-cloud",
                "risk": "CRÍTICO",
                "risk_class": "risk-critical",
                "raw": url,
                "detail": f"Bucket gs://{bucket_name} responde públicamente",
                "detected": ts(),
            })
    except Exception:
        pass
    return results


# ─────────────────────────────────────────────
# MÓDULO 6 — Google Drive (dorks)
# ─────────────────────────────────────────────
def scan_googledrive(term):
    results = []
    dorks = [
        (f'site:drive.google.com "{term}"', "Google Drive — archivos compartidos"),
        (f'site:docs.google.com "{term}"', "Google Docs — documentos públicos"),
        (f'site:sheets.google.com "{term}"', "Google Sheets — hojas de cálculo"),
    ]
    for q, label in dorks:
        url = f"https://www.google.com/search?q={quote(q)}"
        results.append({
            "source": "Google Drive/Docs",
            "source_id": "googledrive",
            "title": f'{label}: "{term}"',
            "url": url,
            "category": "Repositorio Público",
            "category_class": "cat-repo",
            "risk": "ALTO",
            "risk_class": "risk-high",
            "raw": url,
            "detail": f"Dork: {q}",
            "detected": ts(),
            "is_dork": True,
        })
    return results


# ─────────────────────────────────────────────
# MÓDULO 7 — Dropbox / OneDrive / MediaFire
# ─────────────────────────────────────────────
def scan_file_repos(term):
    results = []
    sources = [
        ("dropbox.com", "Dropbox", "cat-repo", "ALTO", "risk-high"),
        ("1drv.ms OR onedrive.live.com", "OneDrive", "cat-repo", "MEDIO", "risk-medium"),
        ("mediafire.com", "MediaFire", "cat-repo", "MEDIO", "risk-medium"),
        ("mega.nz", "MEGA", "cat-repo", "ALTO", "risk-high"),
        ("box.com", "Box", "cat-repo", "MEDIO", "risk-medium"),
    ]
    for site, label, cat_class, risk, risk_class in sources:
        url = f"https://www.google.com/search?q=site%3A{quote(site)}+%22{quote(term)}%22"
        results.append({
            "source": label,
            "source_id": label.lower(),
            "title": f'{label} — archivos públicos con "{term}"',
            "url": url,
            "category": "Repositorio Público",
            "category_class": cat_class,
            "risk": risk,
            "risk_class": risk_class,
            "raw": url,
            "detail": f"Dork Google: site:{site} \"{term}\"",
            "detected": ts(),
            "is_dork": True,
        })
    return results


# ─────────────────────────────────────────────
# MÓDULO 8 — Ahmia (Dark Web indexada, sin Tor)
# ─────────────────────────────────────────────
def scan_ahmia(term):
    results = []
    url = f"https://ahmia.fi/search/?q={quote(term)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            hits = soup.select("li.result")
            if not hits:
                hits = soup.select(".result")
            for hit in hits[:8]:
                title_el = hit.select_one("h4") or hit.select_one("a")
                link_el  = hit.select_one("a")
                desc_el  = hit.select_one("p") or hit.select_one(".description")
                title = title_el.get_text(strip=True) if title_el else "Resultado dark web"
                link  = link_el.get("href", "#") if link_el else "#"
                desc  = desc_el.get_text(strip=True)[:120] if desc_el else ""
                results.append({
                    "source": "Ahmia (Dark Web)",
                    "source_id": "ahmia",
                    "title": title,
                    "url": link,
                    "category": "Dark Web Indexada",
                    "category_class": "cat-dark",
                    "risk": "CRÍTICO",
                    "risk_class": "risk-critical",
                    "raw": link,
                    "detail": desc or f"Contenido dark web indexado por Ahmia con referencia a '{term}'",
                    "detected": ts(),
                })
            if not results:
                results.append({
                    "source": "Ahmia (Dark Web)",
                    "source_id": "ahmia",
                    "title": f'Ahmia: sin resultados para "{term}"',
                    "url": url,
                    "category": "Dark Web Indexada",
                    "category_class": "cat-dark",
                    "risk": "BAJO",
                    "risk_class": "risk-low",
                    "raw": url,
                    "detail": "Sin hallazgos en dark web indexada por Ahmia",
                    "detected": ts(),
                    "is_negative": True,
                })
    except Exception as e:
        results.append(_error_notice("Ahmia", str(e)))
    return results


# ─────────────────────────────────────────────
# MÓDULO 9 — DarkSearch.io (dark web indexada)
# ─────────────────────────────────────────────
def scan_darksearch(term):
    results = []
    url = f"https://darksearch.io/api/search?query={quote(term)}&page=1"
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("data", [])[:8]:
                results.append({
                    "source": "DarkSearch.io",
                    "source_id": "darksearch",
                    "title": item.get("title", "Sitio dark web sin título"),
                    "url": item.get("link", "#"),
                    "category": "Dark Web Indexada",
                    "category_class": "cat-dark",
                    "risk": "CRÍTICO",
                    "risk_class": "risk-critical",
                    "raw": item.get("link", ""),
                    "detail": (item.get("description", "")[:150] or
                               f"Contenido dark web con referencia a '{term}'"),
                    "detected": ts(),
                })
        elif r.status_code == 429:
            results.append(_rate_limit_notice("DarkSearch.io"))
    except Exception as e:
        results.append(_error_notice("DarkSearch.io", str(e)))
    return results


# MÓDULO 9B — OnionSearch (múltiples motores .onion)
def scan_onionsearch(term, proxy=None, limit=1, engines=None):
    results = []
    exe = shutil.which("onionsearch") or shutil.which("onionsearch.exe")
    if not exe:
        results.append({
            "source": "OnionSearch",
            "source_id": "onionsearch",
            "title": "OnionSearch no está instalado",
            "url": "https://github.com/megadose/OnionSearch",
            "category": "Sistema",
            "category_class": "cat-dark",
            "risk": "INFO",
            "risk_class": "risk-low",
            "raw": "pip install onionsearch",
            "detail": "Instala dependencias con: pip install -r requirements.txt",
            "detected": ts(),
            "is_system": True,
        })
        return results

    try:
        limit = max(1, min(int(limit or 1), 5))
    except (TypeError, ValueError):
        limit = 1

    fd, output_path = tempfile.mkstemp(prefix="onionsearch_", suffix=".csv")
    os.close(fd)

    cmd = [
        exe,
        term,
        "--output", output_path,
        "--limit", str(limit),
        "--fields", "engine", "name", "link", "domain",
        "--mp_units", "1",
    ]
    if proxy:
        cmd.extend(["--proxy", proxy])
    if engines:
        selected = [e.strip() for e in str(engines).replace(",", " ").split() if e.strip()]
        if selected:
            cmd.append("--engines")
            cmd.extend(selected)

    try:
        subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=ONIONSEARCH_TIMEOUT,
        )

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            results.append({
                "source": "OnionSearch",
                "source_id": "onionsearch",
                "title": f'OnionSearch: sin resultados para "{term}"',
                "url": "https://github.com/megadose/OnionSearch",
                "category": "Dark Web Indexada",
                "category_class": "cat-dark",
                "risk": "BAJO",
                "risk_class": "risk-low",
                "raw": "",
                "detail": "No se generaron resultados en los motores consultados",
                "detected": ts(),
                "is_negative": True,
            })
            return results

        with open(output_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in list(reader)[:20]:
                link = (row.get("link") or row.get("url") or "").strip()
                name = (row.get("name") or "Resultado OnionSearch").strip()
                engine = (row.get("engine") or "OnionSearch").strip()
                domain = (row.get("domain") or "").strip()
                if not link:
                    continue
                results.append({
                    "source": f"OnionSearch/{engine}",
                    "source_id": "onionsearch",
                    "title": name,
                    "url": link,
                    "category": "Dark Web Indexada",
                    "category_class": "cat-dark",
                    "risk": "CRÍTICO",
                    "risk_class": "risk-critical",
                    "raw": link,
                    "detail": f"Motor: {engine}" + (f" | Dominio: {domain}" if domain else ""),
                    "detected": ts(),
                })
    except subprocess.TimeoutExpired:
        results.append(_error_notice("OnionSearch", "Tiempo máximo agotado; reduce motores o límite"))
    except Exception as e:
        results.append(_error_notice("OnionSearch", str(e)))
    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass

    return results


# MÓDULO 9C — TruffleHog (detección de secretos)
def scan_trufflehog(target, mode="git", results_filter="verified,unknown",
                    github_token=None, include_comments=False, max_findings=20):
    results = []
    exe = shutil.which("trufflehog") or shutil.which("trufflehog.exe")
    if not exe:
        results.append({
            "source": "TruffleHog",
            "source_id": "trufflehog",
            "title": "TruffleHog no está instalado",
            "url": "https://github.com/trufflesecurity/trufflehog",
            "category": "Sistema",
            "category_class": "cat-leak",
            "risk": "INFO",
            "risk_class": "risk-low",
            "raw": "trufflehog",
            "detail": "Instala el binario de TruffleHog y asegúrate de que esté en PATH",
            "detected": ts(),
            "is_system": True,
        })
        return results

    target = (target or "").strip()
    if not target:
        results.append({
            "source": "TruffleHog",
            "source_id": "trufflehog",
            "title": "TruffleHog sin objetivo configurado",
            "url": "https://github.com/trufflesecurity/trufflehog",
            "category": "Sistema",
            "category_class": "cat-leak",
            "risk": "INFO",
            "risk_class": "risk-low",
            "raw": "",
            "detail": "Configura un repositorio, organización o ruta local en Configuración",
            "detected": ts(),
            "is_system": True,
        })
        return results

    mode = (mode or "git").strip().lower()
    results_filter = (results_filter or "verified,unknown").strip()
    if results_filter not in ("verified", "verified,unknown", "verified,unverified,unknown"):
        results_filter = "verified,unknown"
    try:
        max_findings = max(1, min(int(max_findings or 20), 100))
    except (TypeError, ValueError):
        max_findings = 20

    if mode == "github-org":
        org = _github_org_from_target(target)
        cmd = [exe, "github", f"--org={org}"]
    elif mode == "github-repo":
        repo = _github_repo_url(target)
        cmd = [exe, "github", f"--repo={repo}"]
    elif mode == "filesystem":
        cmd = [exe, "filesystem", target]
    else:
        cmd = [exe, "git", target]

    cmd.extend([f"--results={results_filter}", "--json", "--no-update"])
    if include_comments and mode in ("github-repo", "github-org"):
        cmd.extend(["--issue-comments", "--pr-comments"])

    env = os.environ.copy()
    if github_token and mode in ("github-repo", "github-org"):
        env["GITHUB_TOKEN"] = github_token

    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=TRUFFLEHOG_TIMEOUT,
            env=env,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding = _trufflehog_finding(item, target)
            if finding:
                results.append(finding)
            if len(results) >= max_findings:
                break

        if not results:
            detail = "Sin secretos encontrados en el objetivo configurado"
            if proc.returncode not in (0, 183) and proc.stderr:
                detail = f"Sin hallazgos parseables; stderr: {proc.stderr[:140]}"
            results.append({
                "source": "TruffleHog",
                "source_id": "trufflehog",
                "title": f"TruffleHog: sin secretos para {target[:60]}",
                "url": target if target.startswith("http") else "https://github.com/trufflesecurity/trufflehog",
                "category": "Credenciales Filtradas",
                "category_class": "cat-leak",
                "risk": "BAJO",
                "risk_class": "risk-low",
                "raw": "",
                "detail": detail,
                "detected": ts(),
                "is_negative": True,
            })
    except subprocess.TimeoutExpired:
        results.append(_error_notice("TruffleHog", "Tiempo máximo agotado; reduce alcance o objetivo"))
    except Exception as e:
        results.append(_error_notice("TruffleHog", str(e)))

    return results


def _github_repo_url(target):
    target = target.strip()
    if target.startswith(("http://", "https://", "ssh://", "git@")):
        return target
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", target):
        return f"https://github.com/{target}"
    return target


def _github_org_from_target(target):
    target = target.strip().rstrip("/")
    m = re.search(r"github\.com[:/]+([^/\s]+)", target)
    if m:
        return m.group(1)
    if "/" in target and not target.startswith(("http://", "https://")):
        return target.split("/", 1)[0]
    return target


def _trufflehog_finding(item, fallback_url):
    detector = item.get("DetectorName") or item.get("DetectorType") or "Secreto"
    decoder = item.get("DecoderName") or "PLAIN"
    verified = bool(item.get("Verified"))
    redacted = item.get("Redacted") or "[redacted]"
    source_name = item.get("SourceName") or "TruffleHog"
    metadata = item.get("SourceMetadata", {}).get("Data", {})
    location = _trufflehog_location(metadata)
    url = _trufflehog_url(metadata, fallback_url)
    status = "verificado" if verified else "no verificado/unknown"
    risk = "CRÍTICO" if verified else "ALTO"
    risk_class = "risk-critical" if verified else "risk-high"
    detail = f"Detector: {detector} | Decoder: {decoder} | Estado: {status}"
    if location:
        detail += f" | Ubicación: {location}"

    return {
        "source": source_name,
        "source_id": "trufflehog",
        "title": f"TruffleHog: {detector} ({status})",
        "url": url or fallback_url or "https://github.com/trufflesecurity/trufflehog",
        "category": "Credenciales Filtradas",
        "category_class": "cat-leak",
        "risk": risk,
        "risk_class": risk_class,
        "raw": redacted,
        "detail": detail,
        "detected": ts(),
        "is_secret": True,
    }


def _trufflehog_location(metadata):
    if not isinstance(metadata, dict):
        return ""
    git = metadata.get("Git") or metadata.get("Github") or {}
    if isinstance(git, dict):
        parts = []
        if git.get("repository"):
            parts.append(git.get("repository"))
        if git.get("file"):
            file_part = git.get("file")
            if git.get("line"):
                file_part += f":{git.get('line')}"
            parts.append(file_part)
        if git.get("commit"):
            parts.append(str(git.get("commit"))[:12])
        if parts:
            return " | ".join(parts)
    return ""


def _trufflehog_url(metadata, fallback_url):
    if not isinstance(metadata, dict):
        return fallback_url
    git = metadata.get("Git") or metadata.get("Github") or {}
    if isinstance(git, dict):
        repo = git.get("repository") or fallback_url
        file_name = git.get("file")
        commit = git.get("commit")
        line = git.get("line")
        if repo and file_name and commit and str(repo).startswith("http"):
            url = f"{str(repo).rstrip('/')}/blob/{commit}/{file_name}"
            if line:
                url += f"#L{line}"
            return url
        if repo:
            return repo
    return fallback_url


# MÓDULO 9D — Gitleaks (detección de secretos)
def scan_gitleaks(target=".", mode="dir", config_path=None, baseline_path=None,
                  max_findings=20, max_target_mb=None, log_opts=None):
    results = []
    exe = shutil.which("gitleaks") or shutil.which("gitleaks.exe")
    if not exe:
        results.append({
            "source": "Gitleaks",
            "source_id": "gitleaks",
            "title": "Gitleaks no está instalado",
            "url": "https://github.com/gitleaks/gitleaks",
            "category": "Sistema",
            "category_class": "cat-leak",
            "risk": "INFO",
            "risk_class": "risk-low",
            "raw": "gitleaks",
            "detail": "Instala el binario de Gitleaks y asegúrate de que esté en PATH",
            "detected": ts(),
            "is_system": True,
        })
        return results

    target = (target or ".").strip()
    mode = (mode or "dir").strip().lower()
    if mode not in ("dir", "git"):
        mode = "dir"
    try:
        max_findings = max(1, min(int(max_findings or 20), 100))
    except (TypeError, ValueError):
        max_findings = 20

    fd, report_path = tempfile.mkstemp(prefix="gitleaks_", suffix=".json")
    os.close(fd)

    cmd = [
        exe,
        mode,
        "--report-format", "json",
        "--report-path", report_path,
        "--redact=100",
        "--no-banner",
        "--no-color",
        "--exit-code", "0",
    ]
    config_path = (config_path or "").strip()
    baseline_path = (baseline_path or "").strip()
    if config_path:
        cmd.extend(["--config", config_path])
    if baseline_path:
        cmd.extend(["--baseline-path", baseline_path])
    if max_target_mb:
        try:
            cmd.extend(["--max-target-megabytes", str(max(1, int(max_target_mb)))])
        except (TypeError, ValueError):
            pass
    if mode == "git" and log_opts:
        cmd.extend(["--log-opts", str(log_opts)])
    cmd.append(target)

    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=GITLEAKS_TIMEOUT,
        )

        data = []
        if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
            with open(report_path, "r", encoding="utf-8", errors="replace") as f:
                parsed = json.load(f)
                if isinstance(parsed, list):
                    data = parsed
                elif isinstance(parsed, dict):
                    data = parsed.get("Findings") or parsed.get("findings") or []

        for item in data[:max_findings]:
            finding = _gitleaks_finding(item, target)
            if finding:
                results.append(finding)

        if not results:
            detail = "Sin secretos encontrados en el objetivo configurado"
            if proc.returncode not in (0, 1) and proc.stderr:
                detail = f"Sin hallazgos parseables; stderr: {proc.stderr[:140]}"
            results.append({
                "source": "Gitleaks",
                "source_id": "gitleaks",
                "title": f"Gitleaks: sin secretos para {target[:60]}",
                "url": target if target.startswith("http") else "https://github.com/gitleaks/gitleaks",
                "category": "Credenciales Filtradas",
                "category_class": "cat-leak",
                "risk": "BAJO",
                "risk_class": "risk-low",
                "raw": "",
                "detail": detail,
                "detected": ts(),
                "is_negative": True,
            })
    except subprocess.TimeoutExpired:
        results.append(_error_notice("Gitleaks", "Tiempo máximo agotado; reduce alcance o objetivo"))
    except Exception as e:
        results.append(_error_notice("Gitleaks", str(e)))
    finally:
        try:
            os.remove(report_path)
        except OSError:
            pass

    return results


def _gitleaks_finding(item, fallback_url):
    if not isinstance(item, dict):
        return None
    rule_id = item.get("RuleID") or item.get("ruleID") or "secret"
    description = item.get("Description") or item.get("description") or rule_id
    file_name = item.get("File") or item.get("file") or ""
    line = item.get("StartLine") or item.get("Line") or item.get("line")
    commit = item.get("Commit") or item.get("commit") or ""
    fingerprint = item.get("Fingerprint") or item.get("fingerprint") or ""
    secret = item.get("Secret") or item.get("secret") or "[redacted]"
    match = item.get("Match") or item.get("match") or ""
    entropy = item.get("Entropy") or item.get("entropy")

    location = file_name
    if line:
        location = f"{location}:{line}" if location else f"line {line}"
    if commit:
        location = f"{location} | {str(commit)[:12]}" if location else str(commit)[:12]

    detail = f"Rule: {rule_id} | {description}"
    if location:
        detail += f" | Ubicación: {location}"
    if entropy:
        detail += f" | Entropía: {entropy}"
    if fingerprint:
        detail += f" | Fingerprint: {fingerprint}"

    return {
        "source": "Gitleaks",
        "source_id": "gitleaks",
        "title": f"Gitleaks: {description}",
        "url": _gitleaks_url(fallback_url, file_name, commit, line),
        "category": "Credenciales Filtradas",
        "category_class": "cat-leak",
        "risk": "ALTO",
        "risk_class": "risk-high",
        "raw": secret or match or "[redacted]",
        "detail": detail,
        "detected": ts(),
        "is_secret": True,
    }


def _gitleaks_url(fallback_url, file_name, commit=None, line=None):
    if fallback_url and str(fallback_url).startswith("http"):
        url = str(fallback_url).rstrip("/")
        if file_name and commit and "github.com" in url:
            url = f"{url}/blob/{commit}/{file_name}"
            if line:
                url += f"#L{line}"
        return url
    return fallback_url or "https://github.com/gitleaks/gitleaks"


# MÓDULO 9E — Social Analyzer (perfiles sociales)
def scan_social_analyzer(username, websites=None, top=100, mode="fast",
                         method="find", filter_value="good", profiles="detected",
                         metadata=False, extract=False, countries=None,
                         site_type=None, timeout=10, max_findings=30):
    results = []
    username = (username or "").strip()
    if not username:
        results.append({
            "source": "Social Analyzer",
            "source_id": "socialanalyzer",
            "title": "Social Analyzer sin usuario configurado",
            "url": "https://github.com/qeeqbox/social-analyzer",
            "category": "Sistema",
            "category_class": "cat-repo",
            "risk": "INFO",
            "risk_class": "risk-low",
            "raw": "",
            "detail": "Configura uno o varios usernames separados por coma en Configuración",
            "detected": ts(),
            "is_system": True,
        })
        return results

    try:
        top = max(1, min(int(top or 100), 1000))
    except (TypeError, ValueError):
        top = 100
    try:
        timeout = max(3, min(int(timeout or 10), 60))
    except (TypeError, ValueError):
        timeout = 10
    try:
        max_findings = max(1, min(int(max_findings or 30), 100))
    except (TypeError, ValueError):
        max_findings = 30

    mode = mode if mode in ("fast", "slow", "special") else "fast"
    method = method if method in ("find", "get", "all") else "find"
    filter_value = filter_value if filter_value else "good"
    profiles = profiles if profiles else "detected"

    exe = shutil.which("social-analyzer") or shutil.which("social-analyzer.exe")
    cmd = [exe] if exe else [sys.executable, "-m", "social-analyzer"]
    cmd.extend([
        "--username", username,
        "--mode", mode,
        "--method", method,
        "--filter", filter_value,
        "--profiles", profiles,
        "--top", str(top),
        "--timeout", str(timeout),
        "--output", "json",
        "--silent",
        "--trim",
    ])
    if websites:
        cmd.extend(["--websites"])
        cmd.extend(_split_cli_values(websites))
    if countries:
        cmd.extend(["--countries"])
        cmd.extend(_split_cli_values(countries))
    if site_type:
        cmd.extend(["--type", str(site_type).strip()])
    if metadata:
        cmd.append("--metadata")
    if extract:
        cmd.append("--extract")

    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=SOCIAL_ANALYZER_TIMEOUT,
        )
        data = _parse_social_analyzer_json(proc.stdout)
        for item in _social_analyzer_items(data):
            finding = _social_analyzer_finding(item, username)
            if finding:
                results.append(finding)
            if len(results) >= max_findings:
                break

        if not results:
            detail = "Sin perfiles detectados para el usuario configurado"
            if proc.returncode not in (0, 1) and proc.stderr:
                detail = f"Sin hallazgos parseables; stderr: {proc.stderr[:140]}"
            results.append({
                "source": "Social Analyzer",
                "source_id": "socialanalyzer",
                "title": f'Social Analyzer: sin perfiles para "{username}"',
                "url": "https://github.com/qeeqbox/social-analyzer",
                "category": "Perfil Social",
                "category_class": "cat-repo",
                "risk": "BAJO",
                "risk_class": "risk-low",
                "raw": username,
                "detail": detail,
                "detected": ts(),
                "is_negative": True,
            })
    except subprocess.TimeoutExpired:
        results.append(_error_notice("Social Analyzer", "Tiempo máximo agotado; reduce top/websites"))
    except Exception as e:
        results.append(_error_notice("Social Analyzer", str(e)))

    return results


def _split_cli_values(value):
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value or "").replace(",", " ").split() if v.strip()]


def _parse_social_analyzer_json(raw):
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            pass
    start = raw.find("[")
    end = raw.rfind("]")
    if start >= 0 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            pass
    return None


def _social_analyzer_items(data):
    items = []
    if isinstance(data, list):
        items.extend(data)
    elif isinstance(data, dict):
        for key in ("detected", "profiles", "results", "data", "items"):
            value = data.get(key)
            if isinstance(value, list):
                items.extend(value)
        if not items:
            for value in data.values():
                if isinstance(value, list):
                    items.extend(value)
                elif isinstance(value, dict):
                    items.append(value)
    return items


def _social_analyzer_finding(item, fallback_username):
    if not isinstance(item, dict):
        return None
    link = (
        item.get("link") or item.get("url") or item.get("profile")
        or item.get("profile_url") or item.get("website")
    )
    if not link or str(link).strip() in ("", "#"):
        return None

    site = item.get("name") or item.get("site") or item.get("website") or item.get("domain") or "Social"
    username = item.get("username") or item.get("user") or fallback_username
    rate = item.get("rate") or item.get("score") or item.get("rating") or item.get("probability")
    title = item.get("title") or f"Perfil posible: {username} en {site}"
    info = item.get("info") or item.get("text") or item.get("description") or ""
    risk, risk_class = _social_analyzer_risk(rate)
    detail = f"Sitio: {site}"
    if rate not in (None, ""):
        detail += f" | Rate: {rate}"
    if info:
        detail += f" | {str(info)[:120]}"

    return {
        "source": "Social Analyzer",
        "source_id": "socialanalyzer",
        "title": str(title)[:160],
        "url": str(link),
        "category": "Perfil Social",
        "category_class": "cat-repo",
        "risk": risk,
        "risk_class": risk_class,
        "raw": username,
        "detail": detail,
        "detected": ts(),
    }


def _social_analyzer_risk(rate):
    try:
        score = float(str(rate).replace("%", ""))
    except (TypeError, ValueError):
        score = 50
    if score >= 80:
        return "ALTO", "risk-high"
    if score >= 50:
        return "MEDIO", "risk-medium"
    return "BAJO", "risk-low"


# ─────────────────────────────────────────────
# MÓDULO 10 — LeakIX (servicios expuestos)
# ─────────────────────────────────────────────
def scan_leakix(term, api_key=None):
    results = []
    headers = HEADERS.copy()
    headers["Accept"] = "application/json"
    if api_key:
        headers["api-key"] = api_key

    url = f"https://leakix.net/search?scope=leak&q={quote(term)}&page=0"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json() if api_key else []
            for item in data[:6]:
                results.append({
                    "source": "LeakIX",
                    "source_id": "leakix",
                    "title": item.get("event_source", "Servicio expuesto") + " — " + item.get("host", ""),
                    "url": f"https://leakix.net/host/{item.get('host','')}",
                    "category": "Servicio Expuesto",
                    "category_class": "cat-cloud",
                    "risk": "ALTO",
                    "risk_class": "risk-high",
                    "raw": item.get("host", ""),
                    "detail": item.get("summary", f"Servicio expuesto relacionado con '{term}'")[:150],
                    "detected": ts(),
                })
        # Siempre agregar dork de LeakIX
        results.append({
            "source": "LeakIX",
            "source_id": "leakix",
            "title": f'LeakIX — servicios expuestos: "{term}"',
            "url": url,
            "category": "Servicio Expuesto",
            "category_class": "cat-cloud",
            "risk": "ALTO",
            "risk_class": "risk-high",
            "raw": url,
            "detail": "Plataforma que indexa servicios y datos expuestos en internet — verificar manualmente",
            "detected": ts(),
            "is_dork": True,
        })
    except Exception as e:
        results.append(_error_notice("LeakIX", str(e)))
    return results


# ─────────────────────────────────────────────
# MÓDULO 11 — Have I Been Pwned (dominios)
# ─────────────────────────────────────────────
def scan_hibp(domain, api_key=None):
    results = []
    if not api_key:
        # Sin API key solo podemos generar el dork
        url = f"https://haveibeenpwned.com/DomainSearch/{domain}"
        results.append({
            "source": "HaveIBeenPwned",
            "source_id": "hibp",
            "title": f"HIBP — verificar dominio: {domain}",
            "url": url,
            "category": "Credenciales Filtradas",
            "category_class": "cat-leak",
            "risk": "ALTO",
            "risk_class": "risk-high",
            "raw": url,
            "detail": "Requiere API key ($3.50/mes) para búsqueda automática — verificar manualmente en el sitio",
            "detected": ts(),
            "is_dork": True,
        })
        return results

    headers = HEADERS.copy()
    headers["hibp-api-key"] = api_key
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for email, breaches in list(data.items())[:10]:
                results.append({
                    "source": "HaveIBeenPwned",
                    "source_id": "hibp",
                    "title": f"Credencial filtrada: {email[:4]}***@{domain}",
                    "url": f"https://haveibeenpwned.com/account/{email}",
                    "category": "Credenciales Filtradas",
                    "category_class": "cat-leak",
                    "risk": "CRÍTICO",
                    "risk_class": "risk-critical",
                    "raw": email,
                    "detail": f"Encontrada en brechas: {', '.join(breaches[:5])}",
                    "detected": ts(),
                })
    except Exception as e:
        results.append(_error_notice("HIBP", str(e)))
    return results


# ─────────────────────────────────────────────
# MÓDULO 12 — IntelX (dark web + breaches)
# ─────────────────────────────────────────────
def scan_intelx(term, api_key=None):
    results = []
    if not api_key:
        url = f"https://intelx.io/?s={quote(term)}"
        results.append({
            "source": "Intelligence X",
            "source_id": "intelx",
            "title": f'IntelX — búsqueda: "{term}"',
            "url": url,
            "category": "Dark Web / Leaks",
            "category_class": "cat-dark",
            "risk": "ALTO",
            "risk_class": "risk-high",
            "raw": url,
            "detail": "Requiere API key gratuita en intelx.io — verificar manualmente",
            "detected": ts(),
            "is_dork": True,
        })
        return results

    try:
        # Iniciar búsqueda
        search_url = "https://2.intelx.io/intelligent/search"
        payload = {"term": term, "maxresults": 10, "media": 0, "target": 0}
        headers = HEADERS.copy()
        headers["x-key"] = api_key
        r = requests.post(search_url, json=payload, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            search_id = r.json().get("id")
            time.sleep(2)
            result_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=10"
            r2 = requests.get(result_url, headers=headers, timeout=TIMEOUT)
            if r2.status_code == 200:
                for item in r2.json().get("records", [])[:8]:
                    results.append({
                        "source": "Intelligence X",
                        "source_id": "intelx",
                        "title": item.get("name", "Registro IntelX"),
                        "url": f"https://intelx.io/?did={item.get('systemid','')}",
                        "category": "Dark Web / Leaks",
                        "category_class": "cat-dark",
                        "risk": "CRÍTICO",
                        "risk_class": "risk-critical",
                        "raw": item.get("name", ""),
                        "detail": f"Tipo: {item.get('type','')} | Fecha: {item.get('date','')[:10]}",
                        "detected": ts(),
                    })
    except Exception as e:
        results.append(_error_notice("IntelX", str(e)))
    return results


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def _rate_limit_notice(source):
    return {
        "source": source,
        "source_id": source.lower(),
        "title": f"{source} — límite de tasa alcanzado",
        "url": "#",
        "category": "Sistema",
        "category_class": "cat-repo",
        "risk": "INFO",
        "risk_class": "risk-low",
        "raw": "",
        "detail": "Rate limit — esperar antes de reintentar o usar API key",
        "detected": ts(),
        "is_system": True,
    }


def _error_notice(source, err):
    return {
        "source": source,
        "source_id": source.lower(),
        "title": f"{source} — error de conexión",
        "url": "#",
        "category": "Sistema",
        "category_class": "cat-repo",
        "risk": "INFO",
        "risk_class": "risk-low",
        "raw": "",
        "detail": f"Error: {err[:80]}",
        "detected": ts(),
        "is_system": True,
    }


def _fallback_dork(source, term, url):
    return {
        "source": source,
        "source_id": source.lower(),
        "title": f'{source} — dork manual: "{term}"',
        "url": url,
        "category": "Repositorio Público",
        "category_class": "cat-repo",
        "risk": "MEDIO",
        "risk_class": "risk-medium",
        "raw": url,
        "detail": "Verificar manualmente — abre el enlace para ver resultados",
        "detected": ts(),
        "is_dork": True,
    }
