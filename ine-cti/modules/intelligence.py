import csv
import difflib
import hashlib
import io
import json
import os
import re
import uuid
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, date
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape


DEFAULT_WATCHLIST = {
    "Identidad": ["CURP", "RFC", "DNI", "pasaporte", "OCR", "CIC"],
    "Credenciales": [
        "password",
        "contraseña",
        "api key",
        "token",
        "secret",
        "credenciales",
    ],
    "Riesgo digital": [
        "database",
        "dump",
        "sql",
        "backup",
        "xlsx",
        "csv",
        "confidencial",
    ],
    "Infraestructura": [
        "admin",
        "login",
        "vpn",
        "bucket",
        "blob",
        "subdomain",
        "exposed",
    ],
}


DEFAULT_FP_RULES = [
    {
        "type": "keyword",
        "value": "comunicado oficial",
        "reason": "Contenido publico oficial",
        "enabled": False,
    },
    {
        "type": "keyword",
        "value": "noticia",
        "reason": "Mencion periodistica legitima",
        "enabled": False,
    },
    {
        "type": "keyword",
        "value": "periodistico",
        "reason": "Mencion periodistica legitima",
        "enabled": False,
    },
]


FILE_PATTERNS = {
    "CURP": re.compile(r"\b[A-Z][AEIOUX][A-Z]{2}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b", re.I),
    "RFC": re.compile(r"\b[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3}\b", re.I),
    "correos": re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I),
    "telefonos": re.compile(r"(?:\+?52[\s\-\.]?)?(?:\(?\d{2,3}\)?[\s\-\.]?)?\d{3,4}[\s\-\.]?\d{4}\b"),
    "clave_elector": re.compile(r"\b[A-Z]{6}\d{8}[HM]\d{3}\b", re.I),
    "OCR": re.compile(r"\bOCR\b|ocr[\s:_-]*\d{6,}", re.I),
    "CIC": re.compile(r"\bCIC\b|cic[\s:_-]*\d{6,}", re.I),
    "direcciones": re.compile(r"\b(calle|avenida|av\.|colonia|col\.|municipio|cp|codigo postal)\b", re.I),
    "seccion_electoral": re.compile(r"\bsecci[oó]n\s+electoral\b|\bsecci[oó]n[\s:_-]*\d{3,5}\b", re.I),
    "INE": re.compile(r"\bINE\b|Instituto Nacional Electoral|credencial para votar", re.I),
}


STOPWORDS = {
    "para", "como", "desde", "este", "esta", "esto", "that", "with", "http",
    "https", "www", "com", "mx", "ine", "the", "and", "por", "con", "una",
    "uno", "del", "las", "los", "que", "detected", "demo", "site",
}


def normalize_risk(value):
    raw = str(value or "").strip().upper()
    if raw in ("CRITICO", "CRÍTICO", "CRITICA", "CRÍTICA"):
        return "CRITICO"
    if raw in ("ALTO", "HIGH"):
        return "ALTO"
    if raw in ("MEDIO", "MEDIA", "MEDIUM"):
        return "MEDIO"
    if raw in ("BAJO", "LOW"):
        return "BAJO"
    return raw or "BAJO"


def extract_domain(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text and not text.startswith("//"):
        text = "//" + text
    parsed = urlparse(text)
    host = parsed.netloc or parsed.path.split("/")[0]
    host = host.split("@")[-1].split(":")[0].strip().lower()
    return host.strip(".")


def root_domain(domain):
    parts = [p for p in str(domain or "").lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    two_level_suffixes = {
        "gob.mx", "com.mx", "org.mx", "net.mx", "edu.mx",
        "gov.uk", "co.uk", "org.uk", "com.br", "com.ar", "com.co",
    }
    suffix2 = ".".join(parts[-2:])
    if suffix2 in two_level_suffixes:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_official_domain(domain, official=""):
    domain = str(domain or "").lower().strip(".")
    official = str(official or "").lower().strip(".")
    return bool(domain and official and (domain == official or domain.endswith("." + official)))


def finding_signature(finding):
    url = str(finding.get("url") or "").strip().lower()
    file_hash = str(finding.get("hash") or finding.get("file_hash") or "").strip().lower()
    repo = str(finding.get("repository") or finding.get("repo") or "").strip().lower()
    if file_hash:
        raw = "hash:" + file_hash
    elif url:
        raw = "url:" + url.rstrip("/")
    elif repo:
        raw = "repo:" + repo
    else:
        raw = "|".join([
            str(finding.get("source") or ""),
            str(finding.get("title") or ""),
            str(finding.get("detail") or ""),
        ]).lower()
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:20]


def deduplicate_findings(findings):
    merged = []
    groups = {}
    for finding in findings or []:
        if finding.get("is_system"):
            continue
        item = dict(finding)
        key = item.get("dedupe_key") or finding_signature(item)
        item["dedupe_key"] = key
        if key in groups:
            existing = groups[key]
            existing["duplicate_count"] = int(existing.get("duplicate_count") or 1) + 1
            existing["last_detected"] = item.get("detected") or item.get("last_detected") or datetime.now().isoformat()
            sources = set(existing.get("sources_seen") or [existing.get("source", "")])
            if item.get("source"):
                sources.add(item.get("source"))
            existing["sources_seen"] = sorted(s for s in sources if s)
            if item.get("risk") and severity_rank(item.get("risk")) > severity_rank(existing.get("risk")):
                existing["risk"] = item.get("risk")
                existing["risk_class"] = item.get("risk_class", existing.get("risk_class"))
        else:
            item.setdefault("duplicate_count", 1)
            item.setdefault("first_detected", item.get("detected") or datetime.now().isoformat())
            item.setdefault("last_detected", item.get("detected") or item["first_detected"])
            item.setdefault("sources_seen", [item.get("source", "")] if item.get("source") else [])
            groups[key] = item
            merged.append(item)
    duplicates = [
        item for item in merged
        if int(item.get("duplicate_count") or 1) > 1
    ]
    return {
        "findings": merged,
        "duplicates": duplicates,
        "duplicates_collapsed": sum(int(x.get("duplicate_count") or 1) - 1 for x in duplicates),
        "unique_total": len(merged),
    }


def severity_rank(value):
    return {"CRITICO": 4, "ALTO": 3, "MEDIO": 2, "BAJO": 1}.get(normalize_risk(value), 0)


def _date_key(finding):
    raw = str(finding.get("detected_at") or finding.get("detected") or finding.get("first_detected") or "")
    if not raw:
        return date.today().isoformat()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw[:19], fmt).date().isoformat()
        except ValueError:
            pass
    if re.fullmatch(r"\d{1,2}:\d{2}(:\d{2})?", raw.strip()):
        return date.today().isoformat()
    return date.today().isoformat()


def _matches_term(finding, term):
    haystack = " ".join([
        str(finding.get("title") or ""),
        str(finding.get("detail") or ""),
        str(finding.get("url") or ""),
        str(finding.get("category") or ""),
    ]).lower()
    return str(term or "").lower() in haystack


def top_keywords(findings, watchlist=None, limit=10):
    terms = []
    for values in (watchlist or DEFAULT_WATCHLIST).values():
        terms.extend(values)
    counts = Counter()
    for finding in findings or []:
        for term in terms:
            if _matches_term(finding, term):
                counts[term] += 1
    if not counts:
        tokens = re.findall(r"[a-zA-Z0-9_]{4,}", " ".join(
            f"{f.get('title', '')} {f.get('detail', '')}" for f in findings or []
        ).lower())
        counts = Counter(t for t in tokens if t not in STOPWORDS)
    return [{"label": k, "value": v} for k, v in counts.most_common(limit)]


def count_credentials(findings):
    needles = ("api key", "apikey", "token", "password", "secret", "credencial", "credential", "clave")
    total = 0
    for finding in findings or []:
        text = " ".join([
            str(finding.get("title") or ""),
            str(finding.get("detail") or ""),
            str(finding.get("category") or ""),
        ]).lower()
        if finding.get("is_secret") or any(n in text for n in needles):
            total += 1
    return total


def build_dashboard(findings, stats=None, validations=None, watchlist=None, false_positive_rules=None, official_domain=""):
    deduped = deduplicate_findings(findings or [])
    rows = deduped["findings"]
    today = date.today().isoformat()
    by_source = Counter((f.get("source") or "Desconocida") for f in rows)
    by_severity = Counter(normalize_risk(f.get("risk")) for f in rows)
    by_day = Counter(_date_key(f) for f in rows)
    domains = [extract_domain(f.get("url")) for f in rows]
    domains = [d for d in domains if d]
    official = str(official_domain or "").strip().lower()
    suspicious_domains = sorted({
        d for d in domains
        if (not official or not is_official_domain(d, official))
        and (severity_rank(next((f.get("risk") for f in rows if extract_domain(f.get("url")) == d), "")) >= 2)
    })
    closed = sum(1 for v in validations or [] if str(v.get("validation", "")).upper() in ("CONFIRMADO", "FALSO POSITIVO"))
    high_or_critical = sum(1 for f in rows if severity_rank(f.get("risk")) >= 3)
    open_cases = max(high_or_critical - closed, 0)

    return {
        "kpis": {
            "total_findings": len(rows),
            "critical_findings": by_severity.get("CRITICO", 0),
            "new_today": sum(1 for f in rows if _date_key(f) == today),
            "sources_monitored": (stats or {}).get("sources_scanned") or len(by_source),
            "suspicious_domains": len(suspicious_domains),
            "credentials_detected": count_credentials(rows),
            "open_cases": open_cases,
            "closed_cases": closed,
            "avg_review_time": "N/D",
            "duplicates_collapsed": deduped["duplicates_collapsed"],
        },
        "charts": {
            "by_source": [{"label": k, "value": v} for k, v in by_source.most_common(10)],
            "by_severity": [{"label": k, "value": by_severity.get(k, 0)} for k in ("CRITICO", "ALTO", "MEDIO", "BAJO")],
            "by_day": [{"label": k, "value": v} for k, v in sorted(by_day.items())[-14:]],
            "top_keywords": top_keywords(rows, watchlist, 10),
            "top_domains": [{"label": k, "value": v} for k, v in Counter(domains).most_common(10)],
        },
        "suspicious_domains": suspicious_domains[:25],
        "deduplication": deduped,
    }


def false_positive_reason(finding, rules=None):
    rules = rules or DEFAULT_FP_RULES
    domain = extract_domain(finding.get("url"))
    text = " ".join([
        str(finding.get("title") or ""),
        str(finding.get("detail") or ""),
        str(finding.get("url") or ""),
        str(finding.get("category") or ""),
    ]).lower()
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        value = str(rule.get("value") or "").lower().strip()
        if not value:
            continue
        if rule.get("type") == "domain" and is_official_domain(domain, value):
            return rule.get("reason") or "Regla de dominio"
        if rule.get("type") == "keyword" and value in text:
            return rule.get("reason") or "Regla de palabra clave"
        if rule.get("type") == "source" and value == str(finding.get("source") or "").lower():
            return rule.get("reason") or "Regla de fuente"
    return ""


def apply_false_positive_rules(findings, rules=None):
    reviewed = []
    matches = []
    for finding in findings or []:
        item = dict(finding)
        reason = false_positive_reason(item, rules)
        if reason:
            item["false_positive"] = True
            item["fp_reason"] = reason
            matches.append(item)
        reviewed.append(item)
    return {"findings": reviewed, "matches": matches, "count": len(matches)}


def analyze_typosquatting(target_domain, candidates=None):
    target = root_domain(target_domain or "")
    if not target:
        return []
    target_label = target.split(".")[0]
    rows = []
    for raw in candidates or []:
        domain = root_domain(extract_domain(raw) or raw)
        if not domain:
            continue
        label = domain.split(".")[0]
        ratio = difflib.SequenceMatcher(None, target, domain).ratio()
        label_ratio = difflib.SequenceMatcher(None, target_label, label).ratio()
        distance = levenshtein(target, domain)
        contains_brand = target_label in label or label in target_label
        hyphen_brand = target_label + "-" in domain or "-" + target_label in domain
        if domain == target or is_official_domain(domain, target):
            risk = "Bajo"
            similarity = "Oficial"
            use = "Dominio oficial o subdominio autorizado"
        elif label_ratio >= 0.80 or ratio >= 0.78 or distance <= 2 or contains_brand or hyphen_brand:
            risk = "Alto"
            similarity = "Alta"
            use = "phishing o suplantacion"
        elif label_ratio >= 0.55 or ratio >= 0.55:
            risk = "Medio"
            similarity = "Media"
            use = "campana de confusion o landing no autorizada"
        else:
            risk = "Bajo"
            similarity = "Baja"
            use = "relacion debil; revisar contexto"
        rows.append({
            "domain": domain,
            "similarity": similarity,
            "risk": risk,
            "score": round(max(ratio, label_ratio), 3),
            "distance": distance,
            "possible_use": use,
        })
    rows.sort(key=lambda x: ({"Alto": 3, "Medio": 2, "Bajo": 1}.get(x["risk"], 0), x["score"]), reverse=True)
    return rows


def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                curr[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = curr
    return prev[-1]


def analyze_file_text(name, text):
    counts = {label: len(pattern.findall(text or "")) for label, pattern in FILE_PATTERNS.items()}
    total = sum(counts.values())
    ext = Path(name or "archivo.txt").suffix.lower()
    if total >= 100 or counts.get("CURP", 0) >= 25 or counts.get("correos", 0) >= 50:
        risk = "CRITICO"
    elif total >= 25:
        risk = "ALTO"
    elif total:
        risk = "MEDIO"
    else:
        risk = "BAJO"
    summary_bits = [
        f"{value} {label}" for label, value in counts.items() if value
    ]
    summary = ", ".join(summary_bits) if summary_bits else "Sin coincidencias sensibles"
    return {
        "file": name,
        "extension": ext,
        "matches": counts,
        "total_matches": total,
        "risk": risk,
        "summary": summary,
        "finding": {
            "source": "Analisis de archivos",
            "source_id": "file-analysis",
            "title": f"Archivo analizado: {name}",
            "url": name,
            "category": "Archivo sensible",
            "category_class": "cat-leak" if risk in ("CRITICO", "ALTO") else "cat-repo",
            "risk": "CRITICO" if risk == "CRITICO" else risk,
            "detail": summary,
            "detected": datetime.now().strftime("%H:%M:%S"),
            "is_dork": False,
        },
    }


def read_file_for_analysis(path, max_bytes=5_000_000):
    p = Path(path)
    data = p.read_bytes()[:max_bytes]
    suffix = p.suffix.lower()
    if suffix == ".zip":
        chunks = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist()[:25]:
                if name.endswith("/"):
                    continue
                lower = name.lower()
                if not lower.endswith((".txt", ".csv", ".sql", ".json", ".log", ".xml")):
                    continue
                chunks.append(f"\n--- {name} ---\n")
                chunks.append(zf.read(name)[:300_000].decode("utf-8", "ignore"))
        return "\n".join(chunks)
    if suffix == ".xlsx":
        chunks = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.startswith("xl/worksheets/") or name == "xl/sharedStrings.xml":
                    chunks.append(zf.read(name).decode("utf-8", "ignore"))
        return "\n".join(chunks)
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            return "\n".join((page.extract_text() or "") for page in reader.pages[:50])
        except Exception:
            return data.decode("latin-1", "ignore")
    return data.decode("utf-8", "ignore")


def report_lines(payload):
    findings = payload.get("findings") or []
    stats = payload.get("stats") or {}
    term = payload.get("term") or "Objetivo no especificado"
    domain = payload.get("domain") or "Sin dominio especifico"
    dashboard = build_dashboard(findings, stats, payload.get("validated"), payload.get("watchlist"), official_domain=payload.get("domain") or "")
    critical = [f for f in findings if severity_rank(f.get("risk")) >= 3][:15]
    lines = [
        "Dogui Ciberpatrullaje - Reporte Ejecutivo",
        f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Resumen ejecutivo",
        f"Se monitoreo el termino '{term}' y el dominio '{domain}'.",
        f"Hallazgos totales: {dashboard['kpis']['total_findings']}",
        f"Hallazgos criticos: {dashboard['kpis']['critical_findings']}",
        f"Credenciales detectadas: {dashboard['kpis']['credentials_detected']}",
        "",
        "Alcance del monitoreo",
        "Fuentes OSINT, repositorios, nubes publicas, dark web indexada, CTI y analisis local.",
        "",
        "Fuentes analizadas",
    ]
    for row in dashboard["charts"]["by_source"]:
        lines.append(f"- {row['label']}: {row['value']} hallazgo(s)")
    lines.extend(["", "Hallazgos criticos"])
    if critical:
        for finding in critical:
            lines.append(f"- [{finding.get('risk')}] {finding.get('source')}: {finding.get('title')}")
            lines.append(f"  Evidencia: {finding.get('url')}")
            if finding.get("detail"):
                lines.append(f"  Detalle: {finding.get('detail')}")
    else:
        lines.append("- Sin hallazgos criticos registrados.")
    lines.extend([
        "",
        "Evidencia",
        "La evidencia se conserva como URL, archivo, detalle tecnico, fuente y fecha de deteccion.",
        "",
        "Analisis tecnico",
        f"Dominios sospechosos: {dashboard['kpis']['suspicious_domains']}",
        f"Duplicados colapsados: {dashboard['kpis']['duplicates_collapsed']}",
        "",
        "Riesgo",
        "Riesgo Alto/Critico requiere validacion, contencion, takedown o escalamiento SOC.",
        "",
        "Recomendaciones",
        "- Validar hallazgos criticos y crear casos SOC cuando aplique.",
        "- Rotar credenciales expuestas y revisar historial de acceso.",
        "- Solicitar baja de dominios de suplantacion y reforzar monitoreo.",
        "- Mantener watchlist de palabras clave alineada al objetivo monitoreado.",
        "",
        "Anexos",
        "Incluye exportaciones CSV, JSON, Excel y STIX 2.1 para intercambio CTI.",
    ])
    return lines


def render_pdf(lines):
    pages = []
    current = []
    for line in lines:
        wrapped = wrap_text(line, 92) or [""]
        for wline in wrapped:
            current.append(wline)
            if len(current) >= 45:
                pages.append(current)
                current = []
    if current:
        pages.append(current)

    objects = []
    page_ids = []
    font_id = 3
    for page in pages:
        content_lines = ["BT", "/F1 10 Tf", "50 780 Td", "14 TL"]
        first = True
        for line in page:
            if first:
                content_lines.append(f"({pdf_escape(line)}) Tj")
                first = False
            else:
                content_lines.append(f"T* ({pdf_escape(line)}) Tj")
        content_lines.append("ET")
        stream = "\n".join(content_lines).encode("latin-1", "replace")
        content_id = len(objects) + 4
        page_id = len(objects) + 5
        objects.append((content_id, b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"))
        objects.append((page_id, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode("ascii")))
        page_ids.append(page_id)

    base_objects = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, f"<< /Type /Pages /Kids [{' '.join(str(pid) + ' 0 R' for pid in page_ids)}] /Count {len(page_ids)} >>".encode("ascii")),
        (3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"),
    ]
    all_objects = base_objects + objects
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj_id, body in all_objects:
        offsets.append(out.tell())
        out.write(f"{obj_id} 0 obj\n".encode("ascii"))
        out.write(body)
        out.write(b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(all_objects)+1}\n".encode("ascii"))
    out.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    out.write(f"trailer << /Size {len(all_objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("ascii"))
    return out.getvalue()


def pdf_escape(text):
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def wrap_text(text, width):
    text = str(text)
    if len(text) <= width:
        return [text]
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current = (current + " " + word).strip()
        else:
            if current:
                lines.append(current)
            current = word[:width]
    if current:
        lines.append(current)
    return lines


def export_csv(findings):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["#", "Fuente", "Titulo", "Categoria", "Riesgo", "URL", "Detalle", "Detectado", "Duplicados"])
    for i, f in enumerate(findings or [], 1):
        writer.writerow([
            i, f.get("source", ""), f.get("title", ""), f.get("category", ""),
            f.get("risk", ""), f.get("url", ""), f.get("detail", ""),
            f.get("detected", ""), f.get("duplicate_count", 1),
        ])
    return output.getvalue().encode("utf-8-sig")


def export_xlsx(findings):
    rows = [["#", "Fuente", "Titulo", "Categoria", "Riesgo", "URL", "Detalle", "Detectado", "Duplicados"]]
    for i, f in enumerate(findings or [], 1):
        rows.append([
            i, f.get("source", ""), f.get("title", ""), f.get("category", ""),
            f.get("risk", ""), f.get("url", ""), f.get("detail", ""),
            f.get("detected", ""), f.get("duplicate_count", 1),
        ])
    sheet_rows = []
    for r_idx, row in enumerate(rows, 1):
        cells = []
        for c_idx, value in enumerate(row, 1):
            col = excel_col(c_idx)
            cells.append(
                f'<c r="{col}{r_idx}" t="inlineStr"><is><t>{xml_escape(str(value))}</t></is></c>'
            )
        sheet_rows.append(f'<row r="{r_idx}">{"".join(cells)}</row>')
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>' + "".join(sheet_rows) + '</sheetData></worksheet>'
    )
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '</Types>'
        ))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>'
        ))
        zf.writestr("xl/workbook.xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Hallazgos" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ))
        zf.writestr("xl/_rels/workbook.xml.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '</Relationships>'
        ))
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return out.getvalue()


def excel_col(index):
    out = ""
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def export_stix(findings):
    objects = []
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    for finding in findings or []:
        value = finding.get("url") or finding.get("title") or finding.get("source")
        if not value:
            continue
        domain = extract_domain(value)
        pattern = f"[domain-name:value = '{domain}']" if domain else f"[url:value = '{value}']"
        object_id = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, str(value)))
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": object_id,
            "created": now,
            "modified": now,
            "name": str(finding.get("title") or "Dogui Ciberpatrullaje finding")[:250],
            "description": str(finding.get("detail") or ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "labels": ["ine-cti", normalize_risk(finding.get("risk")).lower()],
            "external_references": [{"source_name": str(finding.get("source") or "Dogui Ciberpatrullaje"), "url": str(finding.get("url") or "")}],
        })
    return {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": objects,
    }


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return data
