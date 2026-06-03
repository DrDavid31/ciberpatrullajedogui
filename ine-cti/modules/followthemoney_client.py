# -*- coding: utf-8 -*-
"""
Normalizacion simple de hallazgos al formato FollowTheMoney (FtM).
Usa followthemoney si esta instalado; si no, genera JSON compatible basico.
"""

import hashlib


def _entity_id(*parts):
    raw = "|".join(str(p or "") for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def finding_to_entity(finding, dataset="ine-cti-monitor"):
    title = finding.get("title") or finding.get("source") or "Hallazgo CTI"
    url = finding.get("url") or ""
    detail = finding.get("detail") or ""
    source = finding.get("source") or ""
    risk = finding.get("risk") or ""

    data = {
        "id": _entity_id(source, title, url),
        "schema": "HyperText" if url.startswith(("http://", "https://")) else "Document",
        "properties": {
            "title": [title],
            "sourceUrl": [url] if url else [],
            "summary": [detail] if detail else [],
            "keywords": [value for value in (source, risk) if value],
        },
        "datasets": [dataset],
    }

    try:
        from followthemoney import model

        entity = model.get_proxy(data)
        return entity.to_dict()
    except Exception:
        return data


def normalize_findings(findings, dataset="ine-cti-monitor", limit=100):
    entities = [finding_to_entity(f, dataset) for f in (findings or [])[: int(limit or 100)]]
    return {
        "status": "ok",
        "dataset": dataset,
        "entities": entities,
        "count": len(entities),
    }


def test_normalizer():
    sample = normalize_findings([{
        "source": "Dogui Ciberpatrullaje",
        "title": "Prueba FollowTheMoney",
        "url": "https://example.com",
        "detail": "Entidad de prueba",
        "risk": "BAJO",
    }])
    return {
        "status": "ok",
        "message": "Normalizador FollowTheMoney disponible",
        "sample": sample["entities"][0],
    }
