#!/usr/bin/env python3
import logging
import os
import urllib.parse
from functools import lru_cache
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from requests.exceptions import HTTPError, RequestException
from core.log.mylog import get_custom_logger
import core.mydotenv

OPENCVE_URL_API = os.getenv("OPENCVE_URL_API", "https://api.opencve.io/api").rstrip("/")
OPENCVE_USER = os.getenv("OPENCVE_USER")
OPENCVE_PASS = os.getenv("OPENCVE_PASS")
OPENCVE_URL = os.getenv("OPENCVE_URL", "https://www.opencve.io").rstrip("/")

logger = get_custom_logger("CVE")
_DEFAULT_TIMEOUT = 10

#garde la connexion ouverte pour les appels suivants
@lru_cache(maxsize=1)
def _get_session() -> requests.Session:
    sess = requests.Session()
    if OPENCVE_USER and OPENCVE_PASS:
        sess.auth = (OPENCVE_USER, OPENCVE_PASS)
    sess.headers.update({
        "User-Agent": "NovaSentinel/1.0"
    })
    return sess

def search_cve(cve_id: str) -> dict[str, Any] | None:
    """Retourne le JSON NVD (v2.0) d’un CVE ou None en cas d’erreur."""
    try:
        r = requests.get(f"{NVD_API_URL}?cveId={cve_id}", timeout=10)
        r.raise_for_status()
        j = r.json()
        vulns = j.get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None
    except Exception:
        logger.exception("CVE lookup failed for %s", cve_id)
        return None


def enrich_cves(service: Dict[str, Any]) -> None:
    """Ajoute link_cve[] et score[] à un service déjà rempli par Nmap."""
    links, scores = [], []
    base_url = OPENCVE_URL.rstrip("/").replace("/api", "")
    for cve_id in service.get("cves", []):
        links.append(f"{base_url}/cve/{cve_id}")
        score = "-"
        data = search_cve(cve_id) or {}
        # NVD v2.0 : metrics → cvssMetricV31 / V30 / V2
        for key in ("cvssMetricV40", "cvssMetricV31",
                    "cvssMetricV30", "cvssMetricV2"):
            metric = (data.get("metrics", {}).get(key) or [{}])[0]
            score = metric.get("cvssData", {}).get("baseScore", score)
            if score != "-":
                break
        scores.append(score)
    service["link_cve"] = links
    service["score"] = scores

def format_cve_display(cve_ids: list[str]) -> str:
    output = []
    base_ui_url = OPENCVE_URL.rstrip("/").replace("/api", "")
    for cve_id in cve_ids:
        data = search_cve(cve_id)
        score = "-"
        if data:
            metrics = data.get("metrics", {})
            for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                cvss_data = metrics.get(key, {}).get("data", {})
                if "score" in cvss_data:
                    score = cvss_data["score"]
                    break
        link = f"{base_ui_url}/cve/{cve_id}"
        output.append(f"{cve_id} (score: {score}) — {link}")
    return "\n".join(output)


