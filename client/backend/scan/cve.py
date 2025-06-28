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

def search_cve(cve_id: str, *, timeout: int = _DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    if not OPENCVE_URL_API or not (OPENCVE_USER and OPENCVE_PASS):
        logger.warning("[search_cve] Configuration OpenCVE incomplte")
        return None

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError(f"Identifiant CVE invalide : '{cve_id}'")

    url = f"{OPENCVE_URL_API}/cve/{urllib.parse.quote_plus(cve_id)}"
    sess = _get_session()

    try:
        resp = sess.get(url, timeout=timeout)
        if resp.status_code == 404:
            logger.info(f"[search_cve] CVE non trouver : {cve_id}")
            return None

        resp.raise_for_status()
        return resp.json()

    except HTTPError as exc:
        logger.warning(f"[search_cve] HTTP {resp.status_code} : {exc}")
    except RequestException as exc:
        logger.warning(f"[search_cve] Erreur r\u00e9seau : {exc}")
    except Exception as exc:
        logger.exception(f"[search_cve] Exception inattendue : {exc}")
    return None

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


