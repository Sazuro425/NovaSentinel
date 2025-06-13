
# --- cve.py ---
import logging
import os
import urllib.parse
from functools import lru_cache
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from requests.exceptions import HTTPError, RequestException

load_dotenv()

OPENCVE_URL = os.getenv("OPENCVE_URL", "https://api.opencve.io/api").rstrip("/")
OPENCVE_USER = os.getenv("OPENCVE_USER")
OPENCVE_PASS = os.getenv("OPENCVE_PASS")

logger = logging.getLogger(__name__)
_DEFAULT_TIMEOUT = 10

@lru_cache(maxsize=1)
def _get_session() -> requests.Session:
    sess = requests.Session()
    if OPENCVE_USER and OPENCVE_PASS:
        sess.auth = (OPENCVE_USER, OPENCVE_PASS)
    sess.headers.update({
        "User-Agent": "NovaSentinel/1.0 (+https://example.com)"
    })
    return sess

def search_cve(cve_id: str, *, timeout: int = _DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    if not OPENCVE_URL or not (OPENCVE_USER and OPENCVE_PASS):
        logger.warning("[search_cve] Configuration OpenCVE incompl\u00e8te")
        return None

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError(f"Identifiant CVE invalide : '{cve_id}'")

    url = f"{OPENCVE_URL}/cve/{urllib.parse.quote_plus(cve_id)}"
    sess = _get_session()

    try:
        resp = sess.get(url, timeout=timeout)
        if resp.status_code == 404:
            logger.info(f"[search_cve] CVE non trouv\u00e9e : {cve_id}")
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
    for cve_id in cve_ids:
        data = search_cve(cve_id)
        score = "-"
        if data:
            cvss = data.get("cvss", {})
            score = cvss.get("score", "-")
        link = f"https://www.opencve.io/cve/{cve_id}"
        output.append(f'<a href="{link}" target="_blank">{cve_id}</a> (score: {score})')
    return "<br>".join(output)
