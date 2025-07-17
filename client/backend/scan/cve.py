#!/usr/bin/env python3
"""CVE utilities: lookup via OpenCVE + enrichment helpers (with extensive logging).

You can run this module directly to test two CVE IDs on stdout:

    $ python cve_utils_with_logging.py

Environment variables (all optional):
------------------------------------
OPENCVE_URL_API   URL of the OpenCVE REST API        (default: https://api.opencve.io/api)
OPENCVE_URL       Base URL of the OpenCVE front-end  (default: https://www.opencve.io)
OPENCVE_USER      Login for authenticated API usage  (anonymous is allowed ; rate-limited)
OPENCVE_PASS      Password

Logging: the module creates/uses the logger named ``CVE``.
Set ``LOGLEVEL`` in your environment or configure the root logger upstream.
"""
from __future__ import annotations

import logging
import os
import time
import urllib.parse
from functools import lru_cache
from typing import Any, Dict, Optional

import requests
from dotenv import find_dotenv, load_dotenv
from requests.exceptions import RequestException
from backend.utils.mylog import get_custom_logger

# ---------------------------------------------------------------------------
# Environment & logger ------------------------------------------------------
# ---------------------------------------------------------------------------

load_dotenv(find_dotenv(), override=True)

OPENCVE_URL_API = os.getenv("OPENCVE_URL_API", "https://api.opencve.io/api").rstrip("/")
OPENCVE_URL = os.getenv("OPENCVE_URL", "https://www.opencve.io").rstrip("/")
OPENCVE_USER = os.getenv("OPENCVE_USER")
OPENCVE_PASS = os.getenv("OPENCVE_PASS")

_DEFAULT_TIMEOUT = 10  # seconds for HTTP requests

logger = get_custom_logger("CVE")
logger.debug("Using OpenCVE API at %s", OPENCVE_URL_API)

@lru_cache(maxsize=1)
def _get_session() -> requests.Session:
    """Return a singleton :class:`requests.Session` with proper headers/auth."""
    sess = requests.Session()
    if OPENCVE_USER and OPENCVE_PASS:
        sess.auth = (OPENCVE_USER, OPENCVE_PASS)
        logger.debug("Configured HTTP Basic Auth for OpenCVE user '%s'", OPENCVE_USER)
    sess.headers.update({"User-Agent": "NovaSentinel/1.0"})
    logger.debug("Created new requests.Session for OpenCVE: %s", sess)
    return sess


def search_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Query OpenCVE API and return full JSON for *cve_id*.

    :param cve_id: e.g. ``"CVE-2021-34527"``
    :return: Parsed JSON as dict or ``None`` on error/not found.
    """
    url = f"{OPENCVE_URL_API}/cve/{urllib.parse.quote_plus(cve_id)}"
    logger.debug("Requesting CVE %s at %s", cve_id, url)

    t0 = time.perf_counter()
    try:
        r = _get_session().get(url, timeout=_DEFAULT_TIMEOUT)
        elapsed = time.perf_counter() - t0
        logger.debug("HTTP GET %s completed in %.3fs (status=%s)", url, elapsed, r.status_code)

        if r.status_code == 404:
            logger.warning("CVE %s not found in OpenCVE (404)", cve_id)
            return None
        r.raise_for_status()
        data = r.json()
        logger.info("CVE %s fetched (metrics keys: %s)", cve_id, list(data.get("metrics", {})))
        return data
    except RequestException as exc:
        logger.exception("OpenCVE lookup failed for %s: %s", cve_id, exc)
        return None


def _extract_score(opencve_json: Dict[str, Any]) -> str | float:
    """Return the first available CVSS base score (4.0 → 3.1 → 3.0 → 2.0)."""
    metrics = opencve_json.get("metrics", {})
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        data = metrics.get(key, {}).get("data", {})
        score = data.get("score")
        if score is not None:
            logger.debug("Using %s score %.1f for CVE", key, score)
            return score
    logger.debug("No CVSS score found in metrics keys: %s", list(metrics))
    return "-"


def enrich_cves(service: Dict[str, Any]) -> None:
    """Populate ``link_cve`` and ``score`` arrays for a service dict.

    Modifies *service* in-place, adding:
        * ``link_cve``  list[str]
        * ``score``     list[float|str]
    """
    links, scores = [], []
    base_ui = OPENCVE_URL.rstrip("/").replace("/api", "")

    logger.debug("Enriching service on port %s with %d raw CVEs", service.get("port"), len(service.get("cves", [])))

    for cve_id in service.get("cves", []):
        link = f"{base_ui}/cve/{cve_id}"
        links.append(link)
        data = search_cve(cve_id) or {}
        score = _extract_score(data) if data else "-"
        scores.append(score)
        logger.info("CVE %s → score %s", cve_id, score)

    service["link_cve"] = links
    service["score"] = scores

# backend/scan/cve.py
from html import escape

OPEN_CVE_URL = "https://www.opencve.io/cve/{}"

def format_cve_display(cves: list[str]) -> str:
    """
    Retourne une chaîne HTML contenant les CVE cliquables vers OpenCVE.
    - Affiche « - » quand la liste est vide.
    - Supprime les doublons et trie les identifiants pour l’esthétique.
    """
    if not cves:
        return "-"

    # uniques + triés
    uniq = sorted(set(cves), key=lambda x: (x[:13], int(x.split("-")[2])))
    links = [
        f'<a href="{OPEN_CVE_URL.format(escape(cve))}" '
        f'target="_blank" rel="noopener">{escape(cve)}</a>'
        for cve in uniq
    ]
    # Saut de ligne pour lisibilité dans la cellule du tableau
    return "<br/>".join(links)


if __name__ == "__main__":
    ids = ["CVE-2021-34527", "CVE-2020-0601"]
    logger.info("Running self-test on %s", ids)
    print(format_cve_display(ids))
