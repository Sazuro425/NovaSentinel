#!/usr/bin/env python3
"""
main.py — NovaSentinel **scanner uniquement** (CLI)
=================================================
Ajout : enrichissement automatique des CVE
-----------------------------------------
Chaque service détecté par Nmap possède déjà une clef `cves` (liste d’ID). 
On complète maintenant avec une clef `cves_detail` :
```json
{
  "id": "CVE-2024-12345",
  "score": 9.8,
  "link": "https://www.opencve.io/cve/CVE-2024-12345"
}
```
Ainsi le front (ou l’API) peut directement afficher le score et un lien.

Usage (inchangé) :
    python main.py               # scan + fichier dans reports/
    python main.py --json        # scan → stdout uniquement

Dépendances supplémentaires : `requests`, variables OPENCVE_* dans `.env`.
"""
from __future__ import annotations

import argparse, json, sys, time
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

from core.log.mylog import get_custom_logger
from core.scan.scanner import (
    get_default_ip,
    get_interface_by_ip,
    get_gateway,
    get_dns_servers,
    get_dhcp_server_systemd,
    scan_network,
    scan_with_nmap,
)
# Nouveau : lookup des CVE via OpenCVE
from core.scan.cve import search_cve, OPENCVE_URL

load_dotenv()
logger = get_custom_logger("main")

# ────────────────────────────────────────────────
# Helpers CVE
# ────────────────────────────────────────────────

def enrich_service_with_cves(service: Dict[str, Any]) -> None:
    """Ajoute `cves_detail` à un service (in‑place)."""
    detailed: List[Dict[str, Any]] = []
    for cve_id in service.get("cves", []):
        try:
            data = search_cve(cve_id)  # peut être None si not found / quota
        except Exception as e:
            logger.warning("lookup %s failed: %s", cve_id, e)
            data = None

        score: Any = "-"
        if data:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                score = (
                    data.get("metrics", {})
                    .get(key, {})
                    .get("data", {})
                    .get("score", score)
                )
                if score != "-":
                    break
        detailed.append({
            "id": cve_id,
            "score": score,
            "link": f"{OPENCVE_URL}/cve/{cve_id}",
        })
    service["cves_detail"] = detailed

# ────────────────────────────────────────────────
# Fonction de scan réutilisable
# ────────────────────────────────────────────────

def run_scan() -> Dict[str, Any]:
    """Exécute découverte + Nmap et renvoie un dictionnaire JSON enrichi."""
    logger.info("Démarrage du scan réseau NovaSentinel")

    ip_local    = get_default_ip()
    iface       = get_interface_by_ip(ip_local)
    gateway     = get_gateway()
    dns_servers = get_dns_servers()
    dhcp_server = get_dhcp_server_systemd()

    up_hosts     = scan_network(ip_local, iface)
    nmap_results = scan_with_nmap(up_hosts)

    # Enrichissement CVE
    for host in nmap_results:
        for svc in host.get("services", []):
            if svc.get("cves"):
                enrich_service_with_cves(svc)

    return {
        "timestamp": int(time.time()),
        "network": {
            "ip": ip_local,
            "interface": iface,
            "gateway": gateway,
            "dns": dns_servers,
            "dhcp": dhcp_server,
            "active_hosts": len(up_hosts),
        },
        "hosts": nmap_results,
    }

# ────────────────────────────────────────────────
# Persistance disque
# ────────────────────────────────────────────────

def save_report(data: Dict[str, Any]) -> Path:
    reports_dir = Path("reports"); reports_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    outfile = reports_dir / f"scan_{ts}.json"
    outfile.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    logger.info("Résultats enregistrés dans %s", outfile)
    return outfile

# ────────────────────────────────────────────────
# Entrée : mode CLI uniquement
# ────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NovaSentinel scanner (CLI)")
    parser.add_argument("--json", action="store_true", help="Affiche uniquement le JSON — n’écrit pas de fichier")
    args = parser.parse_args()

    try:
        result = run_scan()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if not args.json:
            save_report(result)
    except KeyboardInterrupt:
        sys.exit("\nScan interrompu par l’utilisateur")
