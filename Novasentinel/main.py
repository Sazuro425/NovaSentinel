#!/usr/bin/env python3
"""
NovaSentinel – standalone scanner entry point.

Fonctionnalités incluses (AUCUN WebSocket / reporting HTML pour l’instant) :
1. Découverte locale : IP, interface, passerelle, DNS, serveur DHCP.
2. Ping‑sweep multi‑thread pour lister les hôtes actifs.
3. Scan Nmap de ces hôtes avec extraction de services + CVE.
4. Sortie du résultat en JSON (stdout **et** fichier `reports/scan_<timestamp>.json`).

Pour lancer :
    python main.py
("reports/" sera créé s’il n’existe pas.)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

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

load_dotenv()
logger = get_custom_logger("main")
logger.info("NovaSentinel scanner-only mode starting…")

def main() -> None:
    """Enchaîne découverte réseau → ping‑sweep → Nmap → JSON."""
    # Découverte rapide des infos réseau de base
    ip_local = get_default_ip()
    iface = get_interface_by_ip(ip_local)
    gateway = get_gateway()
    dns_servers = get_dns_servers()
    dhcp_server = get_dhcp_server_systemd()

    # Ping‑sweep pour trouver les hôtes UP
    up_hosts = scan_network(ip_local, iface)

    # Scan Nmap avec détection de services & CVE vulners NSE
    nmap_results = scan_with_nmap(up_hosts)

    # Agrégation du résultat final
    payload: dict[str, object] = {
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

    print(json.dumps(payload, indent=2, ensure_ascii=False))

    # Sauvegarde disque
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    outfile = reports_dir / f"scan_{ts}.json"
    outfile.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    logger.info("Résultats enregistrés dans %s", outfile)
    logger.info("Scan terminé.")

if __name__ == "__main__":
    main()
