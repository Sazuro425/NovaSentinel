#!/usr/bin/env python3
"""
Script principal pour lancer le scan réseau, récupérer les données Nmap,
et enrichir chaque service avec les scores CVE via OpenCVE.
"""
import json
import sys
import datetime
from uuid import uuid4
from backend.scan.network import (
    scan_network,
    scan_with_nmap,
    get_default_ip,
    get_interface_by_ip
)
from backend.scan.cve import enrich_cves
from pathlib import Path
from typing import Any, Dict, Optional
from backend.utils.myjson import load_scan  # <-- ta nouvelle version

def launch_scan():
    # 1) Ping-sweep pour détecter les hôtes actifs
    default_ip = get_default_ip()
    datetime_str = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    scan_id = f"{datetime_str}-{uuid4()}"
    if not default_ip:
        print("Aucune IP par défaut détectée. Fin du script.")
        sys.exit(1)

    iface = get_interface_by_ip(default_ip)
    print(f"Détection d'hôtes actifs sur {default_ip}/24 via interface {iface}...")
    up_hosts = scan_network(f"{default_ip}/24", iface)

    if not up_hosts:
        print("Aucun hôte actif détecté. Fin du script.")
        sys.exit(0)

    # 2) Scan Nmap + script vulners
    print(f"Lancement du scan Nmap sur {len(up_hosts)} hôtes...")
    nmap_results = scan_with_nmap(up_hosts)

    # 3) Enrichissement des services avec CVE
    print("Enrichissement CVE des services...")
    for host_entry in nmap_results:
        for service in host_entry.get("services", []):
            enrich_cves(service)

    # 4) Exporter les résultats combinés
    output_file = "reports/{scan_id}.json"
    with open(output_file, "w") as f:
        json.dump(nmap_results, f, indent=2, ensure_ascii=False)
    return output_file

if __name__ == "__main__":
    launch_scan()

