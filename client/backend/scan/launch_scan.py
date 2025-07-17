#!/usr/bin/env python3
"""
Script principal pour lancer le scan réseau, récupérer les données Nmap,
et enrichir chaque service avec les scores CVE via OpenCVE.
"""
import json
import sys

from network import scan_network, scan_with_nmap
from cve import enrich_cves  # ou le nom de ton module CVE

from dotenv import load_dotenv,find_dotenv
load_dotenv(find_dotenv(), override=True)
logger = get_custom_logger("scanner")
def main():
    # 1) Ping-sweep pour détecter les hôtes actifs
    default_ip = scan_network.get_default_ip()
    iface = scan_network.get_interface_by_ip(default_ip)
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
        for service in host_entry["services"]:
            enrich_cves(service)

    # 4) Exporter les résultats combinés
    output_file = "scan_enriched_results.json"
    with open(output_file, "w") as f:
        json.dump(nmap_results, f, indent=2, ensure_ascii=False)

    print(f"Résultats enrichis enregistrés dans {output_file}")


if __name__ == "__main__":
    main()
