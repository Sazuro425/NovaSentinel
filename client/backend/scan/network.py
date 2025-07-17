#!/usr/bin/env python3
"""backend.scanner.network
=========================
Outils « bas‑niveau » pour la découverte réseau :

* Informations locales : IP par défaut, interface, passerelle, DNS, DHCP.
* Ping‑sweep multi‑thread (`scan_network`).
* Scan Nmap + extraction des CVE via le script NSE *vulners* (`scan_with_nmap`).

Chaque fonction trace dans le *logger* `scanner.network` pour simplifier le
suivi en production.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import time
from multiprocessing.dummy import Pool as ThreadPool
from pathlib import Path
from typing import Dict, List
import re
import dns.resolver
import netifaces
import nmap
from dotenv import load_dotenv, find_dotenv
from backend.utils.my_report import generate_html_report
from backend.utils.mylog import get_custom_logger
from backend.scan.cve import enrich_cves, format_cve_display
import json
# ────────────────────────────────────────────────
# Chargement .env et logger
# ────────────────────────────────────────────────
load_dotenv(find_dotenv(), override=True)
logger = get_custom_logger("scanner")

# ────────────────────────────────────────────────
# Fonctions d’environnement local
# ────────────────────────────────────────────────
HTML_OUTPUT = os.getenv("HTML_OUTPUT_PATH", "network_report.html")
def get_default_ip() -> str:
    """Adresse IP locale utilisée pour joindre Internet (méthode UDP)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            logger.debug("Default IP detected: %s", ip)
            return ip
    except Exception:
        logger.exception("Unable to determine default IP")
        return ""

def get_interface_by_ip(ip: str) -> str:
    """Retourne l’interface réseau portant *ip* ou '' si inconnue."""
    for iface in netifaces.interfaces():
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            if addr.get("addr") == ip:
                logger.debug("Interface for %s → %s", ip, iface)
                return iface
    logger.warning("No interface found for %s", ip)
    return ""

def get_gateway() -> str:
    try:
        gw = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
        logger.debug("Gateway: %s", gw[0] if gw else None)
        return gw[0] if gw else ""
    except Exception:
        logger.exception("Unable to get gateway")
        return ""

def get_dns_servers() -> List[str]:
    try:
        servers = dns.resolver.Resolver().nameservers
        logger.debug("DNS servers: %s", servers)
        return servers
    except Exception:
        logger.exception("Unable to get DNS servers")
        return []

def get_dhcp_server_systemd() -> str:
    lease_dir = Path("/run/systemd/netif/leases")
    if not lease_dir.is_dir():
        return ""
    for lease in lease_dir.iterdir():
        for line in lease.read_text().splitlines():
            if line.startswith("SERVER_ADDRESS="):
                dhcp = line.split("=", 1)[1].strip()
                logger.debug("DHCP server: %s", dhcp)
                return dhcp
    return ""

# ────────────────────────────────────────────────
# Ping‑sweep
# ────────────────────────────────────────────────

def _ping_host(ip: str) -> bool:
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def scan_network(cidr_ip: str, iface: str, threads_max: int | None = None) -> List[str]:
    """Détecte les hôtes actifs sur le /24 de *cidr_ip* via ICMP."""
    logger.info("[scan_network] Starting ping sweep on %s (%s)", cidr_ip, iface)

    addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
    if not addrs:
        logger.warning("%s has no IPv4", iface)
        return []

    network = ipaddress.IPv4Network(f"{addrs[0]['addr']}/24", strict=False)
    hosts = [str(h) for h in network.hosts()]

    pool_size = min(threads_max or 300, (os.cpu_count() or 4) * 50)
    logger.debug("Ping sweep with %d threads on %d addresses", pool_size, len(hosts))

    start = time.time()
    with ThreadPool(pool_size) as pool:
        alive = pool.map(_ping_host, hosts)
    up = [ip for ip, ok in zip(hosts, alive) if ok]
    logger.info("[scan_network] %d/%d hosts up (%.1fs)", len(up), len(hosts), time.time()-start)
    return up

# ────────────────────────────────────────────────
# Nmap + CVE vulners
# ────────────────────────────────────────────────

def scan_with_nmap(hosts: List[str]) -> List[Dict]:
    if not hosts:
        logger.warning("[scan_with_nmap] empty host list")
        return []

    logger.info("[scan_with_nmap] Scanning %d hosts with Nmap", len(hosts))
    nm = nmap.PortScanner()
    nm.scan(hosts=" ".join(hosts), arguments="-sS -sV -Pn --script=vulners")

    results: List[Dict] = []
    for host in nm.all_hosts():
        entry = {"ip": host, "services": []}

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto]):
                serv = nm[host][proto][port]
                raw = serv.get("script", {}).get("vulners", "")
                logger.debug("Raw NSE vulners output for %s:%s → %r", host, port, raw)
                # Extrait toutes les occurrences de CVE-YYYY-NNNN dans la sortie
                cves = re.findall(r"CVE-\d{4}-\d+", raw)
                # print(cves)

                service = {
                    "port": f"{port}/{proto}",
                    "service": serv.get("name"),
                    "product": serv.get("product"),
                    "version": serv.get("version"),
                    "info": serv.get("extrainfo"),
                    "cves": cves,
                }
                enrich_cves(service)
                entry["services"].append(service)

        results.append(entry)

    logger.info("[scan_with_nmap] Completed. %d hosts detailed", len(results))
    return results

def reverse_dns(ip: str, nameservers: list[str] | None = None, timeout: float = 2.0) -> str:
    """
    Renvoie le nom DNS (PTR) de l’IP ou '' si introuvable.
    nameservers : liste d’IP DNS à utiliser (sinon ceux du système).
    """
    try:
        ptr = dns.reversename.from_address(ip)           # 106.1.168.192.in-addr.arpa
        res = dns.resolver.Resolver()
        if nameservers:
            res.nameservers = nameservers
        res.lifetime = timeout
        answer = res.resolve(ptr, 'PTR')
        return str(answer[0]).rstrip('.')
    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            Exception):
        return ""


def test():
    # Exécution de test rapide
    logger.info("Default IP: %s", get_default_ip())
    iface = get_interface_by_ip(get_default_ip())
    logger.info("Interface for default IP: %s", iface)
    logger.info("Gateway: %s", get_gateway())
    logger.info("DNS servers: %s", get_dns_servers())
    logger.info("DHCP server (systemd): %s", get_dhcp_server_systemd())
    
    # Test de scan réseau
    up_hosts = scan_network(f"get_default_ip()"+"/24", iface, 10)
    logger.info("Active hosts: %s", up_hosts)
    # Test de scan Nmap
    if up_hosts:
        nmap_results = scan_with_nmap(up_hosts)
        logger.info("Nmap results: %s", nmap_results)
    else:
        logger.warning("No active hosts found for Nmap scan.")

if __name__ == "__main__":
    logger.info("=== Démarrage Network Tool ===")

    # 0. Infos réseau
    ip = get_default_ip()
    iface = get_interface_by_ip(ip)
    gateway = get_gateway()
    dns_list = get_dns_servers()
    dhcp_server = get_dhcp_server_systemd()
    logger.info(f"[main] Config réseau -> IP: {ip}, IFACE: {iface}, GW: {gateway}")
    
    # 1. Ping sweep
    hosts_up = scan_network(ip, iface)

    hosts_details = [{
        "ip":  h,
        "dns": reverse_dns(h, dns_list) or "-"
    } for h in hosts_up]

    # 2. Scan Nmap multi-hôtes
    nmap_results = scan_with_nmap(hosts_up)

    # 3. Logs bruts pour vérification
    logger.info("=== Résultats Nmap bruts ===")
    logger.info(json.dumps(nmap_results, indent=2))

    # 4. Préparation des données
    # 4. Préparation des données pour le rapport -------------------------------
    services_flat = []
    for host in nmap_results:
        for s in host["services"]:
            services_flat.append({
                "host":          host["ip"],
                "port":          s["port"],
                "service":       s["service"],
                "product":       s["product"] or "",
                "version":       s["version"] or "",
                "cves":          s["cves"],
                "cves_display":  format_cve_display(s["cves"]) if s["cves"] else "-"
            })

    data = {
        "interface":     iface,
        "ip_address":    ip,
        "gateway":       gateway,
        "dhcp":          dhcp_server,
        "active_hosts":  hosts_details,
        "services":      services_flat
    }

    generate_html_report(data, HTML_OUTPUT)
    logger.info("=== Fin Network Tool ===")
