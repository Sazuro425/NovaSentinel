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

import dns.resolver
import netifaces
import nmap
from dotenv import load_dotenv, find_dotenv

from client.backend.log.mylog import get_custom_logger

# ────────────────────────────────────────────────
# Chargement .env et logger
# ────────────────────────────────────────────────
load_dotenv(find_dotenv(), override=True)
logger = get_custom_logger("scanner")

# ────────────────────────────────────────────────
# Fonctions d’environnement local
# ────────────────────────────────────────────────

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
                cves = [line.split()[0] for line in serv.get("script", {})
                        .get("vulners", "").splitlines() if line.startswith("CVE-")]
                entry["services"].append({
                    "port": f"{port}/{proto}",
                    "service": serv.get("name"),
                    "product": serv.get("product"),
                    "version": serv.get("version"),
                    "info": serv.get("extrainfo"),
                    "cves": cves,
                })
        results.append(entry)
    logger.info("[scan_with_nmap] Completed. %d hosts detailed", len(results))
    return results

def enrich_cves(service: Dict[str, Any]) -> None:
    """Ajoute link_cve[] et score[] en regard de service['cves']."""
    links, scores = [], []
    base_url = OPENCVE_URL.rstrip('/').replace('/api', '')
    for cve_id in service.get("cves", []):
        data  = search_cve(cve_id) or {}
        score = "-"
        metrics = data.get("metrics", {})
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            score = metrics.get(key, {}).get("data", {}).get("score", score)
            if score != "-":
                break
        links.append(f"{base_url}/cve/{cve_id}")
        scores.append(score)
    service["link_cve"] = links
    service["score"]    = scores

# ────────────────────────────────────────────────
# Exécution simple pour debug
# ────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    ip_local = get_default_ip()
    print("IP:", ip_local)
    iface = get_interface_by_ip(ip_local)
    print("Interface:", iface)
    print("Gateway:", get_gateway())
    print("DNS:", get_dns_servers())

    hosts_up = scan_network(ip_local+"/24", iface)
    print("Hosts up:", hosts_up)

    if hosts_up:
        res = scan_with_nmap(hosts_up[:5])  # limite à 5 hôtes pour test
        print(json.dumps(res, indent=2, ensure_ascii=False))
