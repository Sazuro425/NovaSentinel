#!/usr/bin/env python3
"""
Outil réseau complet :
- Récupération d'IP, interface, passerelle, DNS, serveur DHCP
- Scan réseau en parallèle (ping sweep)
- Scan Nmap des hôtes actifs avec détection de services, versions, CVEs via OpenCVE
- Envoi des données à un serveur WebSocket
- Génération d'un rapport PDF
"""

import os
import socket
import subprocess
import ipaddress
import json
import netifaces
import dns.resolver
import nmap
import requests
from dotenv import load_dotenv
from script.core.log.mylog import get_custom_logger
from script.core.report.my_report import generate_html_report
import multiprocessing
from cve import format_cve_display

# Charger les variables d'environnement
load_dotenv()
OPENCVE_URL   = os.getenv("OPENCVE_URL", "")     # URL de l’instance OpenCVE
OPENCVE_USER = os.getenv("OPENCVE_USER")
OPENCVE_PASS = os.getenv("OPENCVE_PASS")
WEBSOCKET_URI = os.getenv("Manager", "ws://localhost:8000")
HTML_OUTPUT = os.getenv("HTML_OUTPUT_PATH", "network_report.html")

logger = get_custom_logger("network_tool")


def get_default_ip() -> str:
    """
    Détermine l’adresse IP locale par défaut en ouvrant une socket UDP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            logger.info(f"[get_default_ip] IP détectée : {ip}")
            return ip
    except Exception:
        logger.exception("[get_default_ip] Erreur obtention IP par défaut")
        return ""


def get_interface_by_ip(ip: str) -> str:
    """
    Recherche l’interface réseau associée à l’IP donnée.
    """
    try:
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                if addr.get("addr") == ip:
                    logger.info(f"[get_interface_by_ip] Interface pour IP {ip} : {iface}")
                    return iface
    except Exception:
        logger.exception("[get_interface_by_ip] Erreur obtention interface")
    logger.warning(f"[get_interface_by_ip] Aucune interface trouvée pour l'IP {ip}")
    return ""


def get_gateway() -> str:
    """
    Récupère la passerelle par défaut.
    """
    try:
        gw = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)
        if gw:
            logger.info(f"[get_gateway] Passerelle par défaut : {gw[0]}")
            return gw[0]
    except Exception:
        logger.exception("[get_gateway] Erreur obtention passerelle")
    return ""


def get_dns_servers() -> list[str]:
    """
    Liste les serveurs DNS configurés par le resolver système.
    """
    try:
        servers = dns.resolver.Resolver().nameservers
        logger.info(f"[get_dns_servers] DNS trouvés : {servers}")
        return servers
    except Exception:
        logger.exception("[get_dns_servers] Erreur obtention serveurs DNS")
        return []

import dns.reversename
import dns.exception

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


def get_dhcp_server_systemd() -> str:
    """
    Lit le fichier de bail DHCP systemd pour extraire le serveur DHCP.
    """
    lease_dir = "/run/systemd/netif/leases"
    try:
        if not os.path.isdir(lease_dir):
            return ""
        for fname in os.listdir(lease_dir):
            with open(os.path.join(lease_dir, fname)) as f:
                for line in f:
                    if line.startswith("SERVER_ADDRESS="):
                        dhcp = line.split("=", 1)[1].strip()
                        logger.info(f"[get_dhcp_server_systemd] DHCP : {dhcp}")
                        return dhcp
    except Exception:
        logger.exception("[get_dhcp_server_systemd] Erreur obtention serveur DHCP")
    return ""


def ping_host(ip: str) -> bool:
    """
    Envoie un ping ICMP unique (-c 1) avec timeout court (-W 1).
    Renvoie True si l’hôte répond, False sinon.
    """
    try:
        subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", ip],
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False


def scan_network(ip: str, iface: str) -> list[str]:
    """
    Balaye le réseau (ping sweep) en parallèle pour détecter les hôtes up.
    """
    up_hosts = []
    try:
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        if not addrs:
            logger.warning(f"[scan_network] Aucune adresse IPv4 sur {iface}")
            return up_hosts
        netmask = addrs[0].get("netmask")
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        logger.info(f"[scan_network] Balayage réseau {network}")
        with multiprocessing.Pool() as pool:
            results = pool.map(ping_host, [str(h) for h in network.hosts()])
        for host, alive in zip(network.hosts(), results):
            if alive:
                up_hosts.append(str(host))
        logger.info(f"[scan_network] Hôtes UP : {up_hosts}")
    except Exception:
        logger.exception("[scan_network] Erreur scan réseau")
    return up_hosts

# ---------------------------------------------------------------------------
# Configuration (variables d'environnement ou définies ailleurs dans le code)
# ---------------------------------------------------------------------------


def scan_with_nmap(hosts: list[str]) -> list[dict]:
    """
    Scanne tous les hôtes en une seule passe Nmap (-sT, -sV, -Pn),
    utilise le script NSE “vulners” pour récupérer les CVEs, et logge les infos pour débogage.
    """
    logger.info(f"[scan_with_nmap] Appelée avec hosts = {hosts!r}")
    if not hosts:
        logger.warning("[scan_with_nmap] Liste d'hôtes vide, rien à scanner")
        return []

    try:
        nm = nmap.PortScanner()
        targets = " ".join(hosts)
        logger.info(f"[scan_with_nmap] Lancement Nmap sur : {targets}")
        nm.scan(
            hosts=targets,
            arguments='-sT -sV -Pn --script=vulners'
        )

        # Debug
        logger.info(f"[scan_with_nmap] Command line : {nm.command_line()}")
        logger.info(f"[scan_with_nmap] Scan info   : {nm.scaninfo()}")
        logger.info(f"[scan_with_nmap] Hôtes trouvés par Nmap : {nm.all_hosts()}")

        results = []
        for host in nm.all_hosts():
            host_entry = {"ip": host, "services": []}
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    serv = nm[host][proto][port]
                    prod, ver = serv.get("product"), serv.get("version")
                    # Récupérer la sortie du script “vulners” s’il existe
                    cve_list: list[str] = []
                    script_outputs: dict = serv.get("script", {})
                    vulners_output = script_outputs.get("vulners", "").splitlines()

                    for line in vulners_output:
                        # Chaque ligne contenant un CVE commence typiquement par "CVE-"
                        txt = line.strip()
                        if txt.startswith("CVE-"):
                            # Extraire l’identifiant (premier token)
                            cve_id = txt.split()[0]
                            cve_list.append(cve_id)

                    svc = {
                        "port":    f"{port}/{proto}",
                        "service": serv.get("name"),
                        "product": prod,
                        "version": ver,
                        "info":    serv.get("extrainfo"),
                        "cves":    cve_list
                    }
                    host_entry["services"].append(svc)
            results.append(host_entry)

        return results

    except Exception as e:
        logger.error(f"[scan_with_nmap] Erreur Nmap multi-hôtes : {e}")
        return []

def discover_domain() -> dict:
    """
    Tente de découvrir le nom de domaine Active Directory via DNS SRV.
    Essaie les suffixes DNS du système s’ils existent.
    Renvoie un dict : {"domain": str, "controllers": [hostnames]}
    """
    domain = ""
    controllers = []
    resolver = dns.resolver.Resolver()

    # 1. Essayer d'utiliser le search domain du système (si défini)
    search_domains = resolver.search if resolver.search else []
    for suffix in search_domains:
        try:
            query = f"_ldap._tcp.dc._msdcs.{suffix.to_text()}"
            answers = resolver.resolve(query, 'SRV')
            domain = suffix.to_text()
            controllers = [str(r.target).rstrip('.') for r in answers]
            logger.info(f"[discover_domain] Domaine trouvé via DNS search : {domain}")
            return {"domain": domain, "controllers": controllers}
        except Exception:
            continue  # On essaie les suivants

    # 2. Tentative brute si aucun domaine connu
    try:
        answers = resolver.resolve("_ldap._tcp.dc._msdcs", 'SRV')
        controllers = [str(r.target).rstrip('.') for r in answers]
        logger.info("[discover_domain] Contrôleurs trouvés sans domaine explicite")
    except Exception:
        logger.warning("[discover_domain] Aucun domaine AD détecté")

    return {"domain": domain, "controllers": controllers}


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
