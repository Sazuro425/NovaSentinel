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
import multiprocessing
import ipaddress
import asyncio
import json
import netifaces
import dns.resolver
import nmap
import requests
import websockets
from dotenv import load_dotenv
from fpdf import FPDF
from script.core.log.mylog import get_custom_logger

# Charger les variables d'environnement
load_dotenv()
OPENCVE_URL   = os.getenv("OPENCVE_URL", "")     # URL de l’instance OpenCVE
OPENCVE_USER = os.getenv("OPENCVE_USER")
OPENCVE_PASS = os.getenv("OPENCVE_PASS")
WEBSOCKET_URI = os.getenv("Manager", "ws://localhost:8000")
PDF_OUTPUT    = os.getenv("PDF_OUTPUT_PATH", "network_report.pdf")

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


# def search_cves(product: str, version: str) -> list[str]:
#     """
#     Interroge l’API OpenCVE (/search) avec Basic Auth et pagination.
#     Retourne la liste complète des identifiants CVE pour le product/version donnés.
#     """
#     # Ne rien faire si la config OpenCVE est incomplète
#     if not OPENCVE_URL or not OPENCVE_USER or not OPENCVE_PASS:
#         return []
#     # Après import requests
#     session = requests.Session()
#     if OPENCVE_USER and OPENCVE_PASS:
#         session.auth = (OPENCVE_USER, OPENCVE_PASS)

#     # Épurer les chaînes pour éviter les erreurs de matching
#     product = product.strip().lower().split()[0]
#     version = version.split()[0]
#     query   = f"{product} {version}"

#     all_cves  = []

#     while True:
#         url    = f"{OPENCVE_URL}/search"
#         params = {
#             "search":         query,
#             "page":      page,
#             "page_size": page_size
#         }

#         try:
#             resp = session.get(url, params=params, timeout=10)
#             resp.raise_for_status()
#             data = resp.json().get("data", {})

#             # Extraire les CVE de la page courante
#             cves_page = [c["cve"] for c in data.get("cves", []) if c.get("cve")]
#             if not cves_page:
#                 break

#             all_cves.extend(cves_page)

#             # Si on a reçu moins que page_size, on est à la fin
#             if len(cves_page) < page_size:
#                 break

#             page += 1

#         except requests.HTTPError as e:
#             logger.warning(f"[search_cves] HTTP {resp.status_code} pour '{query}' → {e}")
#             break
#         except Exception:
#             logger.exception(f"[search_cves] Exception pour '{query}'")
#             break

#     return all_cves



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



def generate_pdf_report(data: dict, filename: str):
    """
    Génère un rapport PDF à partir des données collectées.
    Inclut le logo Novasys en en-tête et adapte les couleurs des titres
    pour s’accorder au bleu du logo.
    Évite l’utilisation de caractères non Latin-1 pour ne pas provoquer d’UnicodeEncodeError.
    """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # --- Insérer le logo en haut à gauche ---
    # Le fichier 'novasys_logo.png' doit se trouver dans le même dossier que ce script.
    try:
        pdf.image('novasys_logo.png', x=10, y=8, w=30)  # largeur 30 mm, hauteur ajustée
    except Exception:
        logger.warning("[generate_pdf_report] Impossible de charger le logo 'novasys_logo.png'")

    # --- Titre principal (à droite du logo) ---
    pdf.set_xy(50, 12)  # positionner le curseur à droite du logo
    pdf.set_text_color(0, 51, 102)  # bleu foncé (approximation du bleu Novasys)
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 10, "Network Scan Report", ln=True, align="C")
    pdf.ln(5)

    # --- Section infos réseau ---
    pdf.set_text_color(0, 0, 0)  # texte en noir
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Interface: {data.get('interface')}", ln=True)
    pdf.cell(0, 8, f"Adresse IP: {data.get('ip')}", ln=True)
    pdf.cell(0, 8, f"Passerelle: {data.get('gateway')}", ln=True)
    pdf.cell(0, 8, f"DNS: {', '.join(data.get('dns', []))}", ln=True)
    pdf.cell(0, 8, f"DHCP: {data.get('dhcp')}", ln=True)
    pdf.ln(8)

    # --- Section hôtes ping ---
    pdf.set_text_color(0, 102, 204)  # bleu moyen pour les sous-titres
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 8, "Hôtes actifs (ping) :", ln=True)
    pdf.set_text_color(0, 0, 0)  # texte des hôtes en noir
    pdf.set_font("Arial", "", 12)
    for host in data.get('hosts_up', []):
        pdf.cell(0, 6, f"- {host}", ln=True)
    pdf.ln(8)

    # --- Section Nmap ---
    pdf.set_text_color(0, 102, 204)  # bleu moyen pour cohérence
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 8, "Résultats Nmap :", ln=True)
    pdf.set_text_color(0, 0, 0)  # texte en noir
    pdf.set_font("Arial", "", 12)

    for host in data.get('nmap', []):
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(0, 51, 102)  # bleu foncé pour le nom de l'hôte
        pdf.cell(0, 7, f"Hôte : {host.get('ip')}", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(0, 0, 0)  # texte en noir pour le détail

        for svc in host.get('services', []):
            # Afficher port/service/product/version avec un tiret ASCII
            line = f"  - {svc.get('port')}  {svc.get('service')}  {svc.get('product') or ''}  {svc.get('version') or ''}"
            pdf.multi_cell(0, 6, line)

            # Si des CVE sont présentes, les afficher en italique et en rouge foncé
            cves = svc.get('cves', [])
            if cves:
                pdf.set_text_color(153, 0, 0)  # rouge foncé pour les CVE
                pdf.set_font("Arial", "I", 11)
                pdf.multi_cell(0, 6, f"    CVEs détectées : {', '.join(cves)}")
                pdf.set_font("Arial", "", 12)
                pdf.set_text_color(0, 0, 0)  # revenir au noir

        pdf.ln(4)

    # --- Générer le fichier PDF ---
    try:
        pdf.output(filename)
        logger.info(f"[generate_pdf_report] Rapport PDF généré : {filename}")
    except Exception:
        logger.exception("[generate_pdf_report] Erreur génération PDF")


async def send_data_to_server(uri: str, data: dict):
    """
    Envoie les données JSON via WebSocket à l’URI spécifiée.
    """
    try:
        async with websockets.connect(uri) as ws:
            await ws.send(json.dumps(data))
            logger.info("[send_data_to_server] Données envoyées via WebSocket")
    except Exception:
        logger.exception("[send_data_to_server] Erreur envoi WebSocket")


def main():
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

    # 2. Scan Nmap multi-hôtes
    nmap_results = scan_with_nmap(hosts_up)

    # 3. Logs bruts pour vérification
    logger.info("=== Résultats Nmap bruts ===")
    logger.info(json.dumps(nmap_results, indent=2))

    # 4. Préparation des données
    data = {
        "interface": iface,
        "ip":        ip,
        "gateway":   gateway,
        "dns":       dns_list,
        "dhcp":      dhcp_server,
        "hosts_up":  hosts_up,
        "nmap":      nmap_results
    }

    # 5. Envoi WebSocket
    try:
        asyncio.run(send_data_to_server(WEBSOCKET_URI, data))
    except Exception:
        logger.exception("[main] Erreur exécution WebSocket final")

    # 6. Génération du rapport PDF
    generate_pdf_report(data, PDF_OUTPUT)

    logger.info("=== Fin Network Tool ===")


if __name__ == "__main__":
    main()
