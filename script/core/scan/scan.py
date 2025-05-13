#!/usr/bin/env python3
"""
Outil réseau complet :
- Récupération d'IP, interface, passerelle, DNS, serveur DHCP
- Scan réseau en parallèle (ping sweep)
- Journalisation via logging
"""
import os
import socket
import subprocess
import multiprocessing
from pathlib import Path
import netifaces
import dns.resolver
import ipaddress
from script.core.log.mylog import get_custom_logger
from script.core.mydotenv import load_dotenv
import netifaces
# Charger les variables d'environnement
load_dotenv()

# Logger dédié
logger = get_custom_logger("network_tool")


def get_default_ip() -> str:
    """IP locale utilisée pour sortir vers Internet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        logger.info(f"IP par défaut déterminée : {ip}")
        return ip
    except Exception as e:
        logger.error(f"Erreur récupération IP par défaut : {e}", exc_info=True)
        return ""


def get_interface_by_ip(ip: str) -> str:
    """Nom de l'interface correspondant à l'IP."""
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                if addr.get("addr") == ip:
                    logger.info(f"Interface pour IP {ip} : {iface}")
                    return iface
        logger.warning(f"Aucune interface trouvée pour IP {ip}")
    except Exception as e:
        logger.error(f"Erreur recherche interface : {e}", exc_info=True)
    return ""


def get_gateway() -> str:
    """Passerelle par défaut IPv4."""
    try:
        gw = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
        gateway = gw[0] if gw else ""
        logger.info(f"Passerelle par défaut : {gateway}")
        return gateway
    except Exception as e:
        logger.error(f"Erreur récupération passerelle : {e}", exc_info=True)
        return ""


def get_dns_servers() -> list[str]:
    """Liste des serveurs DNS configurés."""
    try:
        resolver = dns.resolver.Resolver()
        servers = resolver.nameservers
        logger.info(f"Serveurs DNS : {servers}")
        return servers
    except Exception as e:
        logger.error(f"Erreur récupération DNS : {e}", exc_info=True)
        return []


def get_dhcp_server(iface: str) -> str:
    """Récupère le serveur DHCP en lisant le fichier de bail dhclient."""
    lease_file = f"/var/lib/dhcp/dhclient.{iface}.leases"
    dhcp_server = ""
    try:
        if not os.path.exists(lease_file):
            logger.warning(f"Fichier de bail DHCP introuvable : {lease_file}")
            return ""
        with open(lease_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Cherche l'option DHCP pour le serveur
                if line.startswith('option dhcp-server-identifier'):
                    # Format: option dhcp-server-identifier 192.168.1.1;
                    parts = line.rstrip(';').split()
                    if parts:
                        dhcp_server = parts[-1]
        if dhcp_server:
            logger.info(f"Serveur DHCP pour {iface} : {dhcp_server}")
        else:
            logger.warning(f"Aucun serveur DHCP trouvé dans {lease_file}")
        return dhcp_server
    except Exception as e:
        logger.error(f"Erreur lecture bail DHCP pour {iface} : {e}", exc_info=True)
        return ""


def ping_host(ip: str) -> bool:
    """Ping un hôte, retourne True s'il répond."""
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", ip],
                                 stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def scan_network(ip: str, iface: str) -> list[str]:
    """Effectue un ping sweep sur le réseau local de l'IP donnée."""
    up_hosts = []
    try:
        # Détermine le réseau à partir de l'IP et du mask
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        if not addrs:
            logger.warning(f"Pas d'adresse IPv4 pour interface {iface}")
            return up_hosts
        netmask = addrs[0].get("netmask")
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        # Lance le ping en parallèle
        logger.info(f"Scan du réseau {network}")
        with multiprocessing.Pool() as pool:
            results = pool.map(ping_host, [str(host) for host in network.hosts()])
        for host, alive in zip(network.hosts(), results):
            if alive:
                up_hosts.append(str(host))
        logger.info(f"Hôtes actifs trouvés : {up_hosts}")
    except Exception as e:
        logger.error(f"Erreur durant le scan réseau : {e}", exc_info=True)
    return up_hosts


def main():
    logger.info("=== Démarrage du Network Tool ===")
    ip = get_default_ip()
    iface = get_interface_by_ip(ip)
    gateway = get_gateway()
    dns_list = get_dns_servers()
    dhcp = netifaces.gateways()
    hosts_up = scan_network(ip, iface)

    # Affichage synthétique
    print(f"Interface   : {iface}")
    print(f"IP locale   : {ip}")
    print(f"Passerelle  : {gateway}")
    print(f"Serveur DHCP: {dhcp}")
    print("DNS servers :", ", ".join(dns_list))
    print("Hôtes actifs sur le réseau :")
    for h in hosts_up:
        print(h)
    logger.info("=== Fin du Network Tool ===")


if __name__ == "__main__":
    main()
