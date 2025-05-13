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
import asyncio
import websockets
import json

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


def get_dhcp_server_systemd() -> str:
    """NEED TO BE REWORK"""
    lease_dir = "/run/systemd/netif/leases"
    try:
        if not os.path.isdir(lease_dir):
            logger.warning(f"Répertoire {lease_dir} introuvable ou non utilisé.")
            return ""
        logger.info(f"Contenu du dossier {lease_dir} : {os.listdir(lease_dir)}")
        for fname in os.listdir(lease_dir):
            full_path = os.path.join(lease_dir, fname)
            logger.info(f"Lecture du fichier : {full_path}")
            with open(full_path, 'r') as f:
                for line in f:
                    logger.debug(f"Ligne : {line.strip()}")
                    if line.startswith("SERVER_ADDRESS="):
                        ip = line.split("=")[1].strip()
                        logger.info(f"Serveur DHCP trouvé via systemd-networkd : {ip}")
                        return ip
        logger.warning("Aucune entrée SERVER_ADDRESS trouvée.")
    except Exception as e:
        logger.error(f"Erreur lecture lease systemd : {e}", exc_info=True)
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

async def send_data_to_server(uri: str, data: dict):
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps(data))
            logger.info("Données envoyées avec succès via WebSocket.")
    except Exception as e:
        logger.error(f"Erreur WebSocket : {e}", exc_info=True)
def main():
    logger.info("=== Démarrage du Network Tool ===")
    ip = get_default_ip()
    iface = get_interface_by_ip(ip)
    gateway = get_gateway()
    dns_list = get_dns_servers()
    dhcp_server = get_dhcp_server_systemd()
    hosts_up = scan_network(ip, iface)

    # Affichage synthétique
    print(f"Interface   : {iface}")
    print(f"IP locale   : {ip}")
    print(f"Passerelle  : {gateway}")
    print(f"Serveur DHCP: {dhcp_server}")
    print("DNS servers :", ", ".join(dns_list))
    print("Hôtes actifs sur le réseau :")
    for h in hosts_up:
        print(h)

    # Données à envoyer
    data = {
        "interface": iface,
        "ip": ip,
        "gateway": gateway,
        "dns": dns_list,
        "dhcp": dhcp_server,
        "hosts_up": hosts_up
    }

    # Adresse de ton serveur WebSocket (local pour le test)
    websocket_uri = "ws://localhost:8000"

    # Envoi asynchrone
    try:
        asyncio.run(send_data_to_server(websocket_uri, data))
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi des données WebSocket : {e}")

    logger.info("=== Fin du Network Tool ===")

if __name__ == "__main__":
    main()
