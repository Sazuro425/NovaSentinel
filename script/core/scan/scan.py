#!/usr/bin/env python3
"""
Outil réseau complet :
- Récupération d'IP, interface, passerelle, DNS, serveur DHCP
- Scan réseau en parallèle (ping sweep)
- Scan Nmap des hôtes actifs avec détection de services, versions, CVEs
- Envoi des données à un serveur WebSocket
"""
import os
import socket
import subprocess
import multiprocessing
import xml.etree.ElementTree as ET
import tempfile
import netifaces
import dns.resolver
import ipaddress
import asyncio
import websockets
import json
from script.core.log.mylog import get_custom_logger
from script.core.mydotenv import load_dotenv

load_dotenv()
logger = get_custom_logger("network_tool")

def get_default_ip() -> str:
    """Retourne l'adresse IP locale utilisée pour accéder à Internet (ex: en se connectant à 8.8.8.8)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        logger.error("Erreur IP par défaut", exc_info=True)
        return ""

def get_interface_by_ip(ip: str) -> str:
    """Retourne le nom de l'interface réseau associée à l'adresse IP locale."""
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                if addr.get("addr") == ip:
                    return iface
    except Exception as e:
        logger.error("Erreur interface", exc_info=True)
    return ""

def get_gateway() -> str:
    """Retourne l'adresse IP de la passerelle par défaut."""
    try:
        gw = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
        return gw[0] if gw else ""
    except Exception as e:
        logger.error("Erreur passerelle", exc_info=True)
        return ""

def get_dns_servers() -> list[str]:
    """Retourne la liste des serveurs DNS configurés sur la machine."""
    try:
        return dns.resolver.Resolver().nameservers
    except Exception as e:
        logger.error("Erreur DNS", exc_info=True)
        return []

def get_dhcp_server_systemd() -> str:
    """Lit l'identifiant du serveur DHCP dans les baux système sous /run/systemd/netif/leases."""
    lease_dir = "/run/systemd/netif/leases"
    try:
        if not os.path.isdir(lease_dir):
            return ""
        for fname in os.listdir(lease_dir):
            with open(os.path.join(lease_dir, fname), 'r') as f:
                for line in f:
                    if line.startswith("SERVER_ADDRESS="):
                        return line.split("=")[1].strip()
    except Exception as e:
        logger.error("Erreur DHCP", exc_info=True)
    return ""

def ping_host(ip: str) -> bool:
    """Teste si une adresse IP répond au ping (ICMP echo)."""
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def scan_network(ip: str, iface: str) -> list[str]:
    """Effectue un balayage du réseau local pour détecter les hôtes actifs via ping."""
    up_hosts = []
    try:
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        if not addrs:
            return up_hosts
        netmask = addrs[0].get("netmask")
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        with multiprocessing.Pool() as pool:
            results = pool.map(ping_host, [str(host) for host in network.hosts()])
        for host, alive in zip(network.hosts(), results):
            if alive:
                up_hosts.append(str(host))
    except Exception as e:
        logger.error("Erreur scan réseau", exc_info=True)
    return up_hosts

def scan_with_nmap(targets: list[str]) -> list[dict]:
    """Scanne chaque hôte avec python-nmap en multi-thread pour obtenir les services et versions."""
    import nmap
    import threading

    results = []
    lock = threading.Lock()
    nm = nmap.PortScanner()

    def scan_host(ip):
        try:
            nm.scan(ip, arguments='-sV')
            host_info = {"ip": ip, "services": []}
            for proto in nm[ip].all_protocols():
                lport = nm[ip][proto].keys()
                for port in sorted(lport):
                    serv = nm[ip][proto][port]
                    host_info["services"].append({
                        "port": f"{port}/{proto}",
                        "service": serv.get("name"),
                        "product": serv.get("product"),
                        "version": serv.get("version"),
                        "info": serv.get("extrainfo")
                    })
            with lock:
                results.append(host_info)
        except Exception as e:
            logger.error(f"Erreur Nmap sur {ip} : {e}", exc_info=True)

    threads = []
    for ip in targets:
        t = threading.Thread(target=scan_host, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return results

async def send_data_to_server(uri: str, data: dict):
    """Envoie les données au format JSON vers un serveur WebSocket."""
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps(data))
            logger.info("Données envoyées via WebSocket")
    except Exception as e:
        logger.error("Erreur WebSocket", exc_info=True)

def main():
    """Fonction principale qui orchestre la collecte des informations réseau, le scan, et l'envoi au serveur."""
    logger.info("=== Démarrage Network Tool ===")
    ip = get_default_ip()
    iface = get_interface_by_ip(ip)
    gateway = get_gateway()
    dns_list = get_dns_servers()
    dhcp_server = get_dhcp_server_systemd()
    hosts_up = scan_network(ip, iface)
    nmap_results = scan_with_nmap(hosts_up)

    data = {
        "interface": iface,
        "ip": ip,
        "gateway": gateway,
        "dns": dns_list,
        "dhcp": dhcp_server,
        "hosts_up": hosts_up,
        "nmap": nmap_results
    }

    logger.info(json.dumps(data, indent=2))
    websocket_uri = "ws://localhost:8000"
    try:
        asyncio.run(send_data_to_server(websocket_uri, data))
    except Exception as e:
        logger.error("Erreur envoi WebSocket final", exc_info=True)
    logger.info("=== Fin Network Tool ===")

if __name__ == "__main__":
    main()
