#!/usr/bin/env python3
import socket
import dns.resolver
import netifaces
from script.core.log.mylog import get_custom_logger

# Initialisation du logger pour le scan réseau
logger = get_custom_logger("scan")

def get_default_ip():
    """Retourne l'IP locale utilisée pour sortir vers Internet."""
    logger.debug("Entrée dans get_default_ip()")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        logger.info(f"IP par défaut déterminée : {ip}")
        return ip
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'IP par défaut : {e}", exc_info=True)
        return None
    finally:
        s.close()
        logger.debug("Fermeture du socket dans get_default_ip()")


def get_interface_by_ip(ip):
    """Cherche le nom de l'interface correspondant à une IP."""
    logger.debug(f"Entrée dans get_interface_by_ip(ip={ip})")
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                if addr.get("addr") == ip:
                    logger.info(f"Interface trouvée pour IP {ip} : {iface}")
                    return iface
        logger.warning(f"Aucune interface trouvée pour l'IP {ip}")
        return None
    except Exception as e:
        logger.error(f"Erreur lors de la recherche d'interface pour IP {ip} : {e}", exc_info=True)
        return None


def get_gateway():
    """Récupère la passerelle par défaut IPv4."""
    logger.debug("Entrée dans get_gateway()")
    try:
        gws = netifaces.gateways().get("default", {})
        gw = gws.get(netifaces.AF_INET)
        gateway = gw[0] if gw else None
        logger.info(f"Passerelle par défaut : {gateway}")
        return gateway
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la passerelle : {e}", exc_info=True)
        return None


def get_dns_servers():
    """Renvoie la liste des serveurs DNS configurés."""
    logger.debug("Entrée dans get_dns_servers()")
    try:
        resolver = dns.resolver.Resolver()
        servers = resolver.nameservers
        logger.info(f"Serveurs DNS détectés : {servers}")
        return servers
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des serveurs DNS : {e}", exc_info=True)
        return []


if __name__ == "__main__":
    logger.info("Démarrage du scan réseau")
    ip = get_default_ip()
    iface = get_interface_by_ip(ip)
    gateway = get_gateway()
    dns_list = get_dns_servers()

    logger.info(f"Résultats du scan : Interface={iface}, IP={ip}, Passerelle={gateway}, DNS={dns_list}")

    print(f"Interface  : {iface}")
    print(f"Adresse IP : {ip}")
    print(f"Passerelle : {gateway}")
    print("Serveurs DNS :")
    for dns in dns_list:
        print(f"  - {dns}")

    logger.info("Fin du scan réseau")
