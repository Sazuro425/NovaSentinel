#!/usr/bin/env python3
import socket
import dns.resolver
import netifaces
from script.log.mylog import get_custom_logger
def get_default_ip():
    """Retourne l'IP locale utilisée pour sortir vers Internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def get_interface_by_ip(ip):
    """Cherche le nom de l'interface correspondant à une IP."""
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        for addr in addrs:
            if addr.get("addr") == ip:
                return iface
    return None

def get_gateway():
    """Récupère la passerelle par défaut IPv4."""
    gws = netifaces.gateways().get("default", {})
    gw = gws.get(netifaces.AF_INET)
    return gw[0] if gw else None

def get_dns_servers():
    """Renvoie la liste des serveurs DNS configurés."""
    resolver = dns.resolver.Resolver()
    return resolver.nameservers

def main():
    ip       = get_default_ip()
    iface    = get_interface_by_ip(ip)
    gateway  = get_gateway()
    dns_list = get_dns_servers()

    print(f"Interface  : {iface}")
    print(f"Adresse IP : {ip}")
    print(f"Passerelle : {gateway}")
    print("DNS        :")
    for dns in dns_list:
        print(f"  - {dns}")

if __name__ == "__main__":
    main()
