#!/usr/bin/env python3
import dns.resolver
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp
import socket

print(socket.gethostbyname(socket.gethostname()))

def get_dns():
    """Function to get local DNS resolvers."""
    resolver = dns.resolver.Resolver()
    print(resolver.nameservers)



def send_dhcp_discover(interface="wlo1"):
    dhcp_discover = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(':', '')), xid=0x12345678) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    ans, _ = srp(dhcp_discover, iface=interface, timeout=5, verbose=0)

    for _, pkt in ans:
        if pkt.haslayer(DHCP):
            print(f"Réponse DHCP OFFER reçue de {pkt[IP].src}")
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple):
                    print(f"{opt[0]}: {opt[1]}")



if __name__ == "__main__":
    get_dns()
    
    