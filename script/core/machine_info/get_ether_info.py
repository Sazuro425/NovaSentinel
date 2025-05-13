#!/usr/bin/env python3
import dns.resolver
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp
import socket
print(socket.gethostbyname(socket.gethostname()))