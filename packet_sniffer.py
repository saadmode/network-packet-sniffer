"""
Network Packet Sniffer (improved)

Examples:
    python packet_sniffer.py --list
    python packet_sniffer.py --iface "Wi-Fi" --proto tcp --count 50
    python packet_sniffer.py --filter "port 443" --write capture.pcap
    python packet_sniffer.py            (interactive mode)

Requires: scapy, plus Npcap (Windows) or libpcap (Linux/macOS).
Needs administrator/root privileges to capture.
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

from scapy.all import (
    ARP, DNS, DNSQR, IP, IPv6, TCP, UDP, ICMP,
    conf, sniff,
)
from scapy.utils import PcapWriter

PROTO_FILTERS = {
    "all": "",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp or icmp6",   # covers both ICMPv4 and ICMPv6
    "arp": "arp",
    "dns": "udp port 53",
}

# Capture statistics
stats = {
    "packets": 0,
    "bytes": 0,
    "protocols": Counter(),
    "sources": Counter(),
}
writer = None


# ---------------------------------------------------------------- interfaces
def list_interfaces():
    """Return a list of (name, description, ip) for available interfaces."""
    result = []
    for iface in conf.ifaces.values():
        name = getattr(iface, "name", str(iface))
        desc = getattr(iface, "description", "") or ""
        ip = getattr(iface, "ip", "") or ""
        result.append((name, desc, ip))
    return result


def print_interfaces(interfaces):
    print("\nAvailable interfaces:")
    for i, (name, desc, ip) in enumerate(interfaces, 1):
        extra = f" - {desc}" if desc and desc != name else ""
        addr = f" [{ip}]" if ip else ""
        print(f"  {i}. {name}{extra}{addr}")


def choose_interface():
    interfaces = list_interfaces()
    if not interfaces:
        return None
    print_interfaces(interfaces)
    while True:
        choice = input("\nChoose interface number (Enter = default): ").strip()
        if choice == "":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            return interfaces[int(choice) - 1][0]
        print("Invalid choice, try again.")


# -------------------------------------------------------------------- filter
def choose_filter():
    options = list(PROTO_FILTERS)
    print("\nWhat do you want to capture?")
    for i, name in enumerate(options, 1):
        print(f"  {i}. {name}")
    while True:
        choice = input(f"Choose an option (1-{len(options)}): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return PROTO_FILTERS[options[int(choice) - 1]]
        print("Invalid choice, try again.")


# ------------------------------------------------------------------- parsing
def get_protocol(packet):
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(IPv6) and packet[IPv6].nh == 58:
        return "ICMPv6"
    if packet.haslayer(IP):
        return "IPv4"
    if packet.haslayer(IPv6):
        return "IPv6"
    return "Other"


def get_addresses(packet):
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    if packet.haslayer(ARP):
        return packet[ARP].psrc, packet[ARP].pdst
    return "Unknown", "Unknown"


def get_details(packet):
    """Build a protocol-specific details string."""
    parts = []

    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            parts.append(f"Who has {arp.pdst}? Tell {arp.psrc} ({arp.hwsrc})")
        elif arp.op == 2:
            parts.append(f"{arp.psrc} is at {arp.hwsrc}")
        else:
            parts.append(f"ARP op {arp.op}")
        return " | ".join(parts)

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        parts.append(f"Port {tcp.sport} -> {tcp.dport}")
        parts.append(f"Flags [{tcp.flags}]")
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        parts.append(f"Port {udp.sport} -> {udp.dport}")

    # DNS queries (qr == 0 means query, not response)
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors="replace")
        parts.append(f"DNS query: {qname}")

    return " | ".join(parts)


# ------------------------------------------------------------------- display
def show_packet(packet):
    stats["packets"] += 1
    stats["bytes"] += len(packet)

    protocol = get_protocol(packet)
    source, destination = get_addresses(packet)
    stats["protocols"][protocol] += 1
    if source != "Unknown":
        stats["sources"][source] += 1

    if writer:
        writer.write(packet)

    time_seen = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
    details = get_details(packet)

    print("-" * 75)
    print(f"Packet Number : {stats['packets']}")
    print(f"Time          : {time_seen}")
    print(f"Protocol      : {protocol}")
    print(f"Source        : {source}")
    print(f"Destination   : {destination}")
    print(f"Length        : {len(packet)} bytes")
    if details:
        print(f"Details       : {details}")


def print_summary():
    print("\n" + "=" * 40)
    print("CAPTURE SUMMARY")
    print("=" * 40)
    print(f"Total packets : {stats['packets']}")
    print(f"Total bytes   : {stats['bytes']}")

    if stats["protocols"]:
        print("\nPackets per protocol:")
        for proto, count in stats["protocols"].most_common():
            print(f"  {proto:<8} {count}")

    if stats["sources"]:
        print("\nTop 5 sources:")
        for src, count in stats["sources"].most_common(5):
            print(f"  {src:<40} {count}")


# ---------------------------------------------------------------------- main
def parse_args():
    parser = argparse.ArgumentParser(description="Simple network packet sniffer")
    parser.add_argument("--list", action="store_true", help="list interfaces and exit")
    parser.add_argument("-i", "--iface", help="interface name to capture on")
    parser.add_argument("-p", "--proto", choices=PROTO_FILTERS, help="protocol shortcut")
    parser.add_argument("-f", "--filter", help="raw BPF filter (overrides --proto)")
    parser.add_argument("-c", "--count", type=int, default=0, help="stop after N packets")
    parser.add_argument("-w", "--write", metavar="FILE", help="save capture to a .pcap file")
    return parser.parse_args()


def main():
    global writer
    args = parse_args()

    if args.list:
        print_interfaces(list_interfaces())
        return

    print("=" * 40)
    print("       NETWORK PACKET SNIFFER")
    print("=" * 40)

    interactive = len(sys.argv) == 1
    if interactive:
        iface = choose_interface()
        packet_filter = choose_filter()
    else:
        iface = args.iface
        packet_filter = args.filter or PROTO_FILTERS.get(args.proto or "all", "")

    if args.write:
        writer = PcapWriter(args.write, append=False, sync=True)

    print(f"\nInterface : {iface or 'default'}")
    print(f"Filter    : {packet_filter or 'none'}")
    if args.write:
        print(f"Saving to : {args.write}")
    print("Starting capture... press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=iface,
            filter=packet_filter or None,
            prn=show_packet,
            store=False,
            count=args.count,
        )
    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied. Run as Administrator (Windows) or with sudo (Linux/macOS).")
    except OSError as error:
        print(f"\nCapture error: {error}")
        print("Check that Npcap/libpcap is installed, the interface name is correct,")
        print("and that you have the required privileges.")
    except Exception as error:
        print(f"\nUnexpected error: {error}")
    finally:
        if writer:
            writer.close()
        print_summary()


if __name__ == "__main__":
    main()
