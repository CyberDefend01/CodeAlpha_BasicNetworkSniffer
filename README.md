# CodeAlpha_BasicNetworkSniffer

from scapy.all import sniff, IP, TCP, UDP, ICMP
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine protocol
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = str(proto)

        print(f"[+] {protocol} Packet: {src_ip} -> {dst_ip}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            print(f"    Payload: {payload[:80]}...")  # Print only first 80 bytes

print("🔍 Starting packet sniffing... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)

This project is part of the CodeAlpha Cybersecurity Internship (M3.1) and demonstrates how to build a **Basic Network Sniffer** in Python using the Scapy library.

## 📌 Project Overview

A **network sniffer** is a tool that captures and analyzes packets as they pass through a network. This project helps you:

- Understand how data flows through a network.
- Learn basic network protocols (TCP, UDP, ICMP).
- Inspect source/destination IPs and protocol types.
- View packet payloads for deeper analysis.

## 💻 Features

- Captures live network traffic.
- Displays source and destination IP addresses.
- Identifies transport layer protocol (TCP/UDP/ICMP).
- Prints part of the payload for quick inspection.

## 🧰 Technologies Used

- Python 3
- [Scapy](https://scapy.readthedocs.io/en/latest/) library

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
