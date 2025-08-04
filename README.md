# CodeAlpha_BasicNetworkSniffer

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
**2. Install Dependencies**
bash
Copy
Edit
pip install scapy
**3. Run the Sniffer**
⚠️ Note: Root/administrator privileges are required to capture packets.

bash
Copy
Edit
sudo python3 network_sniffer.py
On Windows, right-click the terminal and run as administrator.

📂 File Structure
bash
Copy
Edit
CodeAlpha_BasicNetworkSniffer/
├── network_sniffer.py  # Main sniffer script
└── README.md           # Project documentation
