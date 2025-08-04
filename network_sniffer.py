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
