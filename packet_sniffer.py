from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_analyzer(packet):
    print("=" * 60)
    print("Time:", datetime.now().strftime("%H:%M:%S"))

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} --> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol Type: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Flags: {tcp_layer.flags}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol Type: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            print("Protocol Type: ICMP")

    else:
        print("Non-IP Packet Captured")

def start_sniffing():
    print("Packet Sniffer Started...")
    print("Press CTRL+C to stop\n")
    sniff(prn=packet_analyzer, store=False)

if __name__ == "__main__":
    start_sniffing()
