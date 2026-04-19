from scapy.all import *

def packet_callback(packet):

    print("\nEthernet Frame:")

    # Ethernet Layer
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f" - Destination: {eth.dst}, Source: {eth.src}, Protocol: {eth.type}")

    # IP Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        print(" - IPv4 Packet:")
        print(f"    Version: {ip.version}, Header Length: {ip.ihl*4}, TTL: {ip.ttl}")
        print(f"    Protocol: {ip.proto}, Source: {ip.src}, Target: {ip.dst}")

    # TCP Layer
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(" - TCP Segment:")
        print(f"    Source Port: {tcp.sport}, Destination Port: {tcp.dport}")
        print(f"    Sequence: {tcp.seq}, Acknowledgment: {tcp.ack}")

        print("    Flags:")
        print(f"     URG: {tcp.flags.U}, ACK: {tcp.flags.A}, PSH: {tcp.flags.P}, "
              f"RST: {tcp.flags.R}, SYN: {tcp.flags.S}, FIN: {tcp.flags.F}")

    # Payload Data
    if packet.haslayer(Raw):
        data = packet[Raw].load
        print(" - Data:")
        print(data)

    print("-" * 60)


print("Starting Network Sniffer... Press Ctrl+C to stop")

sniff(prn=packet_callback, store=False)