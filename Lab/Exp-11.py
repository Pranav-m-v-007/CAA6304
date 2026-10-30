from scapy.all import sniff, IP, TCP, UDP, ICMP

def display_packet(packet):

    print("\nPacket Captured")

    if IP in packet:

        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

    if TCP in packet:

        print("Protocol: TCP")
        print("Source Port:", packet[TCP].sport)
        print("Destination Port:", packet[TCP].dport)

    elif UDP in packet:

        print("Protocol: UDP")
        print("Source Port:", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)

    elif ICMP in packet:

        print("Protocol: ICMP")

    else:

        print("Other Protocol")

    print("Summary:", packet.summary())
    print("-" * 40)


print("NETWORK PACKET SNIFFER")
print("Capturing 10 packets...")

try:

    sniff(
        count=10,
        prn=display_packet,
        store=False
    )

    print("\nPacket Capturing Completed")

except PermissionError:

    print("Permission denied. Run with administrator/root privileges.")

except Exception as error:

    print("Error:", error)
