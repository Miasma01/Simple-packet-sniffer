from scapy.all import sniff, IP, TCP

def packet_sniffer(interface):
    sniff(iface=interface, prn=lambda packet: print(packet.summary()))

# Example usage
interface = "eth0"  # Change to your network interface
packet_sniffer(interface)