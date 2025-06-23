import sys
import platform
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, ARP # Import necessary layers

def packet_callback(packet):
    print("\n--- New Packet Captured ---")

    # Check for Ethernet
    if Ether in packet:
        print(f"MAC Src: {packet[Ether].src} -> MAC Dst: {packet[Ether].dst}")

    # Check for IP
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto 

        # Map common protocol numbers to names
        protocol_name = "UNKNOWN"
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"

        print(f"IP Src: {src_ip} -> IP Dst: {dst_ip}")
        print(f"Protocol: {protocol_name} ({protocol})")

        # Check for TCP/UDP
        if TCP in packet:
            print(f"TCP Port Src: {packet[TCP].sport} -> TCP Port Dst: {packet[TCP].dport}")
            # Decode HTTP
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                print("HTTP Traffic Detected (port 80)")
                if Raw in packet:
                    try:
                        http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        if "HTTP" in http_data or "GET" in http_data or "POST" in http_data:
                            print(f"HTTP Data (partial): {http_data[:100]}...") 
                    except UnicodeDecodeError:
                        pass

        elif UDP in packet:
            print(f"UDP Port Src: {packet[UDP].sport} -> UDP Port Dst: {packet[UDP].dport}")
            # DNS traffic often uses UDP port 53
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                print("DNS Traffic Detected (port 53)")
                if Raw in packet:
                    print(f"DNS Raw Data (partial): {packet[Raw].load.hex()[:50]}...")

        elif ICMP in packet:
            print(f"ICMP Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")

        # Display raw payload data
        if Raw in packet:
            print(f"Payload (Hex): {packet[Raw].load.hex()[:120]}...") 
            try:
                # Try to decode as ASCII/UTF-8 if it seems like text
                ascii_payload = packet[Raw].load.decode('utf-8', errors='ignore')
                printable_payload = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in ascii_payload)
                if len(printable_payload.strip()) > 0 and len(printable_payload) > 5: 
                    print(f"Payload (ASCII): {printable_payload[:120]}...")
            except UnicodeDecodeError:
                pass 

    elif ARP in packet:
        print(f"ARP Request/Reply: {packet[ARP].psrc} ({packet[ARP].hwsrc}) -> {packet[ARP].pdst} ({packet[ARP].hwdst})")
    else:
        print(f"Non-IP Packet: {packet.summary()}")


def start_sniffer(interface=None, count=0, packet_filter=""):
    print("\n--- Starting Packet Sniffer ---")
    print("WARNING: This tool is for educational purposes ONLY. Use it ethically and responsibly.")
    print("Do NOT use it on networks you don't own or have explicit permission to monitor.")
    print("Press Ctrl+C to stop the sniffer.")

    if platform.system() == "Windows" and interface is None:
        print("On Windows, you might need to specify the interface name (e.g., 'Ethernet', 'Wi-Fi')")
        print("You can list interfaces using 'scapy.all.show_interfaces()'.")

    try:
        sniff(iface=interface, prn=packet_callback, store=0, count=count, filter=packet_filter)
    except Exception as e:
        print(f"An error occurred during sniffing: {e}")
        if "No such device" in str(e) or "interface not found" in str(e):
            print("Please check your interface name. On Linux/macOS, it might be 'eth0', 'wlan0', or 'en0'.")
            print("On Windows, it could be 'Ethernet', 'Wi-Fi', or the adapter description.")
            print("Also ensure you have proper permissions (run as administrator/root).")
        print("Exiting sniffer.")

def main():
    interface = None
    count = 0
    packet_filter = ""

    print("\n Simple Packet Sniffer")
    print("1. Start Sniffer")
    print("2. Start Sniffer with Interface and Filter")
    print("3. Exit")

    choice = input("Enter your choice (1-3): ")

    if choice == '1':
        print("Starting sniffer on default interface (may not work on all systems without explicit interface).")
        start_sniffer(interface=None, count=0)
    elif choice == '2':
        print("\nNote: To find your interface name:")
        if platform.system() == "Windows":
            print("  - Run 'get_if_list()' or 'show_interfaces()' in a Python interpreter after importing scapy.all.")
            print("  - Or check Network Connections in Control Panel.")
        else: # Linux/macOS
            print("  - Use 'ip a' (Linux) or 'ifconfig' (macOS) in your terminal.")

        interface = input("Enter network interface name (e.g., eth0, wlan0, Ethernet, Wi-Fi): ").strip()
        packet_filter = input("Enter a BPF filter (e.g., 'tcp', 'udp port 53', 'host 192.168.1.1', leave empty for none): ").strip()

        if not interface:
            print("Interface name cannot be empty for this option. Using default.")
            interface = None 

        print(f"Starting sniffer on interface: {interface if interface else 'default'}")
        if packet_filter:
            print(f"With filter: '{packet_filter}'")
        start_sniffer(interface=interface if interface else None, count=0, packet_filter=packet_filter)
    elif choice == '3':
        print("Exiting")
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()