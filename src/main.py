import sys
from scapy.all import rdpcap, Dot11, Dot11Beacon, Ether
from collections import Counter

def analyze_pcap(file_path):
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error: {e}")
        return

    print(f"{'Source/SSID':<18} | {'MAC Address':<18} | {'Protocol':<12} | {'Security'}")
    print("-" * 80)

    seen_macs = set()
    stats = Counter()

    for pkt in packets:
        # 1. Native 802.11 Check
        if pkt.haslayer(Dot11):
            mac = pkt[Dot11].addr3 or pkt[Dot11].addr2
            if not mac or mac in seen_macs: continue
            
            if pkt.haslayer(Dot11Beacon):
                try:
                    name = pkt.info.decode('utf-8', errors='ignore') or "Hidden"
                except: name = "Unknown"
                proto = "802.11 Mgmt"
                security = "WPA2/WPA3" if pkt.haslayer('Dot11EltRSN') else "Open"
                stats['Management Frames'] += 1
            else:
                name = "Active Device"
                proto = "802.11 Data"
                security = "Encrypted"
                stats['Data Frames'] += 1
            
            print(f"{str(name):<18} | {str(mac):<18} | {str(proto):<12} | {str(security)}")
            seen_macs.add(mac)

        # 2. Ethernet Fallback
        elif pkt.haslayer(Ether):
            mac = pkt[Ether].src
            if mac in seen_macs: continue
            
            name = "Home Device"
            proto = "Ethernet/WF"
            security = "Managed"
            stats['Ethernet Frames'] += 1
            
            print(f"{str(name):<18} | {str(mac):<18} | {str(proto):<12} | {str(security)}")
            seen_macs.add(mac)

    # --- Final Validation Report ---
    print("\n" + "="*30)
    print("   NETWORK VALIDATION REPORT")
    print("="*30)
    print(f"Total Unique Devices: {len(seen_macs)}")
    for frame_type, count in stats.items():
        print(f"{frame_type:<18}: {count}")
    print("="*30)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 src/main.py data/your_file.pcap")
    else:
        analyze_pcap(sys.argv[1])
