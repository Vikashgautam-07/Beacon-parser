Beacon-Parser
Automated 802.11 Protocol Analysis & Validation Tool

Overview
A Python-based utility developed to validate IEEE 802.11 MAC layer management frames. This tool parses PCAP files to extract network capabilities, security configurations, and physical layer parameters.

Technical Highlights
Protocol Validation: Decodes Beacon frames to identify SSID, BSSID, and Channel allocation.

Security Auditing: Parses RSN Information Elements to detect WPA2/WPA3 encryption standards.

Standard Detection: Identifies PHY capabilities (802.11g/n/ac) by analyzing HT/VHT capability bits.

Robustness: Implemented defensive programming to handle malformed packets or missing RadioTap headers.

Setup
pip install -r requirements.txt

python3 src/main.py data/your_capture.pcap
