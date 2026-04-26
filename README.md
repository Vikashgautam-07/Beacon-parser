# Beacon-Parser
**Automated 802.11 Protocol Analysis & Validation Tool**

## 📌 Overview
Beacon-Parser is a Python-based network validation utility developed to analyze IEEE 802.11 MAC layer management and data frames. This tool bridges the gap between low-level hardware captures and high-level network intelligence, providing deep insights into SSID configurations, security standards (WPA2/WPA3), and device activity.

The tool is engineered with a **cross-layer fallback mechanism**, allowing it to process native 802.11 frames (Monitor Mode) as well as Ethernet-encapsulated WLAN traffic (Managed Mode/Windows NDIS), making it highly versatile for firmware and validation engineers.

## 🚀 Key Features
* **Protocol Agnostic Parsing:** Supports both `Dot11` (native Wi-Fi) and `Ether` (standard OS) frame layers.
* **Security Auditing:** Parses RSN (Robust Security Network) Information Elements to detect WPA2/WPA3 encryption standards.
* **Standard Detection:** Identifies PHY capabilities (802.11g/n/ac) by analyzing HT/VHT capability bits.
* **Automated Reporting:** Generates a structured **Network Validation Report** summarizing unique devices and traffic distribution.
* **Defensive Programming:** Implements robust type-checking to handle missing RadioTap headers and malformed TLV (Type-Length-Value) structures.

## 🛠️ Technical Stack
* **Language:** Python 3.x
* **Library:** [Scapy](https://scapy.net/) (Packet manipulation and decoding)
* **Environment:** Tested on Linux (WSL2/Ubuntu) and Windows-based PCAP/PCAPNG dumps.

## Install dependencies:

```Bash
pip install -r requirements.txt
Run the parser:

# For native 802.11 management captures (Monitor Mode)
python3 src/main.py data/wpa-Induction.pcap

# For standard managed network captures (Windows/Standard Driver)
python3 src/main.py data/myhome3.pcapng
```
## 🧠 Engineering Challenges Overcome
Hardware Abstraction Layers: I discovered that standard Windows drivers strip 802.11 headers and present them as Ethernet II frames via the NDIS driver. I implemented a fallback to the Ethernet layer to ensure the tool provides device visibility even without Monitor Mode hardware.

Packet Integrity: Handled NoneType and IndexError exceptions caused by packets missing the standard RadioTap header, ensuring the parser doesn't crash during large batch processing.

## 📜 License
Distributed under the MIT License. See LICENSE for more information.
