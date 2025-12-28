# NetAdmin Pro

A Python-based Network Administration Tool with GUI.

## Features
- **Network Scanner**: Discovery of devices on your local network (IP/MAC).
- **Traffic Monitor**: Real-time Upload/Download speed visualization.
- **Control Center**: Manage known devices.

## Requirements
- `scapy`
- `customtkinter`
- `psutil`

### Creating a Virtual Environment (Recommended)
This tool requires Npcap on Windows for full features (ARP Scanning).

## Installation of Npcap
1. Download Npcap from [https://npcap.com/](https://npcap.com/).
2. Install it with "Install Npcap in WinPcap API-compatible Mode" checked.

## Running
```bash
python net_admin.py
```

## Troubleshooting
- If no devices are found, ensure you have Npcap installed.
- Without Npcap, the tool uses a slower Ping Sweep method.
