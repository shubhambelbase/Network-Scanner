# 🌐 Network Traffic Inspector
> **Professional Real-Time Traffic Analysis & Monitoring Tool**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-lightgrey) ![License](https://img.shields.io/badge/License-MIT-green)

**Network Inspector** is a cutting-edge diagnostic tool designed to give you complete visibility over your local network. Unlike standard scanners, it goes deeper—allowing you to inspect traffic flows, resolve website names (DNS/SNI), and monitor device activity in real-time.

---

## ✨ Key Features

*   **🔍 Advanced Device Scanning**: Instant discovery of all devices (IP, MAC, Vendor).
*   **👁️ Deep Packet Inspection (DPI)**:
    *   **DNS Snooping**: Sees what websites devices are asking for.
    *   **SNI Analysis**: Detects HTTPS websites even without DNS logs.
*   **⚡ Active Interception (MITM)**:
    *   Redirects target traffic through your machine for 100% visibility.
    *   Works on mobile phones, tablets, and IoT devices.
*   **💅 Modern UI**: Fully animated, dark-themed interface built with CustomTkinter.
*   **💾 Log Export**: One-click save to `.txt` for forensic analysis.

---

## 📥 Downloads & Installation

### 🪟 For Windows Users (Recommended)

The easiest way to run the tool. No command line required.

1.  **Download this Repository**: [![Download ZIP](https://img.shields.io/badge/Download_Project_ZIP-ff0066?style=for-the-badge&logo=github)](https://github.com/shubhambelbase/python-image-crawle/archive/refs/heads/main.zip)

2.  Extract the ZIP file to a folder.
3.  Right-click **`run_monitor.bat`** and select **"Run as Administrator"**.
    *   *Note: usage of Npcap (included in Wireshark) is recommended for best performance.*

---

### 🐧 For Linux & 🍏 MacOS Users

Since this tool requires low-level network access, you must run it with `sudo`/root privileges.

#### **1. Prerequisites**
*   **Python 3.8+**
*   **libpcap** (Linux usually has this, Mac might need it)

#### **2. Installation Guide**

**Terminal Setup:**
```bash
# Clone or Download this repository
git clone https://github.com/shubhambelbase/Network-Scanner.git
cd network-monitor

# Install Python Dependencies
pip3 install -r requirements.txt
# OR manually:
pip3 install customtkinter scapy psutil
```

**Running the App:**
You **must** use `sudo` to capture traffic.

```bash
# Linux / MacOS
sudo python3 net_admin.py
```

*Note for Mac Users: If using a newer macOS, you may need to allow Terminal "Local Network" permissions in System Settings.*

---

## 🛠️ How to Use

1.  **Start Scan**: Click the "Network Scanner" tab to list all active devices.
2.  **Inspect**: Click the **`Inspect`** button next to a target device (e.g., a suspicious phone).
3.  **Active Mode**: 
    *   Toggle **"Active Interception"** to **ON**.
    *   This forces the device's traffic to route through you.
4.  **Watch Logs**: Real-time website names (`netflix.com`, `instagram.com`) will appear.
5.  **Save**: Click `Save Logs` to export the session.

---

## ⚠️ Legal Disclaimer

**For Educational and Diagnostic Purposes Only.**
This software is designed for network administrators to monitor their *own* networks. Attempting to intercept traffic on networks you do not own or have permission to test is illegal and punishable by law. The authors accept no responsibility for unauthorized use.

---
*Built with ❤️ by Shubham*

