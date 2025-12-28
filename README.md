# Network Traffic Inspector

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Vibe](https://img.shields.io/badge/Vibe-100%25-ff0066?style=for-the-badge)

A powerful, sleek, and dark-themed network traffic inspector built with Python and CustomTkinter. 
Discover devices, intercept traffic (MITM), and analyze DNS/SNI requests in real-time.

**100% vibe coded**

## ✨ Features

* **🎨 Ultra Modern UI**: Built with `CustomTkinter` for a premium dark-mode experience.
* **🔍 Advanced Device Scanning**: Instant discovery of all devices (IP, MAC, Vendor).
* **👁️ Deep Packet Inspection (DPI)**:
    * **DNS Snooping**: Sees what websites devices are asking for.
    * **SNI Analysis**: Detects HTTPS websites even without DNS logs.
* **⚡ Active Interception (MITM)**:
    * Redirects target traffic through your machine for 100% visibility.
    * Works on mobile phones, tablets, and IoT devices.
* ** Log Export**: One-click save to `.txt` for forensic analysis.
* **� Auto-Setup**: Windows batch script handles dependencies automatically.

## 🚀 Installation

### 🪟 Windows

[![Download ZIP](https://img.shields.io/badge/Download_Project_ZIP-ff0066?style=for-the-badge&logo=github)](https://github.com/shubhambelbase/Network-Scanner/archive/refs/heads/main.zip)

1. **Download and Extract** the ZIP (click the button above).
2. **Start the App**: 
   * Right-click `run_monitor.bat` and select **"Run as Administrator"**.
   * *The script will automatically install dependencies (scapy, customtkinter) if missing.*

---

### 🐧 Linux / � macOS

For Unix-based systems, it is recommended to use a virtual environment. You **must** use `sudo` to capture traffic.

#### **1. Install System Prerequisites**
Ensure you have Python and libpcap installed:

* **macOS (Homebrew):** `brew install python-tk libpcap`
* **Linux (Debian/Ubuntu):** `sudo apt install python3-tk python3-pip libpcap-dev`

#### **2. Setup & Installation**
Open your terminal and run the following commands:

```bash
# Clone the repository
git clone https://github.com/shubhambelbase/Network-Scanner.git
cd Network-Scanner

# Create a virtual environment
python3 -m venv venv

# Activate the environment
# For macOS/Linux:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Run the App (Requires Root/Sudo)
sudo python net_admin.py
```

---

## ⚠️ Legal Disclaimer

**For Educational and Diagnostic Purposes Only.**
This software is designed for network administrators to monitor their *own* networks. Attempting to intercept traffic on networks you do not own or have permission to test is illegal and punishable by law. The authors accept no responsibility for unauthorized use.
