# 🛡️ CyberShield - Wi-Fi Security Analyser & Spectrum Auditor

A professional, high-performance **Wi-Fi Security Analyser, Spectrum Auditor, and Threat Assessment Engine** designed for Windows.

CyberShield audits wireless access points, evaluates encryption protocols against modern cybersecurity standards (NIST, CIS, Wi-Fi Alliance), detects potential Evil-Twin / Rogue APs, analyzes channel congestion, and assesses client-side roaming and DNS privacy risks.

---

## 🌟 Key Features

### 1. 🛰️ Deep Wi-Fi Spectrum & Access Point Scanner
- **Live Discovery**: Discovers all visible SSIDs, BSSIDs (MAC addresses), signal strength (percentage and approximate dBm), frequency band (2.4 GHz vs 5 GHz), channel numbers, and 802.11 standards (802.11b/g/n/ac/ax).
- **Hardware Vendor Identification (OUI)**: Resolves MAC prefixes to device manufacturers (Realtek, Intel, Cisco, Ubiquiti, TP-Link, Netgear, Apple, etc.).
- **Cryptographic Suite Auditing**: Flags Open/Unencrypted networks, deprecated WEP RC4 ciphers, legacy WPA1/TKIP, standard WPA2-CCMP, and modern WPA3-SAE (Simultaneous Authentication of Equals).

### 2. 🚨 Automated Threat Grading & Rogue AP Detection
- **Airspace Health Score**: Aggregated 0–100 security index for the local radio environment.
- **Vulnerability Breakdown**: Each network is assigned a security letter grade (`A+`, `A`, `B`, `C`, `D`, `F`) with detailed CVE/CWE definitions and remediation guidance.
- **Evil Twin / Rogue AP Detection**: Flags situations where multiple APs broadcast identical SSIDs with differing security suites (e.g. an open rogue clone imitating a secure network).
- **Hidden SSID Privacy Warnings**: Identifies hidden SSIDs and warns about client probe-request tracking risks.

### 3. 📊 Visual Channel Spectrum Analyzer
- **Interactive 2.4 GHz & 5 GHz Distribution**: Real-time canvas visualization of active channels.
- **Interference Detector**: Highlights co-channel collisions and non-standard channel overlap (outside non-overlapping channels 1, 6, and 11).

### 4. 🔒 Connected Network Deep Diagnostics
- **Active Connection Auditing**: Analyzes current Wi-Fi interface, link speed (Tx/Rx Mbps), and signal quality.
- **Gateway & Routing**: Measures gateway latency (RTT ping).
- **DNS Security & Privacy Check**: Distinguishes between unencrypted local/ISP DNS and encrypted/high-reputation secure resolvers (Cloudflare, Quad9, Google).
- **Driver Security Capabilities**: Checks for Protected Management Frames (PMF / 802.11w) and FIPS 140-2 support.

### 5. 💾 Saved Profiles & Auto-Connect Audit
- Audits stored Wi-Fi profiles in Windows.
- Alerts on dangerous settings (such as auto-connecting to open Wi-Fi networks).
- Audits MAC address randomization status.

### 6. 🔑 WPA Pre-Shared Key (PSK) Entropy Lab
- Interactive password testing tool measuring Shannon entropy bits, character space pool, and GPU cluster (8x RTX 4090) brute-force cracking resistance.

### 7. 📄 One-Click Audit Export
- Instantly export complete audit findings as structured JSON for compliance, archiving, or reporting.

---

## 🏗️ Project Architecture

```
MiniProject/
├── app.py                  # Main Flask Web Server & REST API backend
├── cli.py                  # Rich terminal CLI security auditor
├── run.bat                 # 1-click Windows launcher
├── requirements.txt        # Python package dependencies
├── core/
│   ├── __init__.py         # Package exports
│   ├── scanner.py          # Native netsh WLAN scanner & parser
│   ├── security_engine.py  # Risk scoring, vulnerability evaluator & rogue AP heuristics
│   ├── connection_info.py  # Network adapter, gateway ping, DNS privacy & driver audit
│   ├── profile_auditor.py  # Stored profile security & password entropy engine
│   └── oui_lookup.py       # Hardware vendor (OUI) lookup
├── static/
│   ├── css/
│   │   └── style.css       # Cybersecurity SOC dashboard design system (Vanilla CSS)
│   └── js/
│       └── app.js          # Interactive dashboard logic, canvas charts, filters & modal
└── templates/
    └── index.html          # Web dashboard layout
```

---

## 🚀 Getting Started

### Prerequisites
- Windows 10 or 11
- Python 3.8+ (Python 3.14 supported)
- Wi-Fi network interface enabled

### Installation

1. Navigate to the project directory:
   ```powershell
   cd "d:\New folder\PROJECTSSUJAL\MiniProject"
   ```

2. (Optional) Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

---

## 💻 Running the Application

### Option A: Web Dashboard (Recommended)
Launch the web interface:
```powershell
python app.py
```
Then open your browser at **[http://127.0.0.1:5050](http://127.0.0.1:5050)**.

### Option B: Terminal CLI Audit
For quick command-line audits:
```powershell
python cli.py
```

### Option C: 1-Click Launcher (Windows)
Double-click `run.bat` in File Explorer or run:
```powershell
.\run.bat
```

---

## 🔒 Security Grading Standards

| Grade | Risk Level | Authentication / Cipher | Description |
|:---:|:---:|:---:|:---|
| **A+** | Secure | WPA3-Personal (SAE) / WPA3-Enterprise | Protected Management Frames, dragonfly handshake, forward secrecy. |
| **A** | Good | WPA2-Personal (CCMP / AES) | Industry standard AES encryption. |
| **B** | Fair | WPA2 with weak signal or mild interference | Secure encryption with environmental cautions. |
| **D** | High Risk | WPA1 / TKIP | Deprecated protocol; susceptible to Beck-Tews and ChopChop attacks. |
| **F** | Critical | Open / Unencrypted or WEP | RC4 stream cipher easily cracked; plaintext eavesdropping risk. |
