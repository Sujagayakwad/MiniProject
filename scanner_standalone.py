#!/usr/bin/env python3
"""
WiFi Security Analyzer - All-in-One Version
Single file, no dependencies, works on Linux/Mac/Windows
"""

import subprocess
import re
import json
import platform
import sys
from datetime import datetime
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


class WiFiScanner:
    def __init__(self):
        self.networks = []
        self.system = platform.system()
        
    def scan(self):
        """Scan for WiFi networks based on OS"""
        print(f"\n[*] Detected OS: {self.system}")
        print("[*] Scanning for WiFi networks...\n")
        
        try:
            if self.system == "Linux":
                self._scan_linux()
            elif self.system == "Darwin":
                self._scan_macos()
            elif self.system == "Windows":
                self._scan_windows()
            else:
                print(f"[!] Unsupported OS: {self.system}")
                return []
                
        except PermissionError:
            print("\n[!] Permission denied!")
            print("[*] Linux/Mac: Run with 'sudo python scanner.py'")
            print("[*] Windows: Run as Administrator")
            return []
        except Exception as e:
            print(f"[!] Error: {e}")
            return []
        
        return self.networks
    
    def _scan_linux(self):
        """Linux: Try iw first, fallback to iwlist"""
        try:
            # Get interface
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            interface = re.search(r'Interface\s+(\w+)', result.stdout)
            
            if not interface:
                # Try iwlist method
                self._scan_linux_iwlist()
                return
            
            iface = interface.group(1)
            
            # Scan
            subprocess.run(['sudo', 'iw', iface, 'scan'], 
                          capture_output=True, check=True)
            result = subprocess.run(['sudo', 'iw', iface, 'scan'], 
                                  capture_output=True, text=True, check=True)
            
            self._parse_iw_scan(result.stdout)
            
        except Exception:
            self._scan_linux_iwlist()
    
    def _scan_linux_iwlist(self):
        """Linux fallback using iwlist"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interface = re.search(r'(\w+)\s+IEEE', result.stdout)
            
            if not interface:
                print("[!] No wireless interface found")
                return
            
            iface = interface.group(1)
            
            result = subprocess.run(['sudo', 'iwlist', iface, 'scan'], 
                                  capture_output=True, text=True, check=True)
            
            self._parse_iwlist(result.stdout)
            
        except Exception as e:
            print(f"[!] iwlist failed: {e}")
    
    def _scan_macos(self):
        """macOS using airport utility"""
        try:
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            result = subprocess.run([airport, '-s'], 
                                  capture_output=True, text=True, check=True)
            self._parse_airport(result.stdout)
        except Exception as e:
            print(f"[!] Airport scan failed: {e}")
    
    def _scan_windows(self):
        """Windows using netsh"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], 
                                  capture_output=True, text=True, check=True)
            self._parse_netsh(result.stdout)
        except Exception as e:
            print(f"[!] Netsh scan failed: {e}")
    
    def _parse_iw_scan(self, output):
        """Parse iw scan output"""
        blocks = output.split('BSS ')
        
        for block in blocks[1:]:
            bssid = re.search(r'([0-9a-f:]{17})', block)
            ssid = re.search(r'SSID:\s*(.+)', block)
            signal = re.search(r'signal:\s*(-\d+\.\d+)', block)
            freq = re.search(r'freq:\s*(\d+)', block)
            
            if not ssid:
                continue
            
            ssid = ssid.group(1).strip()
            bssid = bssid.group(1) if bssid else "Unknown"
            
            sig = int(float(signal.group(1))) if signal else -100
            
            ch = 0
            if freq:
                f = int(freq.group(1))
                ch = (f - 2407) // 5 if f < 5000 else (f - 5000) // 5
            
            sec = self._detect_security(block)
            risk = self._risk_level(sec)
            
            self.networks.append({
                'ssid': ssid, 'bssid': bssid, 'channel': ch,
                'signal': sig, 'security': sec, 'risk': risk
            })
    
    def _parse_iwlist(self, output):
        """Parse iwlist output"""
        cells = output.split('Cell ')
        
        for cell in cells[1:]:
            ssid = re.search(r'ESSID:"([^"]*)"', cell)
            if not ssid:
                continue
            
            bssid = re.search(r'Address:\s*([0-9A-F:]{17})', cell, re.I)
            channel = re.search(r'Channel:(\d+)', cell)
            signal = re.search(r'Signal level[=:](-\d+)', cell)
            
            ssid = ssid.group(1)
            bssid = bssid.group(1) if bssid else "Unknown"
            ch = int(channel.group(1)) if channel else 0
            sig = int(signal.group(1)) if signal else -100
            
            sec = self._detect_security(cell)
            risk = self._risk_level(sec)
            
            self.networks.append({
                'ssid': ssid, 'bssid': bssid, 'channel': ch,
                'signal': sig, 'security': sec, 'risk': risk
            })
    
    def _parse_airport(self, output):
        """Parse macOS airport output"""
        lines = output.strip().split('\n')[1:]
        
        for line in lines:
            parts = line.split()
            if len(parts) < 7:
                continue
            
            ssid = parts[0]
            bssid = parts[1]
            signal = int(parts[2])
            channel = int(parts[3])
            sec_str = ' '.join(parts[6:])
            
            sec = self._detect_security(sec_str)
            risk = self._risk_level(sec)
            
            self.networks.append({
                'ssid': ssid, 'bssid': bssid, 'channel': channel,
                'signal': signal, 'security': sec, 'risk': risk
            })
    
    def _parse_netsh(self, output):
        """Parse Windows netsh output"""
        sections = re.split(r'\nSSID \d+', output)
        
        for section in sections[1:]:
            ssid = re.search(r':\s*(.+)', section)
            if not ssid:
                continue
            
            auth = re.search(r'Authentication\s*:\s*(.+)', section)
            bssid = re.search(r'BSSID\s+\d+\s*:\s*([0-9a-f:]+)', section, re.I)
            signal = re.search(r'Signal\s*:\s*(\d+)%', section)
            
            ssid = ssid.group(1).strip()
            auth = auth.group(1).strip() if auth else "Unknown"
            bssid = bssid.group(1).upper() if bssid else "Unknown"
            
            sig_pct = int(signal.group(1)) if signal else 0
            sig = -100 + (sig_pct // 2)
            
            sec = self._detect_security(auth)
            risk = self._risk_level(sec)
            
            self.networks.append({
                'ssid': ssid, 'bssid': bssid, 'channel': 0,
                'signal': sig, 'security': sec, 'risk': risk
            })
    
    def _detect_security(self, text):
        """Detect security type from text"""
        text = text.upper()
        if 'WPA3' in text:
            return 'WPA3'
        elif 'WPA2' in text:
            return 'WPA2'
        elif 'WPA' in text:
            return 'WPA'
        elif 'WEP' in text:
            return 'WEP'
        elif 'OPN' in text or 'OPEN' in text:
            return 'OPEN'
        return 'Unknown'
    
    def _risk_level(self, security):
        """Calculate risk level"""
        risks = {
            'OPEN': 'CRITICAL',
            'WEP': 'HIGH',
            'WPA': 'MEDIUM',
            'WPA2': 'LOW',
            'WPA3': 'MINIMAL',
            'Unknown': 'UNKNOWN'
        }
        return risks.get(security, 'UNKNOWN')
    
    def display(self):
        """Display results in table"""
        if not self.networks:
            print("[!] No networks found")
            return
        
        # Sort by signal strength
        sorted_nets = sorted(self.networks, key=lambda x: x['signal'], reverse=True)
        
        # Print header
        print("\n" + "="*85)
        print(f"{'SSID':<25} {'BSSID':<18} {'CH':<4} {'Signal':<8} {'Security':<8} {'Risk':<10}")
        print("-"*85)
        
        # Print rows
        for n in sorted_nets:
            # Color coding for risk
            risk = n['risk']
            if risk == 'CRITICAL':
                risk_str = f"[!] {risk}"
            elif risk == 'HIGH':
                risk_str = f"[*] {risk}"
            else:
                risk_str = f"[+] {risk}"
            
            print(f"{n['ssid']:<25} {n['bssid']:<18} {n['channel']:<4} "
                  f"{n['signal']:<8} {n['security']:<8} {risk_str:<10}")
        
        print("="*85)
        print(f"\n[*] Total networks found: {len(self.networks)}")
    
    def save_report(self, filename="wifi_report.json"):
        """Save JSON report"""
        if not self.networks:
            print("[!] Nothing to save")
            return
        
        report = {
            'scan_time': datetime.now().isoformat(),
            'platform': self.system,
            'total_networks': len(self.networks),
            'summary': {
                'critical': len([n for n in self.networks if n['risk'] == 'CRITICAL']),
                'high': len([n for n in self.networks if n['risk'] == 'HIGH']),
                'medium': len([n for n in self.networks if n['risk'] == 'MEDIUM']),
                'low': len([n for n in self.networks if n['risk'] == 'LOW']),
                'minimal': len([n for n in self.networks if n['risk'] == 'MINIMAL'])
            },
            'networks': self.networks
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved: {Path(filename).absolute()}")
        return filename


def main():
    """Main function"""
    # Banner
    print("\n" + "="*50)
    print("    🔒 WiFi Security Analyzer")
    print("    All-in-One Version")
    print("="*50)
    
    # Create scanner and run
    scanner = WiFiScanner()
    scanner.scan()
    scanner.display()
    
    # Save report if networks found
    if scanner.networks:
        scanner.save_report()
        
        # Security warnings
        critical = len([n for n in scanner.networks if n['risk'] == 'CRITICAL'])
        high = len([n for n in scanner.networks if n['risk'] == 'HIGH'])
        
        print()
        if critical > 0:
            print(f"[!] WARNING: Found {critical} OPEN (unencrypted) networks!")
            print("    These networks expose all your data.")
        
        if high > 0:
            print(f"[!] WARNING: Found {high} WEP networks!")
            print("    WEP can be cracked in minutes.")
        
        safe = len([n for n in scanner.networks if n['risk'] in ['LOW', 'MINIMAL']])
        if safe > 0:
            print(f"[+] {safe} networks use secure encryption (WPA2/WPA3)")
    
    print("\n" + "="*50)
    print("    Scan complete!")
    print("="*50 + "\n")


if __name__ == "__main__":
    main()
