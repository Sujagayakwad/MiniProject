import sys
import os
import time

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core import (
    scan_wifi_networks,
    analyze_scan_results,
    audit_current_connection,
    audit_saved_profiles,
    analyze_password_security
)

try:
    # pyrefly: ignore [missing-import]
    from rich.console import Console
    # pyrefly: ignore [missing-import]
    from rich.table import Table
    # pyrefly: ignore [missing-import]
    from rich.panel import Panel
    # pyrefly: ignore [missing-import]
    from rich.progress import Progress, SpinnerColumn, TextColumn
    # pyrefly: ignore [missing-import]
    from rich.text import Text  
    HAS_RICH = True 
except ImportError:     
    HAS_RICH = False

def print_banner():
    banner = """
[+] ================================================================ [+]
      CYBER-SHIELD WI-FI SECURITY ANALYSER & AUDITOR (Windows)
        Deep Spectrum Audit * Vulnerability Radar * Defense
[+] ================================================================ [+]
"""
    if HAS_RICH:
        console = Console()
        console.print(Panel(banner.strip(), style="bold cyan", border_style="cyan"))
    else:
        print(banner)


def run_cli_audit():
    console = Console() if HAS_RICH else None
    print_banner()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Scanning Wi-Fi Spectrum and analyzing cryptographic suites..."),
            transient=True
        ) as progress:
            progress.add_task("scan", total=None)
            time.sleep(1.2)
            scan_data = scan_wifi_networks()
            analysis = analyze_scan_results(scan_data)
            conn = audit_current_connection()
            profiles = audit_saved_profiles()
    else:
        print("[*] Scanning Wi-Fi Spectrum...")
        scan_data = scan_wifi_networks()
        analysis = analyze_scan_results(scan_data)
        conn = audit_current_connection()
        profiles = audit_saved_profiles()

    # Active Connection Panel
    if conn.get("connected"):
        w = conn["wifi"]
        sec = conn["security"]
        conn_text = f"""
[bold green]● Connected Network:[/bold green] [bold white]{w.get('ssid')}[/bold white]
[bold cyan]BSSID:[/bold cyan] {w.get('bssid')} ({w.get('vendor')})
[bold cyan]Security:[/bold cyan] {w.get('authentication')} ({w.get('cipher')}) | [bold cyan]Signal:[/bold cyan] {w.get('signal_percent')}% | [bold cyan]Channel:[/bold cyan] {w.get('channel')}
[bold cyan]Local IP:[/bold cyan] {conn.get('adapter', {}).get('ip_address', 'N/A')} | [bold cyan]Gateway:[/bold cyan] {conn.get('adapter', {}).get('default_gateway', 'N/A')} ({conn.get('gateway', {}).get('latency_ms', '?')} ms)
[bold cyan]Security Score:[/bold cyan] [{ 'bold green' if sec['score']>=80 else 'bold yellow' }]{sec['score']}/100 (Grade {sec['grade']})[/]
        """
        if HAS_RICH:
            console.print(Panel(conn_text.strip(), title="📡 Active Interface Status", border_style="green"))
        else:
            print("\n--- Active Interface Status ---\n" + conn_text)
    else:
        if HAS_RICH:
            console.print(Panel("[yellow]Wi-Fi Interface is currently disconnected or inactive.[/yellow]", title="Active Interface", border_style="yellow"))
        else:
            print("[!] Wi-Fi interface is disconnected.")

    # Airspace Overview Table
    if HAS_RICH:
        table = Table(title="🔍 Discovered Access Points & Security Posture", header_style="bold magenta", border_style="dim")
        table.add_column("SSID", style="bold white", width=22)
        table.add_column("BSSID / MAC", style="dim cyan", width=18)
        table.add_column("Band / Ch", justify="center", width=12)
        table.add_column("Signal", justify="center", width=10)
        table.add_column("Auth & Cipher", width=22)
        table.add_column("Risk / Grade", justify="center", width=14)
        table.add_column("Hardware Vendor", style="dim", width=20)

        for net in analysis.get("networks", []):
            ssid = net.get("ssid", "[Hidden]")
            sec = net.get("security", {})
            grade = sec.get("grade", "?")
            risk = sec.get("risk_level", "LOW")

            grade_color = "bold green" if grade in ("A+", "A") else "bold yellow" if grade == "B" else "bold red"

            for b in net.get("bssids", []):
                sig = b.get("signal_percent", 0)
                sig_color = "green" if sig >= 70 else "yellow" if sig >= 40 else "red"
                sig_str = f"[{sig_color}]{sig}% ({b.get('signal_dbm')} dBm)[/]"

                table.add_row(
                    ssid,
                    b.get("bssid", "N/A"),
                    f"{b.get('band')} / #{b.get('channel')}",
                    sig_str,
                    f"{net.get('authentication')} ({net.get('encryption')})",
                    f"[{grade_color}]{grade} - {risk}[/]",
                    b.get("vendor", "Unknown")
                )

        console.print(table)
    else:
        print("\n--- Discovered Networks ---")
        for net in analysis.get("networks", []):
            print(f"- SSID: {net.get('ssid')} | Auth: {net.get('authentication')} | Grade: {net.get('security', {}).get('grade')}")

    # Rogue AP alerts
    if analysis.get("rogue_alerts"):
        for alert in analysis["rogue_alerts"]:
            if HAS_RICH:
                console.print(Panel(f"[bold red]⚠️ {alert['title']}[/bold red]\n{alert['description']}\n[yellow]Action: {alert['recommendation']}[/yellow]", border_style="red"))
            else:
                print(f"[ALERT] {alert['title']}: {alert['description']}")

    # Saved profiles audit summary
    if HAS_RICH:
        prof_table = Table(title="💾 Saved Wi-Fi Profiles Security Audit", header_style="bold cyan", border_style="dim")
        prof_table.add_column("Profile Name", style="bold white")
        prof_table.add_column("Auto-Connect", justify="center")
        prof_table.add_column("Authentication", width=16)
        prof_table.add_column("MAC Privacy", justify="center")
        prof_table.add_column("Security Risk", justify="center")

        for p in profiles:
            risk_style = "bold green" if p["security_risk"] == "LOW" else "bold red" if p["security_risk"] == "CRITICAL" else "bold yellow"
            auto_style = "bold red" if (p["auto_connect"] and "OPEN" in p["authentication"].upper()) else "cyan"

            prof_table.add_row(
                p["name"],
                f"[{auto_style}]{'Enabled' if p['auto_connect'] else 'Disabled'}[/]",
                p["authentication"],
                p["mac_randomization"],
                f"[{risk_style}]{p['security_risk']}[/]"
            )
        console.print(prof_table)

    print("\n✅ Audit complete. For the interactive Web GUI, run: python app.py\n")

if __name__ == "__main__":
    run_cli_audit()
