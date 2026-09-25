"""
Cyber-Shield Wi-Fi Security Analyser - Web Server & REST API Backend.
Powered by Flask, interfacing directly with Windows WLAN and network APIs.
"""
import sys
import os
import json
import time
from datetime import datetime

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# pyrefly: ignore [missing-import]
from flask import Flask, render_template, jsonify, request, Response

from core import (
    scan_wifi_networks,
    analyze_scan_results,
    audit_current_connection,
    audit_saved_profiles,
    analyze_password_security
)

app = Flask(__name__, static_folder="static", template_folder="templates")

@app.route("/")
def index():
    """Serves the main Cyber-Shield SOC dashboard."""
    return render_template("index.html")

@app.route("/api/scan", methods=["GET"])
def api_scan():
    """
    Executes an active spectrum scan of visible 802.11 networks
    and evaluates their cryptographic security postures and rogue AP indicators.
    """
    try:
        raw_scan = scan_wifi_networks()
        analysis = analyze_scan_results(raw_scan)
        analysis["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return jsonify({"success": True, "data": analysis})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/current", methods=["GET"])
def api_current():
    """
    Retrieves deep diagnostics of the currently active Wi-Fi interface,
    gateway latency, DNS server configuration, and driver security capabilities.
    """
    try:
        conn = audit_current_connection()
        return jsonify({"success": True, "data": conn})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/profiles", methods=["GET"])
def api_profiles():
    """
    Audits saved Wi-Fi profiles for auto-connect risks and privacy leaks.
    """
    try:
        profiles = audit_saved_profiles()
        return jsonify({"success": True, "data": profiles})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/check-password", methods=["POST"])
def api_check_password():
    """
    Evaluates passphrase entropy and GPU cracking resistance.
    """
    try:
        body = request.get_json(silent=True) or {}
        password = body.get("password", "")
        res = analyze_password_security(password)
        return jsonify({"success": True, "data": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/export-report", methods=["GET"])
def api_export_report():
    """
    Generates a consolidated Wi-Fi Security Audit Report in JSON format.
    """
    try:
        raw_scan = scan_wifi_networks()
        analysis = analyze_scan_results(raw_scan)
        conn = audit_current_connection()
        profiles = audit_saved_profiles()

        report = {
            "title": "Wi-Fi Security Assessment and Spectrum Audit Report",
            "generated_at": datetime.now().isoformat(),
            "target_system": "Windows 11/10 WLAN Subsystem",
            "active_connection": conn,
            "airspace_analysis": analysis,
            "saved_profiles_audit": profiles,
            "standards_compliance": {
                "wpa3_readiness": conn.get("driver", {}).get("wpa3_supported", False),
                "pmf_802_11w_supported": conn.get("driver", {}).get("pmf_supported", False),
                "fips_140_2_mode": conn.get("driver", {}).get("fips_supported", False)
            }
        }

        report_json = json.dumps(report, indent=2)
        return Response(
            report_json,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment;filename=wifi_security_audit_{int(time.time())}.json"}
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🚀 CYBER-SHIELD WI-FI SECURITY ANALYSER STARTED")
    print("  🌐 Dashboard URL: http://127.0.0.1:5050")
    print("  ⚡ Press Ctrl+C in terminal to stop server")
    print("="*60 + "\n")
    app.run(host="127.0.0.1", port=5050, debug=False)
