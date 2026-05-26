from flask import Flask, request, jsonify
import requests
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load the .env file explicitly
load_dotenv(os.path.expanduser("~/telemetry-aggregator/.env"))

# TUI Components from Rich
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

app = Flask(__name__)
console = Console()

# Configuration
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY")
LOG_FILE = os.path.expanduser("~/telemetry-aggregator/enriched_alerts.json")

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def enrich_ip(ip):
    if not is_public_ip(ip):
        return {
            "location": "Internal Subnet",
            "isp": "Local Network Asset",
            "abuse_score": 0,
            "total_reports": 0,
            "risk_tier": "INFO"
        }

    enrichment = {
        "location": "Unknown",
        "isp": "Unknown",
        "abuse_score": 0,
        "total_reports": 0,
        "risk_tier": "LOW"
    }

    # 1. Geolocation via IP-API (Free, no key required)
    try:
        geo_res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if geo_res.get("status") == "success":
            enrichment["location"] = f"{geo_res.get('city')}, {geo_res.get('country')}"
            enrichment["isp"] = geo_res.get("isp")
    except Exception:
        pass

    # 2. Reputation Tracking via AbuseIPDB
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        abuse_res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=3).json()
        
        score = abuse_res["data"]["abuseConfidenceScore"]
        enrichment["abuse_score"] = score
        enrichment["total_reports"] = abuse_res["data"]["totalReports"]
        
        if score > 25:
            enrichment["risk_tier"] = "HIGH_RISK"
        elif score > 0:
            enrichment["risk_tier"] = "MEDIUM"
    except Exception:
        pass

    return enrichment

@app.route('/alert', methods=['POST'])
def webhook():
    payload = request.json or {}
    
    # Catch test pings from the Canarytokens UI
    if "src_ip" not in payload:
        return "success", 200

    # --- BULLETPROOF IP EXTRACTION ---
    # Dump the raw payload to a string and regex scan for any embedded public IP, 
    # completely bypassing dictionary case-sensitivity.
    dump = json.dumps(payload)
    public_ip = None
    
    # Grab all IPv4 formats from the JSON string
    potential_ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', dump)
    
    # Loop through them. The first one that passes the is_public_ip() check is the attacker.
    for ip in potential_ips:
        if is_public_ip(ip):
            public_ip = ip
            break
            
    src_ip = public_ip if public_ip else payload.get("src_ip", "127.0.0.1")
    # ---------------------------------
    
    memo = payload.get("memo", "Unknown Token")
    user_agent = payload.get("user_agent", "Unknown Agent")
    
    # Process Enrichment
    intel = enrich_ip(src_ip)
    
    # 1. Write Clean JSON Record for SIEM Engine Integration
    alert_record = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "token_name": memo,
        "attacker_ip": src_ip,
        "user_agent": user_agent,
        "enrichment": intel
    }
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(alert_record) + "\n")
    except Exception:
        pass

    # 2. Dynamic Component Coloring based on Risk Classification
    if intel["risk_tier"] == "HIGH_RISK":
        header_style = "bold red blink"
        panel_border = "red"
        score_color = "bold red"
    elif intel["risk_tier"] == "MEDIUM":
        header_style = "bold yellow"
        panel_border = "yellow"
        score_color = "bold yellow"
    else:
        header_style = "bold cyan"
        panel_border = "blue"
        score_color = "green"

    # Panel Component A: Incident Metadata
    metadata_text = Text()
    metadata_text.append("🎯 Target Rule : ", style="bold white")
    metadata_text.append(f"{memo}\n", style="cyan")
    metadata_text.append("⏱️ Timestamp   : ", style="bold white")
    metadata_text.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="gray")
    metadata_text.append("🌐 User Agent : ", style="bold white")
    metadata_text.append(f"{user_agent[:60]}...", style="italic gray")
    
    panel_meta = Panel(metadata_text, title="[bold white]Incident Metadata[/bold white]", border_style=panel_border)

    # Panel Component B: Threat Intelligence
    intel_text = Text()
    intel_text.append("📍 Location      : ", style="bold white")
    intel_text.append(f"{intel['location']}\n", style="magenta")
    intel_text.append("🏢 ISP/Provider  : ", style="bold white")
    intel_text.append(f"{intel['isp']}\n", style="magenta")
    intel_text.append("⚠️ Abuse Score  : ", style="bold white")
    intel_text.append(f"{intel['abuse_score']}% ", style=score_color)
    intel_text.append(f"({intel['total_reports']} global reports)", style="gray")
    
    panel_intel = Panel(intel_text, title="[bold white]Threat Intelligence[/bold white]", border_style=panel_border)

    # Output Layout Execution
    console.print("\n")
    header_text = Text(f"🚨 INTRUSION THREAT DETECTED — RISK LEVEL: {intel['risk_tier']} 🚨", justify="center")
    console.print(Panel(header_text, style=header_style))
    console.print(Columns([panel_meta, panel_intel], expand=True))
    console.print(f"[dim]Audit Entry Written ──> {LOG_FILE}[/dim]")
    
    return jsonify({"status": "processed"}), 200

if __name__ == '__main__':
    os.system('clear')
    console.print(Panel.fit(
        "[bold green]SIEM TELEMETRY AGGREGATOR ENGINE ACTIVE[/bold green]\n"
        "[dim]Listening for inbound deception webhooks on port 5000...[/dim]",
        border_style="green", title="⚡ Live Deployment"
    ))
    app.run(host='0.0.0.0', port=5000)
