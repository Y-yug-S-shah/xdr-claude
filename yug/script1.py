import os
import re
import math
import json
import sqlite3
import requests
from datetime import datetime, timedelta
from collections import Counter

CORTEX_API_URL = os.getenv("CORTEX_API_URL", "https://api.cortex.example.com")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY")
CORTEX_API_KEY_ID = os.getenv("CORTEX_API_KEY_ID")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

DB_FILE = "triage_cache.db"

IOC_REGEXS = {
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "URL": re.compile(r"\bhttps?://[^\s\"'<>\)\]]+"),
    "Domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "IPv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "IPv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ioc_cache (
            ioc_hash TEXT PRIMARY KEY,
            ioc_value TEXT,
            ioc_type TEXT,
            reputation TEXT,
            raw_metadata TEXT,
            updated_at TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback_store (
            ioc_value TEXT PRIMARY KEY,
            ioc_type TEXT,
            alert_id TEXT,
            feature_vector TEXT,
            analyst_verdict TEXT,
            verdict_timestamp TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def calculate_shannon_entropy(text):
    if not text:
        return 0.0
    text_len = len(text)
    probs = [count / text_len for count in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)

def extract_iocs(alert_payload):
    extracted = []
    text_to_search = json.dumps(alert_payload)
    
    for ioc_type in ["SHA256", "SHA1", "MD5", "URL", "Domain", "IPv4", "IPv6", "Email"]:
        matches = IOC_REGEXS[ioc_type].findall(text_to_search)
        for match in matches:
            if ioc_type == "IPv4":
                if any(int(octet) > 255 for octet in match.split('.')):
                    continue
            
            if ioc_type == "Domain" and any(match in item["value"] for item in extracted if item["type"] == "URL"):
                continue
                
            if not any(item["value"] == match for item in extracted):
                extracted.append({"value": match, "type": ioc_type})
    return extracted

def get_cached_ioc(ioc_value):
    import hashlib
    ioc_hash = hashlib.sha256(ioc_value.encode()).hexdigest() if len(ioc_value) > 64 else ioc_value
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT reputation, raw_metadata, updated_at FROM ioc_cache WHERE ioc_hash = ?", (ioc_hash,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        reputation, raw_metadata, updated_at = row
        updated_dt = datetime.strptime(updated_at, "%Y-%m-%d %H:%M:%S")
        ttl_hours = 168 if reputation == "malicious" else (24 if reputation == "clean" else 1)
        if datetime.now() - updated_dt < timedelta(hours=ttl_hours):
            return json.loads(raw_metadata)
    return None

def write_cached_ioc(ioc_value, ioc_type, reputation, raw_metadata):
    import hashlib
    ioc_hash = hashlib.sha256(ioc_value.encode()).hexdigest() if len(ioc_value) > 64 else ioc_value
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO ioc_cache (ioc_hash, ioc_value, ioc_type, reputation, raw_metadata, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ioc_hash, ioc_value, ioc_type, reputation, json.dumps(raw_metadata), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def enrich_ioc(ioc):
    val = ioc["value"]
    itype = ioc["type"]
    
    cached = get_cached_ioc(val)
    if cached:
        return cached

    enrichment = {"virus_total": None, "abuse_ipdb": None, "url_haus": None}
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        if itype in ["SHA256", "MD5", "SHA1"] and VT_API_KEY:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{val}", headers=headers, timeout=5)
            if r.status_code == 200: enrichment["virus_total"] = r.json()
        elif itype == "IPv4" and ABUSEIPDB_API_KEY:
            r = requests.get(f"https://api.abuseipdb.com/api/v2/check", headers={"Key": ABUSEIPDB_API_KEY}, params={"ipAddress": val}, timeout=5)
            if r.status_code == 200: enrichment["abuse_ipdb"] = r.json()
    except Exception:
        pass 

    verdict = "unknown"
    if enrichment["virus_total"]:
        malicious_stats = enrichment["virus_total"].get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        verdict = "malicious" if malicious_stats >= 2 else "clean"
    elif enrichment["abuse_ipdb"]:
        score = enrichment["abuse_ipdb"].get("data", {}).get("abuseConfidenceScore", 0)
        verdict = "malicious" if score >= 75 else "clean"

    write_cached_ioc(val, itype, verdict, enrichment)
    return enrichment

def fetch_cortex_alerts():
    if not (CORTEX_API_URL and CORTEX_API_KEY):
        return [{
            "alert_id": "11425",
            "severity": "high",
            "alert_name": "Suspicious execution via script component host",
            "actor_process_command_line": "powershell.exe -enc ZWNobyAnSGVsbG8gV29ybGQn",
            "causality_actor_process_command_line": "winword.exe /q",
            "alert_action": "DETECTED",
            "host_name": "PROD-ENDPOINT-04"
        }]

    headers = {"Authorization": CORTEX_API_KEY, "x-xdr-auth-id": CORTEX_API_KEY_ID, "Content-Type": "application/json"}
    payload = {"request_data": {"filters": [{"field": "severity", "operator": "in", "value": ["high", "critical"]}]}}
    res = requests.post(f"{CORTEX_API_URL}/public_api/v1/alerts/get_alerts/", headers=headers, json=payload, timeout=10)
    return res.json().get("reply", {}).get("alerts", []) if res.status_code == 200 else []

def triage_with_claude(alert_ctx, enriched_iocs, system_prompt):
    if not ANTHROPIC_API_KEY:
        return {"error": "Anthropic API credentials unconfigured."}

    payload_package = {
        "alert_telemetry": alert_ctx,
        "enriched_iocs": enriched_iocs,
        "derived_metrics": {
            "cmd_entropy": calculate_shannon_entropy(alert_ctx.get("actor_process_command_line", ""))
        }
    }

    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    
    body = {
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 4000,
        "system": system_prompt,
        "messages": [{"role": "user", "content": json.dumps(payload_package)}]
    }

    res = requests.post("https://api.anthropic.com/v1/messages", headers=headers, json=body, timeout=30)
    if res.status_code == 200:
        raw_text = res.json()["content"][0]["text"]
        return json.loads(raw_text)
    else:
        raise RuntimeError(f"Claude API request failed: {res.status_code} - {res.text}")

def save_verdict_to_feedback_store(alert_id, cl_verdict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for ioc in cl_verdict.get("iocs", []):
        cursor.execute("""
            INSERT OR REPLACE INTO feedback_store (ioc_value, ioc_type, alert_id, feature_vector, analyst_verdict, verdict_timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ioc.get("value"), 
            ioc.get("type"), 
            alert_id, 
            json.dumps(cl_verdict), 
            "PENDING_REVIEW" if cl_verdict.get("classification") == "Mid-confidence" else cl_verdict.get("classification"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
    conn.commit()
    conn.close()

def main():
    init_db()
    
    if not os.path.exists("skillss.md"):
        print("Error: Missing execution system matrix file 'skillss.md'")
        return
        
    with open("skillss.md", "r") as f:
        system_prompt = f.read()

    print("[*] Retrieving telemetry instances from Cortex XDR...")
    alerts = fetch_cortex_alerts()
    
    for alert in alerts:
        print(f"[*] Analyzing alert entry: {alert.get('alert_id')}")
        extracted_iocs = extract_iocs(alert)
        
        enriched_dataset = []
        for ioc in extracted_iocs:
            enrichment_data = enrich_ioc(ioc)
            enriched_dataset.append({"ioc": ioc, "enrichment": enrichment_data})
            
        try:
            verdict = triage_with_claude(alert, enriched_dataset, system_prompt)
            print(f"[+] Verdict Resolved for ID {alert.get('alert_id')}: {verdict.get('classification')} (Score: {verdict.get('confidence_score')})")
            save_verdict_to_feedback_store(alert.get("alert_id"), verdict)
        except Exception as e:
            print(f"[-] Execution compilation failed on alert {alert.get('alert_id')}: {e}")

if __name__ == "__main__":
    main()
  
