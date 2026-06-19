# Cortex XDR Alert Processing & IOC Enrichment Skill

## Overview
Process Cortex XDR security alerts, extract Indicators of Compromise (IOCs), enrich them with threat intelligence, and classify as true positive (TP) or false positive (FP) at minimal or zero cost.

## Scope
- Ingest raw Cortex XDR alerts (JSON/API format)
- Parse and normalize alert data
- Extract IOCs (IPs, domains, file hashes, URLs, email addresses, process signatures)
- Perform enrichment using free threat intelligence sources
- Apply heuristic analysis for TP/FP classification
- Generate summary report with confidence scores

## Cost Optimization Strategy
- Use exclusively free/open-source tools and APIs
- Leverage VirusTotal Community API (5 queries/minute, free tier)
- Use free OSINT databases: AbuseIPDB (free tier), URLhaus, PhishTank
- Implement local caching to avoid duplicate API calls
- Use public DNS and WHOIS data (free)
- Deploy on personal infrastructure or free tier cloud services

## Workflow

### 1. Alert Ingestion
**Input Sources:**
- Cortex XDR API (requires valid credentials and endpoint)
- Direct JSON file uploads
- CSV/structured alert exports

**Supported Alert Fields:**
- alert_id, severity, alert_type, timestamp
- source_ip, destination_ip, domain, file_hash
- process_name, command_line, registry_keys
- user_account, hostname, parent_process
- alert_description, mitre_techniques

### 2. IOC Extraction
**Extract and normalize:**
- IPv4/IPv6 addresses (validate format)
- Domains (extract from URLs, email addresses)
- File hashes (MD5, SHA1, SHA256, normalize)
- URLs (extract from alert descriptions/indicators)
- Email addresses (extract, validate)
- Process signatures (extract from execution paths)
- Registry keys (extract from Windows alerts)

**Validation:** Confirm each IOC matches expected format; discard malformed entries.

### 3. Enrichment (Free APIs)
**IP Reputation:**
- VirusTotal: `https://www.virustotal.com/api/v3/ip_addresses/{ip}` (free tier)
- AbuseIPDB: `https://api.abuseipdb.com/api/v2/check` (free: 1000 queries/day)
- MaxMind GeoIP: Use local GeoLite2-City database (free registration)

**Domain & URL Intelligence:**
- VirusTotal: `https://www.virustotal.com/api/v3/domains/{domain}`
- URLhaus: Query `https://urlhaus-api.abuse.ch/v1/urls/` (free, no auth)
- PhishTank: Download CSV, query locally `http://www.phishtank.com/`

**File Hash Reputation:**
- VirusTotal: `https://www.virustotal.com/api/v3/files/{hash}`
- AlienVault OTX: `https://otx.alienvault.com/api/v1/pulses/subscribed` (free API)

**DNS & Passive DNS:**
- VirusTotal: DNS resolution data included in domain queries
- Google Safe Browsing: `https://safebrowsing.googleapis.com/v4/threatMatches:find` (free API key)
- Public DNS: Use quad9.net or 1.1.1.1 for safe/malicious classification

**WHOIS & Registration Data:**
- WHOIS lookups: Use free whois command-line tool (local execution)
- DomainTools Whois API: Limited free tier

### 4. Enrichment Data Structure
For each IOC, collect:
```
{
  "ioc": "value",
  "type": "ip|domain|hash|url|email",
  "vt_score": {malicious_count}/{total_vendors},
  "vt_last_seen": "timestamp",
  "abuseipdb_score": 0-100,
  "geolocation": {country, city, asn},
  "whois_registrant": "information if available",
  "threat_feeds": ["list of feeds flagging IOC"],
  "reputation": "malicious|suspicious|clean|unknown"
}
```

### 5. True Positive / False Positive Classification

**TP Indicators (weight each):**
- High reputation score (≥3 vendors flag as malicious)
- Known malware hash (detected by multiple AV engines)
- High abuse score (AbuseIPDB ≥50)
- IOC in known threat feeds (URLhaus, PhishTank, OTX)
- IOC geolocation doesn't align with normal business operations
- Correlation with MITRE ATT&CK technique (known malicious)
- Multiple IOCs from same alert all flagged as malicious
- Uncommon process execution with high-risk signature

**FP Indicators (weight each):**
- All vendors report clean (0/X malicious)
- IOC belongs to CDN, cloud provider, or corporate network
- Geolocation aligns with expected organization location
- Process is signed by legitimate vendor
- IOC previously whitelisted in organization
- High traffic volume to IOC (indicates legitimate service)
- Known false positive signature (stored in historical FP database)

**Classification Logic:**
```
confidence_score = (TP_indicators * weights) / (TP_indicators + FP_indicators * weights)

TP_THRESHOLD = 0.70
FP_THRESHOLD = 0.30
UNKNOWN_THRESHOLD = 0.30-0.70
```

### 6. Output Report
**Format:** JSON/CSV with fields:
- alert_id
- severity (original)
- ioc_count (total extracted)
- enriched_ioc_count (successful enrichments)
- classification (TP|FP|UNKNOWN)
- confidence_score (0.0-1.0)
- tp_indicators (list of flags triggering TP)
- fp_indicators (list of flags triggering FP)
- recommended_action (block|investigate|whitelist)
- processing_timestamp

## Implementation Tips

### Code Structure
1. **Alert Parser**: Normalize Cortex XDR format → standard schema
2. **IOC Extractor**: Regex patterns for each IOC type
3. **Enrichment Engine**: Queue-based API calls with retry logic
4. **Classifier**: Scoring engine with weighted heuristics
5. **Cache Layer**: Local SQLite/JSON cache for API responses (24-48hr TTL)
6. **Report Generator**: Structured output formatter

### Rate Limiting & Cost Control
- Implement exponential backoff for API calls
- Cache all API responses (key: hash of IOC value)
- Batch VirusTotal queries where possible
- Use local geolocation database (MaxMind free) instead of API
- Prioritize enrichment by IOC severity/alert severity
- Skip enrichment for already-cached clean IOCs

### Error Handling
- Gracefully handle API timeouts (mark as UNKNOWN)
- Log failed enrichment attempts for manual review
- Implement fallback chains (VT → AbuseIPDB → local feeds)
- Alert on rate limiting; pause processing and retry

### Testing
- Test with sample Cortex XDR alerts (mock data if needed)
- Validate IOC extraction against known samples
- Cross-reference classification against manual analysis
- Measure precision/recall of TP/FP classification over time

## Free API Keys & Setup
1. **VirusTotal**: Register free account → get API key (rate limited)
2. **AbuseIPDB**: Register free account → get API key
3. **MaxMind GeoLite2**: Register free account → download city database
4. **Google Safe Browsing**: Get free API key via Google Cloud
5. **AlienVault OTX**: Register account → use free API
6. **URLhaus & PhishTank**: Download feeds directly (no key needed)

## Security Considerations
- Store API keys in environment variables or secure vault
- Don't log IOC values in logs (privacy)
- Rate-limit queries to avoid IP blocking
- Use HTTPS for all external API calls
- Implement input validation on all alert data
- Audit enrichment data for data leakage

## Maintenance
- Update threat feed databases weekly (URLhaus, PhishTank)
- Monitor free API rate limits and adjust batch sizes
- Review and refine TP/FP classification heuristics monthly
- Archive old enrichment data (30+ days) to reduce cache size
- Periodically audit false positive baseline for false positive causes

## Example Execution
```
cortex_xdr_alert.json → Parser → IOC Extractor → Enrichment Engine → Classifier → Report
Input: Raw alert        Output: Classification (TP/FP) + Confidence + Recommended Action
```

## Success Metrics
- **Speed**: Process 50+ alerts/hour on single machine
- **Cost**: $0 (free tier APIs only)
- **Accuracy**: ≥90% TP/FP classification (validate against manual review)
- **Coverage**: Enrich ≥95% of extracted IOCs successfully
