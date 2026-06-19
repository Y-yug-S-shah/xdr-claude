# Cortex XDR Alert Triage Skill (Zero-Cost, High-Precision)

## Objective
Ingest Cortex XDR alerts → extract IOCs → enrich via free intel sources → score → classify TP/FP with calibrated confidence. Cost target: $0 (free-tier APIs + local caching only).

## Pipeline
```
Cortex XDR API (paginated, watermarked)
  -> Normalize -> Dedup against IOC cache -> Allowlist short-circuit
  -> Tiered Enrichment (cache -> free API -> causality analysis)
  -> Weighted Scoring Engine -> Classification + Confidence
  -> Feedback Store (analyst overrides feed back into allowlist/denylist)
```

## 1. Ingestion
Pull via `GET /public_api/v1/alerts/get_alerts/` using `search_to`/`search_from` pagination and a stored watermark (`last_detection_timestamp`) so each run only fetches new alerts.

Map these Cortex XDR fields exactly (do not invent field names):
`alert_id, detection_timestamp, severity, alert_name, alert_category, alert_action, alert_action_status, host_ip, host_name, source_ip, source_port, destination_ip, destination_port, action_file_name, action_file_path, action_file_sha256, action_file_md5, actor_process_image_name, actor_process_image_path, actor_process_image_sha256, actor_process_command_line, causality_actor_process_image_name, causality_actor_process_command_line, os_actor_process_image_name, user_name, domain, mitre_tactic_id_and_name, mitre_technique_id_and_name`

## 2. Deduplication & Allowlist Short-Circuit (efficiency-critical)
Before any API call:
1. Hash every extracted IOC (sha256 of normalized value) and check the local IOC cache. Skip enrichment entirely on cache hit within TTL.
2. Check against a maintained allowlist: RFC1918/loopback ranges, corporate egress IPs, known CDN/cloud ASNs (Microsoft, Google, AWS, Cloudflare, Akamai), sanctioned internal domains. Allowlist hits are scored `-50` and skip external API calls.
3. Build a single deduplicated IOC set per batch run — enrich each unique IOC once, then fan results back out to every alert referencing it. This is the single biggest cost/speed lever; never enrich the same IOC twice in a run.

Cache TTL by last-known reputation: malicious = 7 days, clean = 24 hours, unknown/error = 1 hour.

## 3. IOC Extraction — exact patterns
```regex
IPv4    \b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b
IPv6    \b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b
Domain  \b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b
URL     \bhttps?://[^\s"'<>\)\]]+
MD5     \b[a-fA-F0-9]{32}\b
SHA1    \b[a-fA-F0-9]{40}\b
SHA256  \b[a-fA-F0-9]{64}\b
Email   \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b
```
Apply in this order: hashes first (longest/most specific), then URLs, then domains extracted from leftover URLs/emails, then bare IPs. Discard any domain match that is a substring of an already-matched URL/email to avoid double-counting. Validate IPv4 octets ≤255; validate hash length exactly matches type before tagging.

## 4. Tiered Enrichment (free sources only)
Run tiers in order; stop early once consensus is reached (saves quota).

**Tier 1 — Reputation (always run, cached aggressively)**
- VirusTotal v3 (`/ip_addresses/{ip}`, `/domains/{domain}`, `/files/{hash}`) — free tier, throttle to 4 req/min via token-bucket queue.
- AbuseIPDB `/api/v2/check` — free tier, 1000/day.
- URLhaus `/v1/host/` and `/v1/payload/` — no auth, no rate limit concerns.

**Tier 2 — Context (run only if Tier 1 is ambiguous, i.e. score lands 20–69)**
- WHOIS (local `whois` binary, free) — flag domains registered <30 days ago.
- MaxMind GeoLite2-City (local DB, free) — flag geolocation mismatched with org's expected regions.
- AlienVault OTX `/api/v1/indicators/{type}/{indicator}/general` — pulse/campaign correlation.

**Tier 3 — Causality (Cortex-native, no external call, run on every alert regardless of IOC score)**
Analyze `causality_actor_process_image_name` / `causality_actor_process_command_line` chain for:
- Known LOLBins (powershell.exe, mshta.exe, rundll32.exe, certutil.exe, wmic.exe) spawning network or encoded commands.
- Office/browser process spawning a shell or script interpreter.
- Process image path mismatched with its claimed name (masquerading), or unsigned binary in a system directory.

Consensus rule: a single source flagging malicious is *not* sufficient for TP ≥70. Require agreement from ≥2 independent Tier-1/Tier-2 sources, or one Tier-1 hit corroborated by a Tier-3 causality red flag.

## 5. Weighted Scoring Engine
Start at 0. Sum applicable points (cap at 100, floor at 0).

| Signal | Points |
|---|---|
| VT ≥5 engines flag malicious | +40 |
| VT 2–4 engines flag malicious | +25 |
| VT 0 engines flag malicious (all clean) | −40 |
| AbuseIPDB score ≥75 | +30 |
| AbuseIPDB score 25–74 | +15 |
| URLhaus/active-feed match | +35 |
| Domain age <30 days (WHOIS) | +20 |
| Domain age >2 years, established/reputable | −25 |
| LOLBin/masquerading in causality chain | +15 |
| Process signed by verified trusted publisher | −35 |
| IOC on org allowlist / CDN-ASN | −50 (auto-FP, see override) |
| IOC on org denylist (prior confirmed TP) | +50 (auto-TP, see override) |
| Cortex native severity = critical/high | +10 |
| High-risk MITRE tactic combo (Initial Access + Privilege Escalation, or Defense Evasion + C2) present | +20 |
| Source corroboration <2 independent hits | −15 (uncorroborated single-source penalty) |

**Overrides** (bypass scoring, apply immediately): org allowlist match → FP; org denylist match → TP. These come from the feedback store (Section 7) and take precedence over computed score.

## 6. Classification Decision Matrix
| Score | Classification | Action |
|---|---|---|
| ≥70 | True Positive | Block / escalate to analyst immediately |
| 40–69 | Likely TP | Investigate, do not auto-close |
| 20–39 | Likely FP | Low-priority review queue |
| <20 | False Positive | Auto-close, eligible for allowlist candidacy |

Flag as `UNKNOWN` (separate from the matrix) if enrichment failed on >50% of an alert's IOCs (API timeout/error) — route to manual review rather than force a score.

## 7. Feedback Loop (drives accuracy up over time, cost stays $0)
Maintain a local SQLite store: `ioc_value, ioc_type, analyst_verdict, verdict_timestamp, alert_id`. On every analyst-confirmed verdict:
- Confirmed FP → add to org allowlist (auto-FP override on future sightings).
- Confirmed TP → add to org denylist (auto-TP override on future sightings).
- Re-score any open alerts sharing that IOC immediately.
This closes the loop so repeat noisy IOCs stop consuming API quota and stop requiring re-analysis.

## 8. Output Schema
```json
{
  "alert_id": "",
  "cortex_severity": "",
  "classification": "TP|Likely TP|Likely FP|FP|UNKNOWN",
  "confidence_score": 0-100,
  "iocs": [
    {"value": "", "type": "", "reputation": "malicious|suspicious|clean|unknown",
     "sources_hit": [], "points_contributed": 0}
  ],
  "causality_flags": [],
  "override_applied": "allowlist|denylist|none",
  "recommended_action": "block|investigate|review|auto-close",
  "processed_at": ""
}
```

## 9. Performance & Cost Targets
- Throughput: ≥100 alerts/hour on a single low-spec VM/container.
- Cache hit rate: ≥80% after first week of steady-state operation.
- API cost: $0 — free tiers only, enforced by token-bucket rate limiting per source.
- Target accuracy: ≥90% agreement with analyst verdicts, measured weekly from the feedback store; if below target, re-tune the points table (Section 5) rather than adding paid sources.

## 10. Implementation Notes
- Concurrency: one async worker pool per API source, each with its own token-bucket limiter matching that source's free-tier rate.
- Never call an external API for an IOC already resolved in this run (Section 2) or within cache TTL.
- Log classification + score breakdown for every alert (not just final verdict) to make scoring tunable and auditable.
- Don't log raw IOC values alongside identifying org data beyond what's needed for the feedback store; restrict store access.
