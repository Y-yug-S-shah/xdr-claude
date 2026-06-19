# Cortex XDR Alert Triage Skill (Zero-Cost, High-Precision)

## Objective
Ingest Cortex XDR alerts → extract IOCs → enrich via free intel sources → score → classify TP/FP with calibrated confidence. Cost target: $0 (free-tier APIs + local caching only). False negatives are costlier than false positives — bias every ambiguous decision toward investigation, not auto-close.

## Pipeline
```
Cortex XDR API (paginated, watermarked)
  -> Normalize -> Dedup against IOC cache -> Allowlist/Denylist short-circuit (with expiry check)
  -> Tiered Enrichment (cache -> reputation -> context -> causality chain -> static analysis fallback)
  -> Cross-IOC compound scoring -> Cross-alert correlation
  -> Calibrated Scoring Model -> Classification + Confidence
  -> Active-learning queue (mid-confidence) -> Feedback Store -> retrain weights
```

## 1. Ingestion
Pull via `GET /public_api/v1/alerts/get_alerts/` using `search_to`/`search_from` pagination and a stored watermark (`last_detection_timestamp`).

Map these Cortex XDR fields exactly:
`alert_id, detection_timestamp, severity, alert_name, alert_category, alert_action, alert_action_status, host_ip, host_name, source_ip, source_port, destination_ip, destination_port, action_file_name, action_file_path, action_file_sha256, action_file_md5, actor_process_image_name, actor_process_image_path, actor_process_image_sha256, actor_process_command_line, causality_actor_process_image_name, causality_actor_process_command_line, os_actor_process_image_name, user_name, domain, mitre_tactic_id_and_name, mitre_technique_id_and_name`

Treat `alert_action_status` and Cortex's own verdict/action (e.g. `BLOCKED`, `DETECTED`, `PREVENTED`) as a first-class model feature, not raw metadata — Cortex's built-in ML has already scored this alert once; don't discard that signal.

## 2. Deduplication & Allowlist/Denylist Short-Circuit
1. Hash every extracted IOC (sha256 of normalized value) and check the local IOC cache. Skip enrichment on a fresh cache hit.
2. Check the org allowlist/denylist (built from the feedback store). On hit, apply the override **only if the entry hasn't expired** — re-validate allowlist/denylist entries every 30 days against current Tier-1 reputation, since a once-benign IP can later be compromised and a once-malicious one can be cleaned up. Stale, unrevalidated overrides are a leading cause of false negatives.
3. Build one deduplicated IOC set per batch run; enrich each unique IOC once, fan results back to every alert referencing it.

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
Order: hashes first, then URLs, then domains/emails left over, then bare IPs. Discard a domain match that's a substring of an already-matched URL/email. Validate IPv4 octets ≤255 and exact hash lengths before tagging.

## 4. Tiered Enrichment
Run tiers in order; stop early once consensus is reached.

**Tier 1 — Reputation** (always run, cached aggressively)
- VirusTotal v3 (`/ip_addresses/{ip}`, `/domains/{domain}`, `/files/{hash}`) — free tier, 4 req/min token-bucket.
- AbuseIPDB `/api/v2/check` — free tier, 1000/day.
- URLhaus `/v1/host/`, `/v1/payload/` — no auth required.

**Tier 2 — Context** (run if Tier 1 is ambiguous)
- WHOIS (local binary) — domain age, registrant.
- MaxMind GeoLite2-City (local DB) — geolocation mismatch vs. org's expected regions.
- AlienVault OTX `/api/v1/indicators/{type}/{indicator}/general` — pulse/campaign correlation.

**Tier 3 — Causality Chain** (Cortex-native, no external call, run on every alert)
Walk the **full process ancestry chain**, not just the immediate parent — follow `causality_actor_process_image_name`/`command_line` back to the root process. A multi-hop chain (e.g. Office → script host → LOLBin → network call) is far more indicative than any single hop. Score:
- Known LOLBins (powershell.exe, mshta.exe, rundll32.exe, certutil.exe, wmic.exe) anywhere in the chain spawning network/encoded activity.
- Office/browser process anywhere upstream of a shell or script interpreter.
- Process image path mismatched with its claimed name, or unsigned binary in a system directory.
- **Command-line obfuscation score**: compute Shannon entropy of `actor_process_command_line`; flag high entropy (>4.0) plus presence of base64/`-enc`/`-EncodedCommand` patterns as an independent signal, separate from the LOLBin check.

**Tier 4 — Static Analysis Fallback** (only for hashes with 0 VT engine hits — i.e. too new to have reputation)
- Run local YARA rules (free, community rulesets) against the sample if available.
- Compute PE header anomalies and file entropy (packed/obfuscated binaries skew high). This catches novel malware that reputation lookups miss entirely, which is otherwise a blind spot.

## 5. Cross-IOC Compound Scoring
Score IOC *combinations* within the same alert, not just each IOC independently. A hash with 0 VT hits that calls out to an IP already flagged malicious should score materially higher than either IOC alone — independent per-IOC scoring under-weights this. Concretely: if any IOC in the alert clears the TP threshold, escalate every other IOC in that same alert by one confidence tier (no auto-FP overrides for the rest of that alert without manual review).

## 6. Cross-Alert Correlation
Before finalizing classification, query recent alerts (e.g. last 24–72h) sharing the same `host_name`, `user_name`, or IOC. Don't judge each alert in total isolation:
- Multiple low/medium alerts on the same host in a short window (an "alert storm") should collectively raise confidence even if each alert individually scores low — this is a kill-chain pattern, not noise.
- Stage progression matching MITRE tactics in sequence (Initial Access → Execution → Persistence → C2) across related alerts is a strong TP signal even if any single alert looks benign.

## 7. Calibrated Scoring Model
Don't rely on a fixed hand-picked point table long-term — it doesn't adapt and treats all sources as equally reliable.

- **Cold start** (feedback store has <~200 labeled IOCs): use the heuristic point table below to bootstrap.
- **Steady state**: train a logistic regression (or gradient-boosted trees) on the feedback store's analyst-confirmed labels, using each Tier 1–4 signal, the cross-IOC/cross-alert features, and the native Cortex verdict as input features. Retrain weekly as labels accumulate.
- **Source reliability weighting**: weight each source's contribution by its own historical precision computed from the feedback store (e.g. if AbuseIPDB hits have only correlated with confirmed TPs 60% of the time historically, down-weight it relative to a source at 90%) — don't treat all sources as equally trustworthy by default.
- **Recency decay**: weight reputation hits by how recent the last-seen timestamp is (e.g. exponential decay with ~30-day half-life). A malicious flag from 18 months ago is much weaker evidence than one from today.
- **Threshold selection**: pick classification thresholds from the ROC/precision-recall curve on held-out labeled data, not an arbitrary guess — and bias the operating point toward higher recall (catch more true positives) even at some precision cost, since missed TPs are more expensive than extra analyst review.

**Cold-start heuristic point table** (used only until enough labels exist for the learned model):

| Signal | Points |
|---|---|
| VT ≥5 engines flag malicious (decayed by recency) | +40 |
| VT 2–4 engines flag malicious (decayed by recency) | +25 |
| VT 0 engines flag malicious | −40 |
| AbuseIPDB score ≥75 | +30 |
| AbuseIPDB score 25–74 | +15 |
| URLhaus/active-feed match | +35 |
| Domain age <30 days | +20 |
| Domain age >2 years, reputable | −25 |
| LOLBin/masquerading anywhere in causality chain | +15 |
| High command-line entropy + encoding pattern | +15 |
| Static analysis (YARA hit / high packed entropy) on 0-hit hash | +25 |
| Process signed by verified trusted publisher | −35 |
| Cross-IOC escalation (another IOC in alert already TP) | +20 |
| Cross-alert storm / stage-progression match | +20 |
| Cortex native verdict = BLOCKED/PREVENTED with high internal confidence | +15 |
| IOC on org allowlist/CDN-ASN (not expired) | −50 (override) |
| IOC on org denylist (not expired) | +50 (override) |
| Source corroboration <2 independent hits | −15 |

## 8. Classification Decision Matrix
| Score | Classification | Action |
|---|---|---|
| ≥65 | True Positive | Block / escalate immediately |
| 35–64 | Mid-confidence | Route to **active-learning queue**: prioritize for analyst labeling, do not auto-close |
| <35 | Likely FP | Low-priority review queue (not auto-close unless allowlist-confirmed) |

Thresholds are intentionally asymmetric and recall-biased — when in doubt, classify up, not down. `UNKNOWN` overrides the matrix if enrichment failed on >50% of an alert's IOCs; route to manual review.

## 9. Active Learning & Feedback Loop
- Alerts landing in the 35–64 mid-confidence band are exactly where the model is least certain — prioritize these for analyst review first, since labeling them improves the model fastest per label spent.
- Maintain a local SQLite store: `ioc_value, ioc_type, alert_id, feature_vector, analyst_verdict, verdict_timestamp`.
- Confirmed FP → allowlist candidate (with 30-day expiry/revalidation). Confirmed TP → denylist candidate (with 30-day expiry/revalidation).
- Re-score any open alerts sharing that IOC immediately after a new verdict is recorded.
- Retrain the calibrated model on the full label set on a fixed cadence (e.g. weekly) and re-evaluate thresholds against fresh ROC/precision-recall curves each time.

## 10. Output Schema
```json
{
  "alert_id": "",
  "cortex_severity": "",
  "cortex_native_verdict": "",
  "classification": "TP|Mid-confidence|Likely FP|FP|UNKNOWN",
  "confidence_score": 0-100,
  "iocs": [
    {"value": "", "type": "", "reputation": "malicious|suspicious|clean|unknown",
     "sources_hit": [], "recency_decayed_weight": 0.0, "points_contributed": 0}
  ],
  "causality_chain_depth": 0,
  "command_line_entropy": 0.0,
  "static_analysis_flag": false,
  "cross_ioc_escalated": false,
  "correlated_alert_ids": [],
  "override_applied": "allowlist|denylist|none",
  "active_learning_priority": false,
  "recommended_action": "block|investigate|review|auto-close",
  "processed_at": ""
}
```

## 11. Performance & Cost Targets
- Throughput: ≥100 alerts/hour on a single low-spec VM/container.
- Cache hit rate: ≥80% after first week of steady-state operation.
- API cost: $0 — free tiers only, enforced by per-source token-bucket limiting.
- Accuracy: track precision, recall, and AUC against the feedback store weekly; re-tune via the ROC curve (Section 7) rather than adding paid sources. Target recall ≥95% on confirmed TPs even if it costs some precision.

## 12. Implementation Notes
- Concurrency: one async worker pool per API source, each with its own token-bucket limiter.
- Never call an external API for an IOC already resolved in this run or within cache TTL.
- Log full feature vectors and score breakdowns for every alert, not just the final verdict, so the model stays auditable and retrainable.
- Restrict feedback-store access; don't log raw IOC values alongside identifying org data beyond what the store needs.
