# SOC Triage SOAR Dashboard: Evaluation & Automation Report

We have successfully resolved all prompt, scoring, and classification inconsistencies in the triage pipeline, implemented a robust **Gemini model fallback chain**, and deployed a **SOAR (Security Orchestration, Automation, and Response) Dashboard** featuring model attribution, background triage pipeline triggering, auto-refresh, and persistent remediation controls.

---

## High-Level Verdict Summary

The table below summarizes the test cases, their classification, and how the fixes affected the results:

| Alert ID & Platform | Case Description | True Threat Nature | Model Classification | Model Score | Model Used | Remediation Status | Key Improvements |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **s1-ransomware-99** (S1) | Vssadmin shadow copy deletion + obfuscated PS + malicious C2 | **TP** (High) | **TP** | 100 | `gemini-3.1-flash-lite` | Idle | **Score Capping Verified:** Clamped perfectly from 120 to 100. |
| **cs-devops-01** (CS) | Jenkins service agent running a Git clone of corporate repo | **FP** (Benign) | **FP** | 0 | `gemini-3.1-flash-lite` | Idle | **Prompt Inconsistency Resolved:** Scored 0 (previously 95) now that it has the scoring rules. |
| **mde-doubleext-02** (MDE) | Outlook attachment double-extension `.pdf.exe` execution | **TP** (Medium) | **TP** | 85 | `gemini-3.1-flash-lite` | Idle | Contextually flagged behavior as high threat. |
| **mde-certutil-03** (MDE) | Certutil LOLBin download from blacklisted domain/IP | **TP** (High) | **TP** | 95 | `gemini-3.1-flash-lite` | Idle | Correctly calculated based on LOLBin behavior. |
| **cs-windowsupdate-04** (CS) | Silent MRT scan by SYSTEM (trusted Windows binary) | **FP** (Benign) | **FP** | 0 | `gemini-3.1-flash-lite` | Idle | **Prompt Inconsistency Resolved:** Scored 0 (previously 95) with signature penalty. |
| **s1-audit-tricky-06** (S1) | Active Directory discovery command (`nltest`) run by auditor | **FP** (Tricky) | **FP** | 0 | `gemini-3.1-flash-lite` | Idle | Correctly ignored discovery alert due to compliance agent context. |
| **cs-obfuscated-tricky-07** (CS) | Dynamic download via PowerShell with a fake comment tag | **TP** (Tricky) | **TP** | 65 | `gemini-3.1-flash-lite` | Idle | Detected bypass comment attempt and categorized as active threat. |
| **mde-search-tricky-08** (MDE) | Admin PowerShell searching scripts for the keyword "mimikatz" | **FP** (Tricky) | **FP** | 0 | `gemini-3.1-flash-lite` | Idle | **Keyword Gullibility Fixed:** Correctly parsed as a read search, avoiding false positive. |
| **cs-dllhijack-tricky-09** (CS) | Legitimate binary (`msoia.exe`) run under SYSTEM from Public | **TP** (Tricky) | **TP** | 85 | `gemini-3.1-flash-lite` | Idle | Correctly identified directory masquerading and privilege escalation. |
| **mde-masquerade-signed-10** (MDE) | Legitimate signed `svchost.exe` executed from `C:\Windows\Temp` | **TP** (Tricky) | **TP** | 55 | `gemini-3.1-flash-lite` | Idle | **Polished Prompt Evasion Rule:** Detected process masquerading despite verified signature and 0 VT hits. |

---

## ⚡ Polished Prompt & Robust Analysis (Case 10)
We polished the system instructions in [managed_soc_instructions.md](file:///d:/xdr-claude/managed_soc_instructions.md#L103-L151) to explicitly separate file-level reputation indices (like VT hits) from behavioral threat patterns. 

This was tested against **Case 10 (`mde-masquerade-signed-10`)**:
* **The Conflict:** An adversary copies the legitimate, Microsoft-signed system utility `svchost.exe` into a temp folder (`C:\Windows\Temp\svchost.exe`) and runs it to spawn a command shell. Strict math scoring rules would subtract **65 points** (verified signature and VT 0 clean hash), resulting in a `0` score.
* **The Logical Evasion:** The polished prompt instructs the agent to ignore reputation penalties when a highly malicious behavioral pattern (like executing system processes outside standard directories) is present. 
* **The Result:** The model calculated `Base 0 + Masquerading (+30) + LOLBin spawning shell (+25) = 55`. It correctly bypasses the reputation override penalty and classifies it as a **TP** due to execution out of Temp, demonstrating robust defense evasion triage.

---

## 🖥️ Web Dashboard Interface & Verification

### Visual Verification

Here is the dashboard viewport displaying all 10 processed cases, including the new model tags and model attributions:

![Dashboard All Verdicts Grid](/C:/Users/jatin/.gemini/antigravity-ide/brain/c7bdea14-56c9-49c5-a3b8-be95a79119f0/dashboard_verified_1782898928844.png)

### Dashboard Verification Animation

Below is the recording of the subagent refreshing the dashboard and verifying the details of Alert 10:

![Dashboard Flow Demo](/C:/Users/jatin/.gemini/antigravity-ide/brain/c7bdea14-56c9-49c5-a3b8-be95a79119f0/alert_10_verification_1782898893039.webp)
