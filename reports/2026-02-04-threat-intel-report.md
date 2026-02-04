# Cyber Threat Intelligence Report
**Date:** February 4, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0204

---

## Executive Summary

- **NEW**: CISA adds 4 KEV entries (Feb 3) - SolarWinds WHD CVE-2025-40551 actively exploited; deadline **February 6, 2026**
- **NEW**: Google Looker "LookOut" vulnerabilities - RCE chain affects 60,000+ organizations; self-hosted instances must patch immediately
- **NEW**: Iranian APT Infy (Prince of Persia) detailed analysis - Telegram-based C2 using Tonnerre v50, active since 2007
- **NEW**: ITRC 2025 Report - Record breaches but 79% fewer victim notices; attackers shifting to targeted data theft
- **NEW**: Target breach confirmed - 860 GB source code stolen, released on Gitea
- **UPDATE**: SolarWinds WHD now under active exploitation - chains with other CVEs for full system takeover
- **DEADLINE PASSED**: Microsoft DWM CVE-2026-20805 deadline was February 3

---

## Critical Vulnerabilities

### NEW: CISA KEV Additions (February 3, 2026)

Four vulnerabilities added with evidence of active exploitation:

| CVE | Product | CVSS | Deadline |
|-----|---------|------|----------|
| CVE-2025-40551 | SolarWinds Web Help Desk | 9.8 | **Feb 6, 2026** |
| CVE-2019-19006 | Sangoma FreePBX | - | Feb 24, 2026 |
| CVE-2021-39935 | GitLab CE/EE | - | Feb 24, 2026 |
| CVE-2025-64328 | Sangoma FreePBX | - | Feb 24, 2026 |

**Source:** [CISA](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)

---

### NEW: SolarWinds Web Help Desk - Active Exploitation Confirmed

**CVE:** CVE-2025-40551
**CVSS:** 9.8 (Critical)
**Type:** Deserialization of untrusted data → RCE
**Authentication:** None required
**CISA Deadline:** February 6, 2026 (3 days)

**Details:**
Vulnerability in AjaxProxy functionality due to improper sanitization. Attackers can execute arbitrary commands on host without authentication.

**Attack Chaining:**
Attackers can chain CVE-2025-40552 or CVE-2025-40554 with CVE-2025-40551 or CVE-2025-40553 for complete system takeover, enabling lateral movement, data theft, and ransomware deployment.

**Affected:** Web Help Desk 12.8.8 HF1 and all prior versions
**Fixed:** Web Help Desk 2026.1

**Threat Intelligence:**
- Underground community discussions increasing post-disclosure
- No public PoC observed yet
- Functional exploits confirmed via KEV inclusion
- CISA lists ransomware usage as "unknown"

**Impact:** 300,000+ customers worldwide; heavily used in government, education, and healthcare

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/cisa-adds-actively-exploited-solarwinds.html), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-critical-solarwinds-rce-flaw-as-actively-exploited/), [Horizon3.ai](https://horizon3.ai/attack-research/cve-2025-40551-another-solarwinds-web-help-desk-deserialization-issue/)

---

### NEW: Google Looker "LookOut" Vulnerabilities

**CVE:** CVE-2025-12743
**Researcher:** Tenable
**Impact:** RCE, SQL injection, cross-tenant access
**Affected Organizations:** 60,000+ across 195 countries

**Vulnerabilities:**
1. **RCE Chain** - Full server takeover via remote command execution
2. **SQL Injection** - schemas parameter allows extraction from internal MySQL

**Attack Impact:**
- Steal sensitive secrets
- Manipulate data
- Pivot into internal networks
- Cloud instances: potential cross-tenant access

**Remediation:**
- **Looker-hosted:** Already mitigated, no action required
- **Self-hosted:** Upgrade immediately to patched versions

**Patched Versions:** 24.12.106, 24.18.198+, 25.0.75, 25.6.63+, 25.8.45+, 25.10.33+, 25.12.1+, 25.14+

**Source:** [Help Net Security](https://www.helpnetsecurity.com/2026/02/04/google-looker-vulnerabilities-cve-2025-12743/)

---

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2025-40551 | SolarWinds Web Help Desk | **February 6, 2026** |
| CVE-2026-20045 | Cisco Unified CM/Webex | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |
| CVE-2019-19006/CVE-2021-39935/CVE-2025-64328 | FreePBX, GitLab | February 24, 2026 |

---

## APT & Threat Actor Activity

### NEW: Iranian APT Infy (Prince of Persia) - Deep Dive

**Threat Actor:** Infy / Prince of Persia
**Attribution:** Iranian government-linked
**Active Since:** 2007 (~20 years operational)
**Discovered by:** SafeBreach Labs

**Significance:** "The longest publicly known threat actor who has operated with the same arsenal."

**Recent Targets:**
- Iran, Iraq, Turkey, India, Canada, Europe
- Iranian dissidents, journalists, diplomats, civil society

**Malware Arsenal:**

| Malware | Version | Purpose |
|---------|---------|---------|
| Foudre | v34 | First-stage recon, victim identification |
| Tonnerre | v12-18, v50 | Data exfiltration, surveillance |

**Key Evolution - Tonnerre v50:**
- First use of **Telegram-based C2** in Infy's history
- Commands relayed via Telegram bot (ttestro1bot) to attacker-controlled group
- Operator identified as "Ehsan" (Persian name)
- Last active: December 13, 2025

**Delivery Method:**
- Excel files with embedded malicious executable (SFX archive)
- Contains malicious DLL + decoy MP4 video
- Zero detection on VirusTotal

**C2 Protection:**
- RSA signature verification
- Domain Generation Algorithm (DGA) - 100 domains/week
- Only trusts C2 if signature verifies correctly

**Sources:** [SafeBreach](https://www.safebreach.com/blog/prince-of-persia-a-decade-of-an-iranian-nation-state-apt-campaign-activity/), [The Hacker News](https://thehackernews.com/2025/12/iranian-infy-apt-resurfaces-with-new.html), [Dark Reading](https://www.darkreading.com/threat-intelligence/iran-apt-spying-dissidents)

---

## Data Breaches

### NEW: Target - 860 GB Source Code Stolen

**Victim:** Target Corporation
**Confirmed:** January 13, 2026
**Data Volume:** ~860 GB
**Contents:** Internal code, developer documentation across multiple repositories
**Leak Platform:** Gitea

**Notable:** Attackers targeted source code rather than customer data, suggesting potential supply chain attack preparation or competitive espionage.

**Source:** [Security Magazine](https://www.securitymagazine.com/articles/102110-7-data-breaches-exposures-to-know-about-january-2026)

---

### NEW: ITRC 2025 Annual Data Breach Report

**Released:** February 4, 2026
**Key Finding:** 2025 had the highest number of breaches to date

**Paradigm Shift:**
- Victim notices decreased **79% year-over-year**
- Attackers moving away from "mega-breaches" (2024 trend)
- Favoring frequent, precise attacks on valuable data sources

**Implication:** Organizations may be unaware they've been breached; detection capabilities critical.

**Source:** [Bright Defense](https://www.brightdefense.com/resources/recent-data-breaches/)

---

### NEW: Monroe University - 320,000 Affected

**Victim:** Monroe University
**Breach Date:** December 23, 2024
**Disclosed:** January 2, 2026
**Affected:** ~320,000 individuals

**Source:** [Tech.co](https://tech.co/news/data-breaches-updated-list)

---

### February 3-4, 2026 Ransomware Activity

| Victim | Threat Actor | Sector |
|--------|--------------|--------|
| BASF SE | 0APT | Chemical |
| Honeywell | 0APT | Industrial |
| BEAM | TheGreenBloodGroup | Unknown |
| Comune di Battipaglia | Medusa | Government (Italy) |
| Elabs | Rhysida | Unknown |
| Encompass | Devman | Unknown |
| Erickson | DragonForce | Unknown |
| Exterior Worlds | Qilin | Unknown |
| Ferretti Group | Akira | Luxury Yachts |
| Liberia Revenue Authority | Unknown | Government |
| Dassault Systèmes | Unknown | Software |
| Linde plc | Unknown | Industrial Gas |

**Source:** [BreachSense](https://www.breachsense.com/breaches/2026/february/)

---

## KEV Catalog Statistics

| Metric | Value |
|--------|-------|
| Total KEV entries | 1,505 |
| Added in 2025 | 245 (+30% YoY) |
| End of 2024 | 1,239 |
| End of 2025 | 1,484 |
| Silent ransomware flips (2025) | 59 |

**Key Insight:** 59 vulnerabilities were silently updated to "known ransomware use" status during 2025 without public announcement.

**Source:** [GreyNoise](https://www.greynoise.io/blog/unmasking-cisas-hidden-kev-ransomware-updates), [Cyble](https://cyble.com/blog/cisa-kev-2025-exploited-vulnerabilities-growth/)

---

## Vendor Advisories

### SolarWinds
- **Web Help Desk 2026.1** released January 28, 2026
- Patches CVE-2025-40551 (critical RCE)
- All prior versions vulnerable

### Google (Looker)
- Self-hosted instances must upgrade to patched versions
- Looker-hosted already mitigated

### FreePBX/Sangoma
- CVE-2019-19006: Improper authentication
- CVE-2025-64328: OS command injection
- Deadline: February 24, 2026

### GitLab
- CVE-2021-39935: SSRF vulnerability
- Affects Community and Enterprise editions
- Deadline: February 24, 2026

---

## Recommended Actions

### Immediate Priority (Next 48 Hours)

1. **SolarWinds WHD** - Patch to version 2026.1 before **February 6** CISA deadline
2. **Google Looker (self-hosted)** - Upgrade immediately; RCE chain actively disclosed
3. **FreePBX/Sangoma** - Review for CVE-2019-19006/CVE-2025-64328 exposure

### High Priority (This Week)

4. **Cisco UCM/Webex** - Patch CVE-2026-20045 before February 11 deadline
5. **GitLab CE/EE** - Patch CVE-2021-39935 SSRF vulnerability
6. **n8n** - Ensure updated; three critical flaws (10.0, 9.9, 8.5 CVSS)

### Threat Hunting

7. **Excel files with embedded executables** - Hunt for Infy/Prince of Persia indicators
8. **Telegram bot C2** - Monitor for ttestro1bot connections
9. **SolarWinds WHD logs** - Review AjaxProxy requests for exploitation attempts
10. **Looker audit logs** - Check for SQL injection patterns in schemas parameter

### Breach Monitoring

11. **Target suppliers/partners** - Assess exposure from 860 GB code leak
12. **ITRC notification gaps** - Review whether your organization may have unreported exposures

---

## Sources

- [CISA - February 3 KEV Additions](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [The Hacker News - SolarWinds WHD](https://thehackernews.com/2026/02/cisa-adds-actively-exploited-solarwinds.html)
- [BleepingComputer - SolarWinds](https://www.bleepingcomputer.com/news/security/cisa-flags-critical-solarwinds-rce-flaw-as-actively-exploited/)
- [Help Net Security - Google Looker](https://www.helpnetsecurity.com/2026/02/04/google-looker-vulnerabilities-cve-2025-12743/)
- [SafeBreach - Prince of Persia](https://www.safebreach.com/blog/prince-of-persia-a-decade-of-an-iranian-nation-state-apt-campaign-activity/)
- [Dark Reading - Iranian APT](https://www.darkreading.com/threat-intelligence/iran-apt-spying-dissidents)
- [Horizon3.ai - SolarWinds Analysis](https://horizon3.ai/attack-research/cve-2025-40551-another-solarwinds-web-help-desk-deserialization-issue/)
- [BreachSense - February 2026](https://www.breachsense.com/breaches/2026/february/)
- [Security Magazine - January 2026 Breaches](https://www.securitymagazine.com/articles/102110-7-data-breaches-exposures-to-know-about-january-2026)
- [GreyNoise - KEV Ransomware Updates](https://www.greynoise.io/blog/unmasking-cisas-hidden-kev-ransomware-updates)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 2-3, 2026 reports:

- CVE-2026-21858/CVE-2026-1470/CVE-2026-0863 n8n critical vulnerabilities
- CVE-2026-20805 Microsoft DWM zero-day (deadline passed Feb 3)
- CVE-2026-20045 Cisco UCM/Webex zero-day
- CVE-2026-21509 Microsoft Office zero-day
- CVE-2026-24061 GNU InetUtils telnetd
- CVE-2026-0625 D-Link DSL routers (no patch available)
- Under Armour breach (72.7M accounts, Everest ransomware)
- Nike/WorldLeaks claims (1.4TB)
- Crunchbase breach (ShinyHunters, 2M+ records)
- AT&T breach data resurface
- Phantom Taurus NET-STAR malware suite
- BlackCat/Alphv sentencing (March 12, 2026)
- SimonMed Imaging ransomware (Medusa)
- Illinois DHS breach (600K+)
- University of Phoenix breach (3.5M)
- Sedgwick Government Solutions ransomware

---

*Report generated: 2026-02-04*
*Next report: 2026-02-05*
*Classification: TLP:CLEAR*
