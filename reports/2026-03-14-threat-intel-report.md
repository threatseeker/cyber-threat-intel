# Cyber Threat Intelligence Report
**Date:** 2026-03-14
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0314

---

## Executive Summary

- **CRITICAL:** Chrome/Chromium zero-days CVE-2026-3909 and CVE-2026-3910 added to CISA KEV on March 13 -- actively exploited Skia OOB write and V8 engine flaw affecting all Chromium-based browsers; update immediately
- **CRITICAL:** n8n workflow automation CVE-2025-68613 added to CISA KEV on March 11 -- critical RCE via improper code resource control; FCEB deadline March 25, 2026
- **CRITICAL:** Handala hacktivist group claims March 12 wiper attack against Stryker Medical via Microsoft Intune abuse -- 200,000+ devices wiped across 79 countries, 5,000+ workers sent home in Ireland
- **HIGH:** Backup Viewer RCE (CVE-2026-21708, CVSS 9.9) published March 12 -- unauthenticated code execution as postgres user
- **HIGH:** GL-iNet router CVE-2026-26792 (CVSS 9.8) -- unauthenticated command injection on GL-AR300M16; no user interaction required
- **HIGH:** APT42 (Iran/IRGC) SpearSpecter campaign targeting senior government and defense officials via WhatsApp-based social engineering and multi-stage payload delivery
- **MEDIUM:** Pro-Russian Cardinal group claims IDF network infiltration; 313 Team hit Romania National Tax Agency in one-hour DDoS
- **MEDIUM:** New ransomware victims include Brightspeed (Crimson Collective), Sedgwick (TridentLocker 3.4GB), Malaysia Airlines; AI-generated malware Slopoly (Hive0163) disclosed by IBM X-Force

---

## Critical Vulnerabilities

### CISA KEV Additions -- New Since March 11, 2026

| CVE | Product | Type | CVSS | KEV Date | FCEB Due Date |
|-----|---------|------|------|----------|---------------|
| CVE-2025-68613 | n8n Workflow Automation | Improper Code Resource Control (RCE) | Critical | 2026-03-11 | 2026-03-25 |
| CVE-2026-3909 | Google Chrome / Chromium (Skia) | Out-of-Bounds Write | High | 2026-03-13 | TBD |
| CVE-2026-3910 | Google Chrome / Chromium (V8) | Type Confusion / Active Exploit | High | 2026-03-13 | TBD |

> **Note:** Items already reported in CTI-2026-0311 (CVE-2026-22719, CVE-2026-1603, CVE-2025-26399, CVE-2021-22054, CVE-2017-7921, CVE-2021-22681, CVE-2021-30952, CVE-2023-41974, CVE-2023-43000) are omitted.

### New High/Critical CVEs (Not Yet in KEV)

| CVE | Product | Type | CVSS | Published |
|-----|---------|------|------|-----------|
| CVE-2026-21708 | Backup Viewer Component | RCE (arbitrary code exec as postgres user) | 9.9 | 2026-03-12 |
| CVE-2026-26792 | GL-iNet GL-AR300M16 v4.3.11 | Command Injection (unauthenticated, no interaction) | 9.8 | March 2026 |

---

## Exploits and Zero-Days

### CVE-2026-3909 and CVE-2026-3910 -- Chrome/Chromium Actively Exploited

CISA added two Chrome vulnerabilities to KEV on March 13, 2026. Both affect the core Chromium engine used by Chrome, Edge, and Opera:

- **CVE-2026-3909** -- Out-of-bounds write in **Skia** (Chromium 2D graphics engine). Triggered via crafted HTML page; enables sandbox escape and arbitrary code execution. No privileges required.
- **CVE-2026-3910** -- Active exploitation in **Chromium V8 JavaScript engine**. Type confusion in V8 is a historically reliable pathway to full renderer compromise.

**Fix:** Update all Chromium-based browsers to build **146.0.7680.75 or newer**. Enforce automatic updates on managed endpoints immediately.

### CVE-2025-68613 -- n8n Critical RCE

n8n workflow expression evaluation engine fails to properly control dynamically managed code resources. Allows remote unauthenticated attackers to execute arbitrary code. Any self-hosted n8n instance exposed to the network is at risk. CISA deadline: March 25, 2026.

### CVE-2026-21708 -- Backup Viewer RCE (CVSS 9.9)

Published March 12. Critical flaw in a Backup Viewer component allows arbitrary code execution with postgres user privileges -- no authentication required. High priority for patching in environments running affected backup tooling.

### CVE-2026-26792 -- GL-iNet Router Command Injection

Multiple unauthenticated command injection vulnerabilities in GL-iNet GL-AR300M16 v4.3.11. Zero authentication, zero user interaction required. Attackers with network access can fully compromise the device and pivot into the LAN.

---

## Malware and Ransomware

### Slopoly -- AI-Generated Malware (IBM X-Force Disclosure)

IBM X-Force disclosed **Slopoly**, a suspected AI-generated malware framework used by financially motivated threat actor **Hive0163**. Researcher Golo Muhr confirmed the malware shows structural hallmarks of LLM-assisted development -- dramatically reducing time-to-capability for threat actors. This is a concrete, named real-world instance of AI-generated malware in active use.

### LockBit Exploiting Apache ActiveMQ

Threat actors are actively exploiting vulnerable Apache ActiveMQ servers (CVE-2023-46604) to deploy LockBit ransomware in targeted intrusion campaigns. Unpatched ActiveMQ instances should be treated as an active risk.

### Ransomware Cartelization -- Qilin / LockBit / Akira

Researchers confirmed increasing operational collaboration between Qilin, LockBit, and Akira ransomware groups. Shared infrastructure, affiliate overlap, and coordinated victim pressure mean organizations may face simultaneous multi-group extortion.

### New Ransomware Victims (March 12-14, 2026)

| Organization | Threat Actor | Impact |
|---|---|---|
| Brightspeed (US telecom/ISP) | Crimson Collective | Ransomware attack claimed |
| Sedgwick (gov subsidiary) | TridentLocker | 3.4 GB exfiltrated from isolated file transfer system |
| Malaysia Airlines | Unknown | 16M+ passenger records under investigation |
| einstein-tech.com.au | TheGentlemen | Ransomware |
| extremetrailers.com | Akira | Ransomware |
| flad.com | Chaos | Ransomware |

---

## Threat Actors

### [UPDATE] Handala Hack -- Stryker Wiper Attack (March 12, 2026)

Previously reported (CTI-2026-0311): Handala claimed breaches of Sharjah National Oil and Israel Opportunity Energy. Now escalating significantly.

On March 12, Handala claimed a destructive **wiper attack** against medical technology giant **Stryker**, alleging they abused **Microsoft Intune** to remotely wipe over **200,000 devices across 79 countries**, sending more than **5,000 workers home in Ireland**. Framed as retaliation for a February 28 missile strike on an Iranian school.

**Critical TTP:** Abusing MDM/Intune as a wiper delivery mechanism. Any org with misconfigured or compromised Intune admin access is a potential wiper target. Verify Intune conditional access policies and enforce phishing-resistant MFA on all admin accounts immediately.

Research identifies overlap between Handala (Void Manticore) and Scarred Manticore (IRGC-linked APT).

### APT42 / SpearSpecter -- IRGC WhatsApp Social Engineering Campaign

APT42 (IRGC-linked, active since 2015) evolved into a multi-stage campaign called SpearSpecter:
1. Initial contact via highly personalized WhatsApp outreach to senior government and defense officials
2. Victims guided to malicious infrastructure delivering a sophisticated custom payload
3. Tradecraft relies on OSINT-based persona construction and social trust before any technical exploitation

Targeting: Senior government and defense officials across US, Israel, and allied nations.

### Cardinal (Pro-Russian) -- Claims IDF Network Infiltration

Cardinal, a pro-Russian state-aligned hacktivist group, publicly claimed via Telegram to have infiltrated IDF networks, referencing a purportedly confidential document related to Magen Tsafoni (Northern Shield). Likely exaggerated for psychological effect but warrants monitoring.

### 313 Team -- Romania National Tax Agency DDoS

313 Team took down Romania National Tax Agency for one hour in retaliation for Romanian presidential statements on US military base access. First confirmed European government target of the current conflict cyber escalation.

---

## Data Breaches

| Organization | Country | Disclosure | Impact | Actor |
|---|---|---|---|---|
| Brightspeed | US | March 2026 | ISP customer data at risk | Crimson Collective |
| Sedgwick (gov subsidiary) | US | March 2026 | 3.4 GB sensitive data | TridentLocker |
| Malaysia Airlines | Malaysia | March 2026 | 16M+ passenger records under investigation | Unknown |
| Multiple (March 13 tracker) | Global | 2026-03-13 | Various orgs | Akira, Chaos, TheGentlemen, Exitium |

Note: Conduent (25M), HanseMerkur, Lacoste SA, and USHA International reported in CTI-2026-0311 are omitted here.

---

## Vendor Advisories

| Vendor | Update | Key CVEs |
|--------|--------|----------|
| Google Chrome | Update to 146.0.7680.75+ immediately | CVE-2026-3909, CVE-2026-3910 (both KEV) |
| n8n | Patch self-hosted instances now | CVE-2025-68613 (KEV, critical RCE) |
| GL-iNet | Patch GL-AR300M16 firmware | CVE-2026-26792 (CVSS 9.8 unauth CI) |
| Microsoft Intune | Audit conditional access and admin MFA | Abused by Handala as wiper delivery mechanism |
| Apache ActiveMQ | Patch CVE-2023-46604 | Active LockBit deployment vector |

---

## Recommended Actions

1. **IMMEDIATE:** Update all Chromium-based browsers (Chrome, Edge, Opera) to 146.0.7680.75+ -- CVE-2026-3909 and CVE-2026-3910 are actively exploited and in CISA KEV
2. **IMMEDIATE (by March 25):** Patch all n8n self-hosted instances against CVE-2025-68613 -- unauthenticated RCE, CISA FCEB deadline
3. **HIGH:** Audit Microsoft Intune admin accounts -- enforce phishing-resistant MFA and conditional access policies to prevent Handala-style MDM wiper abuse
4. **HIGH:** Patch GL-iNet GL-AR300M16 firmware -- CVSS 9.8 unauthenticated command injection; common in remote/SMB environments
5. **HIGH:** Patch CVE-2026-21708 (Backup Viewer RCE, CVSS 9.9) -- check vendor advisory and update affected backup tooling
6. **HIGH:** Hunt for APT42/SpearSpecter indicators -- WhatsApp-based initial contact targeting gov/defense personnel; brief staff on tradecraft
7. **MEDIUM:** Patch Apache ActiveMQ (CVE-2023-46604) -- active LockBit deployment vector
8. **MEDIUM:** Review exfiltration detection coverage -- AI-generated malware (Slopoly) and encryption-free ransomware are evading signature-based controls

---

## Sources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds One KEV March 11 n8n](https://www.cisa.gov/news-events/alerts/2026/03/11/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV Adds Skia and V8 Flaws -- Windows Forum](https://windowsforum.com/threads/cisa-kev-adds-critical-skia-and-chromium-v8-flaws-cve-2026-3909-cve-2026-3910-patch-now.405045/)
- [CVE-2026-21708 Critical RCE in Backup Viewer -- TheHackerWire](https://www.thehackerwire.com/critical-rce-in-backup-viewer-cve-2026-21708/)
- [GL-iNet Critical Command Injection -- TheHackerWire](https://www.thehackerwire.com/gl-inet-gl-ar300m16-critical-command-injection/)
- [CVE-2026-3910 Chrome V8 -- RedPacket Security](https://www.redpacketsecurity.com/cve-alert-cve-2026-3910-google-chrome/)
- [Stryker Cyber Attack Iranian Threat Actor -- Cyber Magazine](https://cybermagazine.com/news/iran-war-cyber-front-stryker-cyber-attack)
- [Iran Cyber Escalation Threat Brief -- Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [Iranian Cyber Capability 2026 -- Trellix](https://www.trellix.com/blogs/research/the-iranian-cyber-capability-2026/)
- [Iran vs Israel Cyber War -- SOCRadar](https://socradar.io/blog/cyber-reflections-us-israel-iran-war/)
- [Seedworm APT on US Networks -- Security.com](https://www.security.com/threat-intelligence/iran-cyber-threat-activity-us)
- [Ransomware Without Encryption -- Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Top Ransomware Attacks 2026 -- SharkStriker](https://sharkstriker.com/blog/top-10-ransomware-attack-of-2026/)
- [State of Ransomware 2026 -- BlackFog](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [March 2026 Data Breaches -- SharkStriker](https://sharkstriker.com/blog/march-data-breaches-today-2026/)
- [March 2026 Patch Tuesday -- CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-march-2026/)
- [Microsoft Patches 84 Flaws -- The Hacker News](https://thehackernews.com/2026/03/microsoft-patches-84-flaws-in-march.html)
- [Security Signals Early March 2026 -- Malware Patrol](https://www.malwarepatrol.net/early-march-2026-cyber-threat-reports/)
- [CYFIRMA Weekly Intelligence March 5 2026](https://www.cyfirma.com/news/weekly-intelligence-report-05-march-2026/)

---

*Report generated by CTI Sensei | TLP:CLEAR*
