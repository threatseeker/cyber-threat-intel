# Cyber Threat Intelligence Report
**Date:** 2026-03-11
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0311

---

## Executive Summary

- **Microsoft March 2026 Patch Tuesday** fixes 84 vulnerabilities including 8 Critical and 2 publicly disclosed zero-days (CVE-2026-21262, CVE-2026-26127)
- **Google Android March 2026 update** patches 129 vulnerabilities including actively exploited Qualcomm zero-day **CVE-2026-21385** targeting 234+ chipsets
- **CISA adds 10 vulnerabilities to KEV catalog** in March including VMware Aria Operations CVE-2026-22719, Ivanti EPM auth bypass CVE-2026-1603, and SolarWinds WHD deserialization flaw
- **Iran escalates cyber operations** following US-Israel military strikes; Seedworm APT active on US bank, airport, and software company networks
- **Singapore completes Operation Cyber Guardian** — largest national cyber operation to evict China-linked UNC3886 from four major telcos
- **Two US cybersecurity professionals** (former incident responders) sentenced March 12 for operating as ALPHV/BlackCat ransomware affiliates
- **Ransomware-without-encryption** trend accelerating — pure data exfiltration attacks surging as attackers shift away from traditional encryption

---

## Critical Vulnerabilities

### CISA KEV Additions (March 2026)

| CVE | Product | Type | CVSS | Due Date |
|-----|---------|------|------|----------|
| CVE-2026-22719 | VMware Aria Operations | Command Injection | 8.1 | TBD |
| CVE-2026-1603 | Ivanti Endpoint Manager | Authentication Bypass | TBD | 2026-03-23 |
| CVE-2025-26399 | SolarWinds Web Help Desk | Deserialization of Untrusted Data | TBD | 2026-03-12 |
| CVE-2021-22054 | Omnissa Workspace ONE | Server-Side Request Forgery | TBD | 2026-03-23 |
| CVE-2017-7921 | Hikvision Multiple Products | Improper Authentication | TBD | TBD |
| CVE-2021-22681 | Rockwell Multiple Products | Insufficient Protected Credentials | TBD | TBD |
| CVE-2021-30952 | Apple Multiple Products | Integer Overflow | TBD | TBD |
| CVE-2023-41974 | Apple iOS/iPadOS | Use-After-Free | TBD | TBD |
| CVE-2023-43000 | Apple Multiple Products | Use-After-Free | TBD | TBD |

### Microsoft Patch Tuesday (March 11, 2026)

**84 vulnerabilities patched** — 8 Critical, 76 Important. None actively exploited at time of release.

| CVE | Product | Type | CVSS |
|-----|---------|------|------|
| CVE-2026-21536 | Microsoft Devices Pricing Program | RCE (Unrestricted File Upload) | 9.8 |
| CVE-2026-26111 | Windows RRAS | RCE (SYSTEM privileges) | Critical |
| CVE-2026-26110 | Microsoft Office | RCE (Untrusted Pointer Deref) | 8.4 |
| CVE-2026-26113 | Microsoft Office | RCE (Type Confusion) | 8.4 |
| CVE-2026-23674 | Windows MapUrlToZone | Security Feature Bypass | Critical |
| CVE-2026-25190 | Windows GDI | RCE | Critical |

**Breakdown by type:** Elevation of Privilege 56%, RCE 20%, Information Disclosure 12%.

### Google Android Security Update (March 2026)

**129 vulnerabilities patched** across two patch levels (2026-03-01 and 2026-03-05).

| CVE | Component | Type | Status |
|-----|-----------|------|--------|
| CVE-2026-21385 | Qualcomm Display Driver | Memory Corruption (Integer Overflow) | **Actively Exploited** |

The Qualcomm zero-day affects 234+ chipsets (hundreds of millions of devices). Suspected commercial spyware vendors exploiting for targeted surveillance of journalists, activists, and government officials.

---

## Exploits & Zero-Days

### Actively Exploited

- **CVE-2026-21385** (Qualcomm Display Driver) — Integer overflow enabling local privilege escalation. Qualcomm alerted Dec 18, 2025; patched March 2026. Targeted exploitation by suspected commercial spyware vendors.
- **CVE-2026-22719** (VMware Aria Operations) — Command injection allowing unauthenticated arbitrary command execution. Added to CISA KEV.
- **CVE-2026-1603** (Ivanti EPM) — Authentication bypass. Added to CISA KEV.

### Publicly Disclosed (Not Yet Exploited)

- **CVE-2026-21262** (Microsoft SQL Server) — Improper access control allowing authenticated attackers to gain SQL admin privileges over a network.
- **CVE-2026-26127** (.NET Framework) — Out-of-bounds read enabling remote denial-of-service.

---

## Malware & Ransomware

### ALPHV/BlackCat Sentencing

Two former US cybersecurity professionals — **Ryan Goldberg** (40, Georgia, ex-Sygnia incident response manager) and **Kevin Martin** (36, Texas, ex-DigitalMint ransomware negotiator) — pleaded guilty to conspiracy to commit extortion as ALPHV/BlackCat affiliates. They attacked multiple US organizations between April-December 2023. **Sentencing: March 12, 2026.** They face up to 20 years in prison.

### Ransomware Trend: Pure Exfiltration Attacks

A significant shift is underway: many ransomware operations now skip encryption entirely. Attackers quietly exfiltrate data over weeks/months, then extort victims after the breach. This model is harder to detect, lower risk for attackers, and nearly impossible to investigate once logs age out.

### Active Ransomware Groups

- **DragonForce** — Claimed breach of German insurer HanseMerkur; ~97GB exfiltrated
- **Lapsus$** — Targeted Lacoste SA; scope of exfiltration under investigation
- **Conduent breach update** — Safepay ransomware gang responsible; impact expanded to **25+ million** individuals affected
- **INC Ransomware** — Using strong encryption + double extortion
- **Gentlemen Ransomware** — Globally active, dual-extortion, advanced evasion techniques

---

## Threat Actors

### Iran — Seedworm/MuddyWater (Post-Kinetic Escalation)

Following the February 28, 2026 US-Israel joint military offensive against Iran, cyber retaliation has escalated significantly:

- **Seedworm** (MuddyWater/Temp Zagros/Static Kitten) active on networks of a **US bank, airport, software company**, and NGOs in the US and Canada since early February 2026
- **Handala group** claimed breaches of Sharjah National Oil Corporation and Israel Opportunity Energy
- Unit 42 issued a dedicated [Threat Brief on Iranian cyber escalation](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)

### China — UNC3886 (Singapore Telecom Espionage)

Singapore completed **Operation Cyber Guardian**, its largest-ever coordinated cyber incident response:

- **Target:** All four major Singapore telcos (Singtel, StarHub, M1, Simba Telecom)
- **Method:** Zero-day exploit to bypass perimeter firewalls; rootkits for persistent undetected access
- **Exfiltration:** Small amount of technical/network data stolen
- **Response:** 100+ cyber defenders from 6 agencies (CSA, IMDA, CSIT, DIS, GovTech, ISD) over 11 months
- UNC3886 is a suspected Chinese state-sponsored cyber espionage group

### Pakistan — APT36

APT36 has begun using **AI coding tools to mass-produce malware**, designed to overwhelm defenses through sheer volume rather than technical sophistication. This represents a notable evolution in AI-assisted offensive operations.

---

## Data Breaches

| Organization | Date | Impact | Threat Actor |
|-------------|------|--------|-------------|
| Conduent | Ongoing (updated) | 25+ million individuals | Safepay Ransomware |
| HanseMerkur (Germany) | Early March 2026 | ~97GB exfiltrated | DragonForce |
| Lacoste SA (France) | March 2026 | Under investigation | Lapsus$ |
| USHA International (India) | March 2026 | Employee data, SAP/CMS/CMR databases | Unknown |
| Multiple orgs (March 10) | 2026-03-10 | Various | Everest, LockBit, INC_RANSOM |

---

## Vendor Advisories

| Vendor | Advisory | Details |
|--------|----------|---------|
| **Microsoft** | March 2026 Patch Tuesday | 84 flaws, 8 Critical, 2 zero-days |
| **Google** | Android March 2026 Bulletin | 129 flaws, 1 actively exploited zero-day (Qualcomm) |
| **Qualcomm** | CVE-2026-21385 | Display driver integer overflow, 234+ chipsets |
| **VMware/Broadcom** | CVE-2026-22719 | Aria Operations command injection |
| **Ivanti** | CVE-2026-1603 | EPM authentication bypass |
| **SolarWinds** | CVE-2025-26399 | Web Help Desk deserialization |

---

## Recommended Actions

1. **IMMEDIATE:** Apply SolarWinds Web Help Desk patch (CISA deadline: March 12, 2026)
2. **IMMEDIATE:** Deploy Microsoft March 2026 Patch Tuesday updates — prioritize CVE-2026-21536 (CVSS 9.8) and RRAS CVE-2026-26111
3. **IMMEDIATE:** Push Android March 2026 security update to managed devices — CVE-2026-21385 is actively exploited
4. **HIGH:** Patch VMware Aria Operations (CVE-2026-22719) and Ivanti EPM (CVE-2026-1603) — both in CISA KEV
5. **HIGH:** Hunt for Seedworm/MuddyWater indicators on US networks, especially financial, transportation, and software sectors
6. **HIGH:** Review telco/ISP perimeter defenses against UNC3886 TTPs — zero-day firewall bypass + rootkit persistence
7. **MEDIUM:** Audit data exfiltration detection capabilities — ransomware groups increasingly using encryption-free extortion
8. **MEDIUM:** Monitor for APT36 AI-generated malware variants — high volume, lower quality, designed to overwhelm signature-based detection

---

## Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds Two KEV — March 3, 2026](https://www.cisa.gov/news-events/alerts/2026/03/03/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Adds Five KEV — March 5, 2026](https://www.cisa.gov/news-events/alerts/2026/03/05/cisa-adds-five-known-exploited-vulnerabilities-catalog)
- [CISA Adds Three KEV — March 9, 2026](https://www.cisa.gov/news-events/alerts/2026/03/09/cisa-adds-three-known-exploited-vulnerabilities-catalog)
- [CISA Flags VMware Aria CVE-2026-22719 — The Hacker News](https://thehackernews.com/2026/03/cisa-adds-actively-exploited-vmware.html)
- [CISA Flags SolarWinds, Ivanti, Workspace ONE — The Hacker News](https://thehackernews.com/2026/03/cisa-flags-solarwinds-ivanti-and.html)
- [Microsoft March 2026 Patch Tuesday — CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-march-2026/)
- [Microsoft March 2026 Patch Tuesday — SecPod](https://www.secpod.com/blog/84-flaws-patched-including-two-publicly-disclosed-vulnerabilities-microsofts-march-2026-patch-tuesday-update/)
- [Microsoft March 2026 Patch Tuesday — BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/)
- [Microsoft March 2026 Patch Tuesday — Krebs on Security](https://krebsonsecurity.com/2026/03/microsoft-patch-tuesday-march-2026-edition/)
- [Microsoft Patch Tuesday — Zero Day Initiative](https://www.zerodayinitiative.com/blog/2026/3/10/the-march-2026-security-update-review)
- [Microsoft Patch Tuesday — Talos Intelligence](https://blog.talosintelligence.com/microsoft-patch-tuesday-march-2026/)
- [CVE-2026-23674 MapUrlToZone Bypass — Windows News](https://windowsnews.ai/article/microsoft-patches-critical-cve-2026-23674-mapurltozone-bypass-in-march-2026-security-updates.404622)
- [CVE-2026-25190 GDI Vulnerability — Windows News](https://windowsnews.ai/article/cve-2026-25190-microsoft-patches-critical-gdi-vulnerability-in-march-2026-security-update.404599)
- [CVE-2026-26111 RRAS RCE — Windows News](https://windowsnews.ai/article/microsoft-patches-critical-rras-remote-code-execution-vulnerability-cve-2026-26111-in-march-2026-upd.404601)
- [Google Android March 2026 Security Update — CyberScoop](https://cyberscoop.com/android-security-update-march-2026/)
- [CVE-2026-21385 Qualcomm Zero-Day — SOC Prime](https://socprime.com/blog/cve-2026-21386-vulnerability/)
- [Android Zero-Day — BleepingComputer](https://www.bleepingcomputer.com/news/security/google-patches-android-zero-day-actively-exploited-in-attacks/)
- [Android Zero-Day — TechRepublic](https://www.techrepublic.com/article/news-google-android-security-update-129-vulnerabilities/)
- [Iran Cyber Escalation — Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [Seedworm APT on US Networks — Security.com](https://www.security.com/threat-intelligence/iran-cyber-threat-activity-us)
- [Singapore Operation Cyber Guardian — Computer Weekly](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [Singapore UNC3886 — IMDA Press Release](https://www.imda.gov.sg/resources/press-releases-factsheets-and-speeches/press-releases/2026/largest-cyber-operation-mounted-to-counter-unc3886-threat)
- [UNC3886 Singapore Telcos — The Hacker News](https://thehackernews.com/2026/02/china-linked-unc3886-targets-singapore.html)
- [Singapore Telcos vs Chinese Hackers — Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/singapore-major-telcos-fend-chinese-hackers)
- [APT36 AI Malware — Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/nation-state-actor-ai-malware-assembly-line)
- [ALPHV/BlackCat Guilty Plea — DOJ](https://www.justice.gov/opa/pr/two-americans-plead-guilty-targeting-multiple-us-victims-using-alphv-blackcat-ransomware)
- [BlackCat Affiliates — SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [BlackCat Affiliates — CSO Online](https://www.csoonline.com/article/4112400/two-cybersecurity-experts-plead-guilty-to-running-ransomware-operation.html)
- [Ransomware Without Encryption — Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Top Ransomware Attacks 2026 — SharkStriker](https://sharkstriker.com/blog/top-10-ransomware-attack-of-2026/)
- [Conduent Breach 25M — Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/the-conduent-breach-from-10-million-to-25-million-and-counting)
- [March 2026 Data Breaches — SharkStriker](https://sharkstriker.com/blog/march-data-breaches-today-2026/)
- [State of Ransomware 2026 — BlackFog](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [CYFIRMA Weekly Intelligence Report — March 5, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-05-march-2026/)

---

*Report generated by PAI Threat Intelligence | TLP:CLEAR*
