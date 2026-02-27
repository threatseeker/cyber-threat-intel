# Cyber Threat Intelligence Report
**Date:** 2026-02-27
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0227

---

## Executive Summary

- **CRITICAL DEADLINE TODAY:** CISA emergency directive requires federal agencies to patch CVE-2026-20127 (Cisco Catalyst SD-WAN auth bypass) by 5:00 PM ET today (Feb 27)
- Microsoft February 2026 Patch Tuesday patched **6 actively exploited zero-days** and 58 total flaws - immediate patching required
- **BeyondTrust CVE-2026-1731** (CVSS 9.9) actively exploited with VShell and SparkRAT backdoors; 10,600+ internet-exposed instances remain unpatched
- China-nexus APT group **UNC3886** compromised all four major Singapore telecommunications operators; Singapore launched its largest-ever cyber operation in response
- Ransomware actors struck **Advantest** (chip testing giant) and claimed 8 TB stolen from **Conduent** - critical infrastructure targeting accelerating
- **Chrome zero-day CVE-2026-2441** (use-after-free in CSS) under active exploitation - browser updates should be deployed immediately
- Two **RoundCube Webmail** vulnerabilities (CVE-2025-49113, CVE-2025-68461) added to CISA KEV on Feb 20 - patch mail servers now

---

## Critical Vulnerabilities

### CISA KEV Additions - February 2026

| CVE | Product | Type | CISA Deadline |
|-----|---------|------|---------------|
| CVE-2026-20127 | Cisco Catalyst SD-WAN Controller/Manager | Auth Bypass | **Feb 27, 2026 (TODAY)** |
| CVE-2022-20775 | Cisco Catalyst SD-WAN | Path Traversal / Privilege Escalation | Feb 27, 2026 |
| CVE-2026-1731 | BeyondTrust Remote Support / PRA | OS Command Injection (RCE) | Feb 27, 2026 |
| CVE-2025-49113 | RoundCube Webmail | Deserialization of Untrusted Data | Added Feb 20 |
| CVE-2025-68461 | RoundCube Webmail | Cross-site Scripting | Added Feb 20 |
| CVE-2026-21510 | Microsoft Windows Shell | Security Feature Bypass | Added Feb 10 |
| CVE-2026-21513 | Microsoft MSHTML Framework | Security Feature Bypass | Added Feb 10 |
| CVE-2026-21514 | Microsoft Office Word | Untrusted Input Security Bypass | Added Feb 10 |
| CVE-2026-21519 | Microsoft Windows | Type Confusion / EoP | Added Feb 10 |
| CVE-2026-21525 | Microsoft Windows | NULL Pointer Deref / DoS | Added Feb 10 |
| CVE-2026-21533 | Windows Remote Desktop Services | Elevation of Privilege | Added Feb 10 |
| CVE-2019-19006 | Sangoma FreePBX | Improper Authentication | Added Feb 3 |
| CVE-2025-64328 | Sangoma FreePBX | OS Command Injection | Added Feb 3 |
| CVE-2021-39935 | GitLab Community/Enterprise | SSRF | Added Feb 3 |
| CVE-2025-40551 | SolarWinds Web Help Desk | Deserialization of Untrusted Data | Added Feb 3 |

### High-Priority Non-KEV CVEs

| CVE | Product | CVSS | Details |
|-----|---------|------|---------|
| CVE-2026-20127 | Cisco Catalyst SD-WAN | Critical | Unauthenticated admin access; confirmed exploitation in wild |
| CVE-2026-1731 | BeyondTrust RS/PRA | 9.9 | Unauthenticated RCE; 10,600+ exposed instances remain unpatched |
| CVE-2026-25049 | n8n Workflow | 9.4 | Bypass of prior patch (CVE-2025-68613); enables system command execution via malicious workflows |
| CVE-2026-26119 | Windows Admin Center | Critical | Privilege escalation; patched December 2025 |

---

## Exploits & Zero-Days

### Microsoft February 2026 Zero-Days (6 Actively Exploited)

All six zero-days were added to the CISA KEV catalog on February 10, 2026:

| CVE | Component | CVSS | Impact |
|-----|-----------|------|--------|
| CVE-2026-21510 | Windows Shell | 8.8 | Single-click security bypass; runs attacker content without consent dialogs |
| CVE-2026-21513 | MSHTML Framework | 8.8 | Bypasses web rendering security protections |
| CVE-2026-21514 | Microsoft Word | 5.5 | Security feature bypass via malicious documents |
| CVE-2026-21519 | Windows Desktop Window Manager | 7.8 | Local EoP via type confusion |
| CVE-2026-21525 | Windows RasMan (VPN) | 6.2 | Denial-of-service against VPN connections |
| CVE-2026-21533 | Windows Remote Desktop Services | 7.8 | EoP to SYSTEM level |

### Google Chrome Zero-Day

- **CVE-2026-2441** - Use-after-free in CSS; allows remote code execution inside sandbox via crafted HTML page. First actively exploited Chrome zero-day of 2026. Emergency patch released - update all browsers immediately.

### BeyondTrust Active Exploit Chain (CVE-2026-1731)

Attackers (multiple threat groups) are executing a multi-stage kill chain:
1. Network reconnaissance
2. Account creation on compromised hosts
3. Web shell deployment
4. C2 establishment
5. Backdoor installation (VShell - fileless Linux backdoor; SparkRAT - Go-based open-source RAT linked to DragonSpark group)
6. Lateral movement
7. Data exfiltration

Affected sectors: Financial services, legal, healthcare, higher education, retail, and high-tech across US, France, Germany, Australia, and Canada.

---

## Malware & Ransomware

### Active Campaigns

**Advantest (Chip Testing Giant) - Qilin/Unknown Ransomware**
- Japanese semiconductor testing giant Advantest detected IT network intrusion on February 15, 2026
- Significant operational disruption to critical semiconductor supply chain infrastructure

**Conduent - Ransomware Extortion**
- Ransomware actors claim ~8 TB of sensitive data stolen from Conduent (major US government IT services provider)
- One of the largest reported US data breach volumes in recent years; millions of Americans potentially affected

**Conpet (Romania National Oil Pipeline) - Qilin Ransomware**
- Qilin ransomware group hit Romania's national oil pipeline operator
- Critical infrastructure attack consistent with escalating energy sector targeting

**North Korean Actors - Medusa Ransomware**
- DPRK state-backed threat actors deploying Medusa ransomware against US healthcare sector
- Combining extortion with intelligence collection objectives

### Threat Landscape

- Active ransomware and extortion groups surged **49% year-over-year** in 2025
- 57 new ransomware groups and 27 new extortion groups emerged in 2025
- AI-powered attacks dramatically reducing time-to-exploit; IBM X-Force 2026 Threat Index reports shrinking attack timelines

---

## Threat Actors

### UNC3886 (China-Nexus) - Singapore Telecom Sector
**Operation CYBER GUARDIAN** (Singapore CSA, Feb 9, 2026)

- **Attribution:** UNC3886 - Mandiant-tracked China-nexus cyber espionage group
- **Targets:** All four major Singapore telecom operators - M1, SIMBA Telecom, Singtel, StarHub
- **TTPs:**
  - Zero-day exploit to bypass perimeter firewall
  - Rootkit deployment for persistent, undetected access
  - Long-term covert presence for intelligence collection
- **Impact:** No confirmed data exfiltration or service disruption; access was pre-positioned for potential disruption operations
- Singapore launched its **largest-ever cyber operation** to oust the threat actor

### DPRK (North Korea) - Healthcare/Financial Targeting
- Continued use of Medusa ransomware against US healthcare organizations
- Dual objectives: financial gain and intelligence collection

### Cisco SD-WAN Exploiters
- CVE-2026-20127 exploitation confirmed in the wild; Australian cybersecurity authorities first reported real-world attacks
- Unauthenticated attackers gaining administrative access to SD-WAN management infrastructure

---

## Data Breaches

| Organization | Scope | Data Exposed | Date |
|-------------|-------|-------------|------|
| Odido (Dutch Telecom) | 6 million+ accounts | Names, phone numbers, emails, bank accounts, passport numbers | Investigated Feb 7 |
| Conduent (US GovTech) | Millions of Americans | Large-scale government services data; ~8 TB claimed stolen | Disclosed Feb 2026 |
| IRS / DHS Data Sharing | 1.28 million individuals | Names and addresses shared with ICE; legal dispute ongoing | Filed Feb 12 |
| Substack | Undisclosed users | Phone numbers, email addresses, user data | Unauthorized access Feb 3 |
| Cottage Hospital | 1,600+ employees | SSNs, driver's license numbers, bank account information | Letters sent Feb 6 (Oct 2025 breach) |
| MedRevenu | Healthcare patients | HIPAA-regulated health data | Disclosed Feb 2026 |
| EyeCare Partners | Healthcare patients | HIPAA-regulated health data | Disclosed Feb 2026 |
| ACWA Power, Aju Pharm, Akol Law, Apex Hospitals | Multiple organizations | Varies | Discovered Feb 25 |

---

## Vendor Advisories

### Microsoft (February 2026 Patch Tuesday - Feb 10)
- **58 total vulnerabilities** patched; 5 Critical, 6 actively exploited zero-days
- Priority patches: All 6 zero-day CVEs listed above
- Additional: Updated Secure Boot certificates rolling out to replace expiring 2011 certificates (deadline: late June 2026)

### Adobe (February 2026 - Feb 10)
- **9 security advisories** covering 44 vulnerabilities across:
  - Adobe Audition, After Effects, InDesign Desktop
  - Substance 3D Designer, Stager, Modeler
  - Adobe Bridge, Lightroom Classic, DNG SDK
- **27 of 44 vulnerabilities rated Critical** - update all Adobe products

### Cisco (February 2026)
- CVE-2026-20127: Emergency patch for Catalyst SD-WAN Controller/Manager auth bypass
- CVE-2022-20775: Patch for Catalyst SD-WAN path traversal (legacy flaw now actively exploited)
- Apply patches immediately; CISA emergency directive deadline is today

### BeyondTrust (Feb 6, 2026)
- CVE-2026-1731: Critical RCE patch released; CVSS 9.9
- 10,600+ internet-exposed instances remain unpatched - immediate action required

### Google Chrome
- CVE-2026-2441: Emergency update released for use-after-free zero-day
- Deploy browser updates across all endpoints immediately

---

## Recommended Actions

### Priority 1 - TODAY (Emergency)

1. **Cisco Catalyst SD-WAN** - Apply CVE-2026-20127 and CVE-2022-20775 patches NOW. CISA FCEB deadline is 5:00 PM ET today. Treat all SD-WAN management interfaces as potentially compromised pending patch verification.

2. **BeyondTrust Remote Support / PRA** - Patch CVE-2026-1731 (CVSS 9.9) immediately. Audit for indicators of compromise: unexpected accounts, web shells, VShell/SparkRAT artifacts. Restrict internet exposure of BeyondTrust interfaces.

3. **Google Chrome** - Force-update all browsers to latest version. CVE-2026-2441 actively exploited in the wild.

### Priority 2 - This Week

4. **Microsoft February 2026 Patches** - Deploy all Patch Tuesday updates, prioritizing the 6 zero-days (CVE-2026-21510, 21513, 21514, 21519, 21525, 21533). Focus on Windows Shell, MSHTML, Word, and RDP Services.

5. **RoundCube Webmail** - Patch CVE-2025-49113 and CVE-2025-68461. Mail server exposure is high-value for initial access.

6. **n8n Workflow Platform** - Patch CVE-2026-25049 (CVSS 9.4) if running n8n in production. Audit existing workflows for malicious injections.

### Priority 3 - This Month

7. **Adobe Products** - Deploy all February Adobe security updates across all workstations. 27 critical flaws across creative suite.

8. **Sangoma FreePBX** - Patch CVE-2019-19006 and CVE-2025-64328 if running VoIP infrastructure.

9. **SolarWinds Web Help Desk** - Apply patch for CVE-2025-40551 deserialization vulnerability.

10. **GitLab** - Patch CVE-2021-39935 SSRF vulnerability on self-hosted instances.

11. **Threat Hunting** - Hunt for UNC3886 TTPs if operating in telecom, government, or critical infrastructure sectors. IOCs: perimeter firewall zero-day indicators, rootkit artifacts, unusual service persistence.

12. **Ransomware Resilience** - Verify offline backups for OT/ICS environments following Advantest and Conpet incidents. Test restoration procedures.

13. **Secure Boot** - Begin planning Secure Boot certificate migration ahead of the June 2026 deadline for 2011 certificate expiration.

---

## Sources

- [CISA KEV - Feb 20 Additions (RoundCube)](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 10 Additions (Microsoft)](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 13 Addition (BeyondTrust)](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV - Feb 3 Additions](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Cisco CVE-2026-20127 - Rapid7 ETR](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-vulnerability-exploited-in-the-wild-cve-2026-20127/)
- [Cisco SD-WAN Auth Bypass - TheHackerWire](https://www.thehackerwire.com/cisco-sd-wan-critical-peering-authentication-bypass-cve-2026-20127/)
- [CISA KEV Cisco Update - WindowsForum](https://windowsforum.com/threads/cisa-kev-update-patch-urgency-for-cisco-catalyst-sd-wan-flaws.403256/)
- [BeyondTrust CVE-2026-1731 - Unit 42 / Palo Alto](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [BeyondTrust VShell SparkRAT - SecurityAffairs](https://securityaffairs.com/188370/hacking/cve-2026-1731-fuels-ongoing-attacks-on-beyondtrust-remote-access-products.html)
- [BeyondTrust Flaw Web Shells - The Hacker News](https://thehackernews.com/2026/02/beyondtrust-flaw-used-for-web-shells.html)
- [n8n CVE-2026-25049 - The Hacker News](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [Windows Admin Center CVE-2026-26119 - Help Net Security](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)
- [Microsoft February 2026 Patch Tuesday - BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [February 2026 Patch Tuesday - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)
- [February 2026 Patch Tuesday - Krebs on Security](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [February 2026 Patch Tuesday - Zero Day Initiative](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
- [Patch Tuesday Analysis - CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-february-2026/)
- [Patch Tuesday - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2026/02/10/microsoft-patch-tuesday-february-2026-security-update-review)
- [Patch Tuesday - Tenable](https://www.tenable.com/blog/microsofts-february-2026-patch-tuesday-addresses-54-cves-cve-2026-21510-cve-2026-21513)
- [Patch Tuesday - Cisco Talos](https://blog.talosintelligence.com/microsoft-patch-tuesday-february-2026/)
- [Chrome Zero-Day CVE-2026-2441 - The Hacker News](https://thehackernews.com/2026/02/new-chrome-zero-day-cve-2026-2441-under.html)
- [Chrome Zero-Day - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)
- [UNC3886 Singapore Operation - Computer Weekly](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [UNC3886 - Singapore CSA Press Release](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [Advantest Ransomware - SecurityWeek](https://www.securityweek.com/chip-testing-giant-advantest-hit-by-ransomware/)
- [Conduent Breach - TechCrunch](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [Ransomware Roundup - Advanced IT Technologies](https://www.advancedittechnologies.com/post/february-2026-cybersecurity-news-roundup-major-breaches-ai-driven-attacks-critical-vulnerabiliti)
- [Ransomware Trends 2026 - Cyble](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)
- [IBM X-Force 2026 Threat Index](https://uk.newsroom.ibm.com/ibm-2026-x-force-threat-index)
- [Odido Data Breach - Privacy Guides](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [IRS Data Sharing Incident](https://evrimagaci.org/gpt/irs-data-breach-sparks-outcry-over-immigration-deal-528626)
- [Healthcare Breaches - HIPAA Journal](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [Cottage Hospital Breach - Valley News](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [SharkStriker February Breaches Roundup](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)
- [Security Signals Feb 10-24 - Malware Patrol](https://www.malwarepatrol.net/late-february-2026-cyber-threat-reports/)
