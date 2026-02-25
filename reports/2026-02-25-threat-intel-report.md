# Cyber Threat Intelligence Report
**Date:** 2026-02-25
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0225

---

## Executive Summary

- **Conduent breach grows to 25M+** - Potentially the largest breach in U.S. history; Social Security numbers, medical data, and financial records exposed for 25+ million Americans across multiple states
- **Microsoft February Patch Tuesday** - 6 actively exploited zero-days patched among 58 total CVEs; SmartScreen bypass and Windows Shell flaws being actively weaponized
- **BeyondTrust RCE (CVE-2026-1731) now linked to ransomware** - CISA added to KEV; VShell/SparkRAT malware observed in active exploitation
- **UNC3886 (China-nexus APT) targets Singapore telecoms** - All 4 major telecoms (M1, SIMBA, Singtel, StarHub) targeted in highly coordinated espionage operation
- **CISA KEV updated Feb 24** - CVE-2026-25108 (Soliton FileZen OS Command Injection) added; RoundCube deserialization and XSS bugs added Feb 20
- **Advantest ransomware attack** - Japanese semiconductor testing giant hit Feb 15; supply chain impact being assessed
- **Qilin ransomware** - Nearly 190 victims claimed in 2026 YTD; continues to be most prolific active group

---

## Critical Vulnerabilities

### CISA KEV Additions - February 2026

| CVE | Product | Type | Added |
|-----|---------|------|-------|
| CVE-2026-25108 | Soliton Systems FileZen | OS Command Injection | Feb 24 |
| CVE-2025-49113 | RoundCube Webmail | Deserialization of Untrusted Data | Feb 20 |
| CVE-2025-68461 | RoundCube Webmail | Cross-Site Scripting | Feb 20 |
| CVE-2026-1731 | BeyondTrust Remote Support | Remote Code Execution | Feb 13 |
| CVE-2026-21510 | Microsoft Windows Shell | Security Feature Bypass | Feb 10 |
| CVE-2026-21513 | Microsoft MSHTML Framework | Security Feature Bypass | Feb 10 |
| CVE-2026-21514 | Microsoft Office Word | Reliance on Untrusted Inputs | Feb 10 |
| CVE-2026-21519 | Microsoft Windows DWM | Type Confusion / EoP | Feb 10 |
| CVE-2026-21525 | Windows Remote Access | NULL Pointer Dereference | Feb 10 |
| CVE-2026-21533 | Windows Remote Desktop Services | Elevation of Privilege | Feb 10 |
| CVE-2025-40551 | SolarWinds Web Help Desk | Deserialization | Feb 3 |
| CVE-2025-64328 | Sangoma FreePBX | OS Command Injection | Feb 3 |
| CVE-2019-19006 | Sangoma FreePBX | Improper Authentication | Feb 3 |
| CVE-2021-39935 | GitLab Community/Enterprise | SSRF | Feb 3 |

### Other Critical CVEs (CVSS 9+)

| CVE | Product | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2026-24300 | Azure Front Door | 9.8 | Critical EoP - remote attackers with no privileges can escalate |
| CVE-2026-25049 | n8n workflow automation | 9.4 | Inadequate sanitization enables system command execution via malicious workflows |
| CVE-2025-40540 | Serv-U | 9.1 | Type confusion RCE; grants arbitrary native code execution as privileged account |
| CVE-2026-26119 | Windows Admin Center | Critical | Privilege escalation (patch released Dec 2025, disclosed Feb 2026) |
| CVE-2026-1731 | BeyondTrust Remote Support | Critical | RCE in thin-scc-wrapper WebSocket handler - now ransomware-linked |

---

## Exploits & Zero-Days

### Microsoft February 2026 Patch Tuesday - Six Actively Exploited Zero-Days

1. **CVE-2026-21510** (CVSS 8.8) - Windows SmartScreen bypass; attackers trick users into opening malicious shortcut files to circumvent security prompts. Actively exploited in the wild.

2. **CVE-2026-21513** (CVSS 8.8) - MSHTML Framework vulnerability; used by Internet Explorer mode in Edge, actively exploited.

3. **CVE-2026-21514** (CVSS 5.5) - Microsoft Word remote code execution triggered by opening malicious .docx files. Preview Pane is NOT an attack vector.

4. **CVE-2026-21519** (CVSS 7.8) - Windows Desktop Window Manager (DWM) type confusion elevation of privilege; local low-privilege attackers gain SYSTEM without user interaction.

5. **CVE-2026-21533** (CVSS 7.8) - Windows Remote Desktop Services EoP via improper privilege management.

6. **CVE-2026-21525** (CVSS 6.2) - Windows Remote Access Connection Manager denial-of-service; unauthenticated local trigger.

### Chrome Zero-Day

- **CVE-2026-2441** - First Chrome zero-day of 2026; enables code execution via malicious webpages. Users should ensure Chrome is updated immediately.

### BeyondTrust Active Exploitation

- **CVE-2026-1731** - RCE in BeyondTrust Remote Support <= 25.3.1 via exposed WebSocket handler; CISA/FBI confirmed ransomware groups now weaponizing this flaw. VShell backdoor and SparkRAT observed post-exploitation. Palo Alto Unit 42 published analysis.

---

## Malware & Ransomware

### Active Ransomware Campaigns

**Qilin Ransomware**
- Most prolific active group in 2026 with 1,480+ total victims; ~190 claimed in 2026 YTD
- Targeting healthcare, education, and critical infrastructure sectors globally

**Hellcat Ransomware**
- Compromised Ascom's technical ticketing system
- Exfiltrated ~44 GB including source code, invoices, and confidential documents

**Safeway Ransomware Group**
- Claimed responsibility for the Conduent breach; 8+ TB of data stolen
- Multi-state enforcement and federal class actions now underway

### Ransomware Incident: Advantest Corporation
- Japanese chip testing giant hit with ransomware on February 15, 2026
- Unauthorized access to portions of IT network; forensic investigation ongoing
- Supply chain risk: Advantest is a critical supplier to global semiconductor manufacturers

### Trend: BeyondTrust RCE Now Ransomware-Weaponized
- CISA confirmed ransomware operators are exploiting CVE-2026-1731 in BeyondTrust Remote Support
- Organizations still running versions <= 25.3.1 should patch immediately or take offline

### Industry Context
- 2025 saw ~6,500 ransomware incidents (second-highest ever, up 47% in two years)
- Smaller, agile groups are rapidly adopting enterprise-grade playbooks from larger gangs

---

## Threat Actors

### UNC3886 (China-Nexus APT) - Singapore Telecom Campaign
- **Operation CYBER GUARDIAN** disclosed February 9, 2026 by Singapore CSA and IMDA
- All four major Singapore telecoms targeted: M1, SIMBA Telecom, Singtel, StarHub
- **TTPs**: Zero-day exploit to bypass perimeter firewalls; rootkit deployment for persistent, undetected access
- No evidence of data exfiltration or service disruption confirmed
- UNC3886 previously linked to Juniper router implants and VMware ESXi exploitation

### Nation-State Threat Landscape (2026)
- Security experts warn that a decade of infrastructure pre-positioning is now bearing fruit
- Cyberwarfare activity expected to escalate significantly through 2026
- Telecom, energy, and financial sectors remain primary nation-state targets

---

## Data Breaches

### Conduent (CRITICAL - Potentially Largest in U.S. History)
- **Affected:** 25+ million Americans across multiple states
- **States confirmed:** Oregon (10.5M), Texas (15.4M), Wisconsin, others still reporting
- **Data exposed:** Names, dates of birth, addresses, Social Security numbers, health insurance info, medical records
- **Incident window:** October 21, 2024 - January 13, 2025
- **Attribution:** Safeway ransomware group; 8+ TB of data stolen
- **Status:** 10+ federal class action lawsuits filed; multi-state enforcement actions underway
- Texas AG describes as "potentially the largest breach in U.S. history"

### Odido (Dutch Telecommunications)
- **Affected:** 6+ million accounts
- **Data exposed:** Names, phone numbers, email addresses, bank account numbers, passport numbers
- **Discovery:** February 7, 2026; unauthorized access terminated

### Cottage Hospital
- **Affected:** 1,600+ individuals
- **Data exposed:** Names, SSNs, driver's license numbers, bank account information
- **Incident date:** October 2025; discovered December 2025; notification February 2026

### IRS Data Disclosure
- IRS improperly shared confidential tax data of thousands with DHS/ICE
- ICE submitted requests for names/addresses of 1.28 million individuals
- Legal challenges ongoing over the scope and legality of the data sharing

### Healthcare Sector
- MedRevenu and EyeCare Partners disclosed separate data breaches in February 2026
- Nova Biomedical Corp: 10,764 victims affected from a July 2025 breach (newly disclosed)

---

## Vendor Advisories

### Microsoft (February 2026 Patch Tuesday - February 10)
- **58 vulnerabilities** patched; **6 zero-days** actively exploited; **5 critical** severity
- Priority patches: CVE-2026-21510 (SmartScreen), CVE-2026-21519 (DWM EoP), CVE-2026-24300 (Azure Front Door CVSS 9.8)
- Outlook Preview Pane attack vector confirmed for CVE-2026-21260
- [Full analysis - BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)

### Google Chrome
- Zero-day CVE-2026-2441 patched - update Chrome immediately
- [Malwarebytes advisory](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)

### Apple
- Security patches released as part of February 2026 cycle; zero-day threats persist
- Ensure all Apple devices are running latest OS versions

### Cisco
- Updates released for Secure Web Appliance and Cisco Meeting Management
- [Govinfo Security](https://www.govinfosecurity.com/no-rest-in-2026-as-patch-alerts-amass-for-cisco-hpe-n8n-a-30482)

### Adobe
- 9 bulletins addressing 44 unique CVEs across various Adobe products

### SAP, Intel, VMware, Fortinet, Check Point
- Part of the 60+ vendor February patch cycle
- [Rescana February Patch Report](https://www.rescana.com/post/february-2026-security-patch-report-microsoft-sap-intel-adobe-and-60-vendors-address-critical)

---

## Recommended Actions

**IMMEDIATE (Within 24 Hours)**

1. **Patch BeyondTrust Remote Support** - CVE-2026-1731 (RCE) is actively exploited by ransomware groups; upgrade from <= 25.3.1 or take offline immediately
2. **Apply Microsoft February Patch Tuesday** - 6 zero-days actively exploited; prioritize CVE-2026-21510 (SmartScreen), CVE-2026-21519 (DWM EoP), and CVE-2026-21513 (MSHTML)
3. **Update Google Chrome** - CVE-2026-2441 zero-day enables code execution via malicious webpages
4. **Patch RoundCube Webmail** - CVE-2025-49113 (deserialization) and CVE-2025-68461 (XSS) both actively exploited per CISA KEV

**SHORT-TERM (Within 72 Hours)**

5. **Patch n8n** if used - CVE-2026-25049 (CVSS 9.4) allows system command execution via malicious workflows
6. **Audit Serv-U deployments** - CVE-2025-40540 (CVSS 9.1) enables RCE as privileged account
7. **Review SolarWinds Web Help Desk** - CVE-2025-40551 (deserialization) added to KEV Feb 3
8. **Patch Soliton FileZen** - CVE-2026-25108 (OS command injection) added to KEV Feb 24
9. **Audit Sangoma FreePBX deployments** - CVE-2019-19006 and CVE-2025-64328 both added to KEV

**STRATEGIC**

10. **Assess Conduent exposure** - If your organization uses Conduent services or state benefit systems in Oregon, Texas, or Wisconsin, initiate breach response protocols
11. **Telecom sector defenders** - Review UNC3886 TTPs (zero-day firewall bypass + rootkit persistence); verify perimeter integrity and hunt for rootkits on network appliances
12. **Ransomware resilience** - With Qilin claiming 190+ 2026 victims, test backup integrity and offline backup availability
13. **n8n workflow audit** - If self-hosting n8n, audit all workflow nodes for malicious content; apply CVE-2026-25049 patch

---

## Sources

- [CISA KEV - Feb 24 Addition](https://www.cisa.gov/news-events/alerts/2026/02/24/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV - Feb 20 Additions (RoundCube)](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 10 Additions (Microsoft)](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 3 Additions](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA Flags Four Flaws Under Active Exploitation - The Hacker News](https://thehackernews.com/2026/02/cisa-flags-four-security-flaws-under.html)
- [Microsoft Feb 2026 Patch Tuesday - BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [6 Zero-Days Patched by Microsoft - SecurityWeek](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)
- [February 2026 Patch Tuesday - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days/)
- [Zero Day Initiative - Feb 2026 Security Update Review](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
- [Patch Tuesday - Krebs on Security](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [February 2026 Patch Tuesday - CrowdStrike Analysis](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-february-2026/)
- [Chrome Zero-Day CVE-2026-2441 - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)
- [BeyondTrust CVE-2026-1731 - Palo Alto Unit 42](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [BeyondTrust RCE Now Exploited in Ransomware - BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-beyondtrust-rce-flaw-now-exploited-in-ransomware-attacks/)
- [Critical n8n Flaw CVE-2026-25049 - The Hacker News](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [Windows Admin Center CVE-2026-26119 - Help Net Security](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)
- [Serv-U Type Confusion CVE-2025-40540 - TheHackerWire](https://www.thehackerwire.com/serv-u-type-confusion-critical-rce-cve-2025-40540/)
- [Singapore UNC3886 Operation CYBER GUARDIAN - Computer Weekly](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [Singapore CSA Press Release - UNC3886](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [Cyber Insights 2026: Nation State Threats - SecurityWeek](https://www.securityweek.com/cyber-insights-2026-cyberwar-and-rising-nation-state-threats/)
- [Conduent Breach Grows to 25M - TechCrunch](https://techcrunch.com/2026/02/24/conduent-data-breach-grows-affecting-at-least-25m-people/)
- [Conduent Breach - Largest in US History - WRDW](https://www.wrdw.com/2026/02/20/conduent-data-breach-could-be-largest-us-history/)
- [Conduent Data Breach 8TB Stolen - CybersecurityNews](https://cybersecuritynews.com/conduent-data-breach/)
- [Conduent Breach 25M Exposed - PYMNTS](https://www.pymnts.com/cybersecurity/2026/wisconsin-reveals-conduent-breach-affected-25-million-americans/)
- [Advantest Ransomware Attack - SecurityWeek](https://www.securityweek.com/chip-testing-giant-advantest-hit-by-ransomware/)
- [10 Ransomware Groups 2025 Trends - Cyble](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)
- [CYFIRMA Weekly Intelligence Report Feb 20 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [Odido Data Breach - Privacy Guides Roundup](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [Cottage Hospital Data Breach - Valley News](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [IRS Data Disclosure - Grand Pinnacle Tribune](https://evrimagaci.org/gpt/irs-data-breach-sparks-outcry-over-immigration-deal-528626)
- [MedRevenu & EyeCare Partners Breach - HIPAA Journal](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [February 2026 Security Patch Report - Rescana](https://www.rescana.com/post/february-2026-security-patch-report-microsoft-sap-intel-adobe-and-60-vendors-address-critical)
- [No Rest in 2026 - Cisco, HPE, n8n Patches - GovInfoSecurity](https://www.govinfosecurity.com/no-rest-in-2026-as-patch-alerts-amass-for-cisco-hpe-n8n-a-30482)
- [Apple and Google Zero-Day Patches Persist into 2026 - Tech Channels](https://www.tech-channels.com/breaking-news/apple-and-google-push-out-security-patches-as-zero-day-threats-persist-into-2026)
- [WEF Cyberthreats to Watch in 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
