# Cyber Threat Intelligence Report
**Date:** 2026-02-28
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0228

---

## Executive Summary

- **Microsoft February 2026 Patch Tuesday** patched 58 flaws including 6 actively exploited zero-days across Windows Shell, MSHTML, Word, and RDP - immediate patching required
- **Cisco Catalyst SD-WAN (CVE-2026-20127)** critical auth bypass actively exploited in the wild; CISA issued emergency directive requiring federal patches by 2026-02-27
- **Juniper PTX Junos OS Evolved (CVE-2026-21902)** critical unauthenticated root takeover flaw disclosed 2026-02-26 - patch immediately
- **UNC3886 (China-nexus APT)** conducted targeted campaign against Singapore's four major telecom operators using zero-day perimeter firewall exploits and rootkits
- **North Korean Lazarus group** pivoting to Medusa ransomware for continued healthcare sector extortion attacks in the US
- **Conduent breach** - approximately 8 TB of sensitive data stolen; one of the largest reported US data breaches in recent years
- **Odido (Netherlands)** telecom breach exposing 6+ million customer records including bank account numbers and passport numbers

---

## Critical Vulnerabilities

### CISA KEV Additions - February 2026

| CVE | Product | Type | Added |
|-----|---------|------|-------|
| CVE-2026-20127 | Cisco Catalyst SD-WAN | Auth Bypass | 2026-02-25 |
| CVE-2026-25108 | Soliton FileZen | OS Command Injection | 2026-02-24 |
| CVE-2025-49113 | RoundCube Webmail | Deserialization | 2026-02-20 |
| CVE-2025-68461 | RoundCube Webmail | XSS | 2026-02-20 |
| CVE-2026-21510 | Microsoft Windows Shell | Security Feature Bypass | 2026-02-10 |
| CVE-2026-21513 | Microsoft MSHTML Framework | Security Feature Bypass | 2026-02-10 |
| CVE-2026-21514 | Microsoft Office Word | Security Feature Bypass | 2026-02-10 |
| CVE-2026-21519 | Microsoft Windows DWM | Type Confusion / EoP | 2026-02-10 |
| CVE-2026-21525 | Microsoft Windows RACM | Null Pointer Dereference | 2026-02-10 |
| CVE-2026-21533 | Windows Remote Desktop Services | EoP | 2026-02-10 |
| CVE-2025-40551 | SolarWinds Web Help Desk | Deserialization | 2026-02-03 |
| CVE-2021-39935 | GitLab CE/EE | SSRF | 2026-02-03 |
| CVE-2019-19006 | Sangoma FreePBX | Improper Auth | 2026-02-03 |
| CVE-2025-64328 | Sangoma FreePBX | OS Command Injection | 2026-02-03 |

### Additional Critical CVEs (CVSS 9+)

| CVE | Product | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2026-21902 | Juniper PTX Junos OS Evolved | Critical | Unauthenticated root takeover via exposed internal port |
| CVE-2026-2749 | Centreon Open Tickets | 9.9 | Critical flaw on Central Server Linux (disclosed 2026-02-27) |
| CVE-2026-2251 | Xerox FreeFlow Core | 9.8 | Path traversal to unauthenticated RCE (disclosed 2026-02-27) |
| CVE-2026-25049 | n8n Workflow System | 9.4 | System command execution via malicious workflows |
| CVE-2026-20781 | OCPP WebSocket | Critical | WebSocket impersonation in EV charging infrastructure |

---

## Exploits & Zero-Days

### Microsoft February 2026 Patch Tuesday - 6 Actively Exploited Zero-Days

All six were added to CISA KEV on 2026-02-10:

1. **CVE-2026-21510** - Windows Shell SmartScreen bypass; triggered by opening malicious link/shortcut file
2. **CVE-2026-21513** - MSHTML Framework security feature bypass; affects Windows and multiple applications
3. **CVE-2026-21514** - Microsoft Word security feature bypass; requires opening malicious `.docx` - Preview Pane is confirmed attack vector
4. **CVE-2026-21519** - Windows Desktop Window Manager EoP; low-privilege authenticated attacker, no user interaction required
5. **CVE-2026-21525** - Windows Remote Access Connection Manager DoS; unauthenticated local attacker, low complexity
6. **CVE-2026-21533** - Windows RDS EoP via improper privilege management

Three (CVE-2026-21513, CVE-2026-21510, CVE-2026-21514) were also publicly disclosed prior to patching.

### Chrome Zero-Day

- **CVE-2026-2441** - First Chrome zero-day of 2026; allows code execution via malicious webpages. Google issued emergency out-of-band update to stable channel - update immediately.

### Apple Zero-Day

- **CVE-2026-20700** - Memory corruption zero-day affecting iPhone, iPad, Mac, and Apple Watch. Critical security update released; patch all Apple devices immediately.

---

## Malware & Ransomware

### Active Campaigns

**Qilin Ransomware**
- Claimed attack on Conpet in February 2026
- Continues to be one of the most active ransomware groups in 2026

**LockBit**
- Active campaigns tracked in late February 2026 per Malware Patrol threat reports

**Medusa Ransomware (North Korea-linked)**
- Lazarus group has pivoted to deploying Medusa ransomware
- Continued targeting of US healthcare sector for extortion
- Blurs line between nation-state espionage and financially motivated attacks

**Conduent Attack**
- Approximately 8 TB of sensitive data stolen
- One of the largest reported US data breaches in recent years

### Trend Data (2025 Retrospective, Relevant for 2026 Planning)
- Ransomware victim claims up 50% YoY in 2025 - most active year on record
- Active ransomware groups surged 49% YoY (ecosystem fragmentation)
- Ransomware payments fell ~8% to ~$820M in 2025 - victim payment rate hit all-time low of 28%
- AI-powered attacks are compressing attack timelines dramatically in 2026

---

## Threat Actors

### UNC3886 (China-Nexus APT)
- **Target:** Singapore telecommunications sector (all four major operators: M1, SIMBA, Singtel, StarHub)
- **Disclosed:** 2026-02-09 by Singapore's Cyber Security Agency (CSA)
- **TTPs:** Zero-day exploit to bypass perimeter firewalls; rootkit deployment for persistent, undetected access
- **Data Exfiltrated:** Small amount of network-related technical data; no customer records confirmed compromised
- **Response:** Singapore mounted its largest-ever multi-agency cyber operation to oust the actor
- **Attribution:** UNC3886 is a China-nexus cyber espionage group (Mandiant designation)

### North Korean Lazarus Group
- Pivoting to Medusa ransomware for financially motivated attacks
- Continued focus on US healthcare sector
- Represents blending of nation-state and financially motivated threat actor behaviors

### Iran
- CSIS analysis: Iran operating coordinated cyber threat landscape beyond hacktivism
- Coordinated campaigns spanning espionage, sabotage, and information operations

---

## Data Breaches

| Organization | Sector | Records/Impact | Vector | Disclosed |
|---|---|---|---|---|
| Conduent | Business Services | ~8 TB data stolen | Ransomware | Feb 2026 |
| Odido (Netherlands) | Telecom | 6M+ accounts (names, phone, email, IBAN, passport) | Cyberattack | ~Feb 7, 2026 |
| Harvard University | Education | ~115,000 alumni records | Vishing (ShinyHunters) | Feb 4, 2026 |
| IRS / DHS | Government | 1.28M individuals' tax data shared with ICE | Policy/Improper Disclosure | Feb 12, 2026 |
| Cottage Hospital | Healthcare | 1,600+ individuals (SSN, DL, bank info) | Unknown - Oct 2025 breach | Feb 6, 2026 |
| Substack | Media/Tech | User phone numbers, emails, other PII | Unauthorized access | Feb 3, 2026 |
| MedRevenu / EyeCare Partners | Healthcare | Undisclosed | Unknown | Feb 2026 |

---

## Vendor Advisories

### Microsoft - February 2026 Patch Tuesday (2026-02-10)
- **58 total vulnerabilities** patched; 6 actively exploited zero-days
- Affected: Windows Shell, MSHTML, Office Word, DWM, Remote Access, RDS, Outlook (Preview Pane vector confirmed)
- **Action:** Apply all February 2026 cumulative updates immediately

### Cisco
- **CVE-2026-20127** (Catalyst SD-WAN): Critical auth bypass - CISA emergency directive issued; federal deadline was 2026-02-27
- Additional advisories for Secure Web Appliance and Cisco Meeting Management
- **Action:** Patch Catalyst SD-WAN controller/manager immediately

### Juniper
- **CVE-2026-21902** (PTX Junos OS Evolved): Unauthenticated root takeover - disclosed 2026-02-26
- **Action:** Apply Juniper patches; restrict access to internal services

### Google
- **CVE-2026-2441** Chrome zero-day: Emergency stable channel update released
- **Action:** Update Chrome to latest stable version immediately

### Apple
- **CVE-2026-20700**: Memory corruption zero-day affecting all major Apple platforms
- **Action:** Apply latest iOS, iPadOS, macOS, and watchOS updates

### Additional Vendors (February 2026 Patch Cycle)
- SAP, Intel, Adobe, VMware, Fortinet, Check Point, QNAP, Samba - all released security advisories
- Over 60 vendors issued patches this cycle
- **Action:** Review vendor-specific advisories for products in your environment

### SolarWinds
- **CVE-2025-40551** (Web Help Desk): Deserialization vulnerability added to CISA KEV 2026-02-03
- **Action:** Patch SolarWinds Web Help Desk immediately if in use

### RoundCube Webmail
- CVE-2025-49113 (Deserialization) and CVE-2025-68461 (XSS) both added to CISA KEV 2026-02-20
- **Action:** Update RoundCube to latest patched version immediately

---

## Recommended Actions

**Immediate (within 24 hours)**
1. Patch **Cisco Catalyst SD-WAN** (CVE-2026-20127) - CISA emergency directive, active exploitation confirmed
2. Apply **Microsoft February 2026 Patch Tuesday** updates - 6 zero-days actively exploited
3. Update **Chrome** and **Apple** devices - actively exploited zero-days in the wild
4. Patch **RoundCube Webmail** - both CVEs added to CISA KEV
5. Assess **SolarWinds Web Help Desk** exposure and apply patches

**Short-Term (within 72 hours)**
6. Evaluate **Juniper PTX Junos OS Evolved** systems for CVE-2026-21902 exposure; restrict network access to internal services
7. Patch **n8n workflow instances** (CVE-2026-25049) if internet-exposed
8. Assess **Xerox FreeFlow Core** exposure for CVE-2026-2251 (unauthenticated RCE)
9. Review **Centreon Open Tickets** deployments (CVE-2026-2749, CVSS 9.9)
10. Audit EV charging infrastructure for **OCPP WebSocket** exposure (CVE-2026-20781)

**Ongoing**
11. Monitor for **UNC3886 IOCs** - particularly if you operate telecom, critical infrastructure, or ISP services; inspect perimeter firewall logs for anomalous internal routing behavior
12. Implement **healthcare sector ransomware controls** - Lazarus/Medusa actively targeting healthcare; ensure offline backups, network segmentation, and IR plans are current
13. Validate that **GitLab CE/EE** (CVE-2021-39935) and **Sangoma FreePBX** (CVE-2019-19006, CVE-2025-64328) are patched - legacy CVEs added to KEV indicate active exploitation in the wild
14. Review **IRS/government data sharing** policies if handling PII - improper disclosure controls a growing compliance risk
15. Apply broader **February 2026 vendor patches** for SAP, Adobe, VMware, Fortinet, QNAP in your environment

---

## Sources

- [CISA KEV - Feb 3 Additions](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 10 Additions](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 20 Additions](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 24 Additions](https://www.cisa.gov/news-events/alerts/2026/02/24/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Cisco Catalyst SD-WAN CVE-2026-20127 - Rapid7](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-vulnerability-exploited-in-the-wild-cve-2026-20127/)
- [Juniper PTX CVE-2026-21902 - Threat Intel Report](https://www.threatintelreport.com/2026/02/26/vulnerabilities_exploits/critical-juniper-ptx-junos-os-evolved-flaw-enables-unauthenticated-root-takeover-cve-2026-21902/)
- [Centreon CVE-2026-2749 - TheHackerWire](https://www.thehackerwire.com/centreon-open-tickets-critical-vulnerability-cve-2026-2749/)
- [Xerox FreeFlow CVE-2026-2251 - TheHackerWire](https://www.thehackerwire.com/xerox-freeflow-core-path-traversal-to-rce-cve-2026-2251/)
- [n8n CVE-2026-25049 - The Hacker News](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [OCPP CVE-2026-20781 - TheHackerWire](https://www.thehackerwire.com/critical-ocpp-websocket-impersonation-cve-2026-20781/)
- [Microsoft February 2026 Patch Tuesday - BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [6 Zero-Days - SecurityWeek](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)
- [February 2026 Patch Tuesday - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days/)
- [Zero Day Initiative - February 2026 Review](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
- [Chrome Zero-Day CVE-2026-2441 - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)
- [Krebs on Security - February 2026 Patch Tuesday](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [Help Net Security - February 2026 Patch Tuesday](https://www.helpnetsecurity.com/2026/02/11/february-2026-patch-tuesday/)
- [SecPod - Microsoft February 2026 Analysis](https://www.secpod.com/blog/microsofts-february-2026-patch-tuesday-six-zero-days-patched-amid-growing-exploit-activity/)
- [Apple & Google Patches - Tech Channels](https://www.tech-channels.com/breaking-news/apple-and-google-push-out-security-patches-as-zero-day-threats-persist-into-2026)
- [February 2026 Security Patch Report - Rescana](https://www.rescana.com/post/february-2026-security-patch-report-microsoft-sap-intel-adobe-and-60-vendors-address-critical)
- [UNC3886 Singapore Telecom Operation - Computer Weekly](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [CSA Singapore - UNC3886 Press Release](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [Ransomware Payments 2025 - The Register](https://www.theregister.com/2026/02/27/ransomware_chainalysis/)
- [Ransomware Trends 2025/2026 - BlackFog](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [IBM X-Force Threat Index 2026](https://uk.newsroom.ibm.com/ibm-2026-x-force-threat-index)
- [Late February Threat Reports - Malware Patrol](https://www.malwarepatrol.net/late-february-2026-cyber-threat-reports/)
- [WEF 2026 Cyber Threats](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [Harvard Breach - InfoStealers](https://www.infostealers.com/article/a-technical-and-ethical-post-mortem-of-the-feb-2026-harvard-university-shinyhunters-data-breach/)
- [Cottage Hospital Breach - Valley News](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [IRS Data Breach - evrimagaci](https://evrimagaci.org/gpt/irs-data-breach-sparks-outcry-over-immigration-deal-528626)
- [Data Breach Roundup Jan 30-Feb 5 - Privacy Guides](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [Data Breach Brief Week of Feb 11 - For The People](https://www.forthepeople.com/blog/data-breach-brief-week-february-11th-2026/)
- [SharkStriker February 2026 Breach Tracker](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)
- [Breachsense 2026 Data Breaches](https://www.breachsense.com/breaches/)
- [February 2026 Cybersecurity Roundup - Advanced IT Technologies](https://www.advancedittechnologies.com/post/february-2026-cybersecurity-news-roundup-major-breaches-ai-driven-attacks-critical-vulnerabiliti)
- [CVE Details - February 2026](https://www.cvedetails.com/vulnerability-list/year-2026/month-2/February.html)
- [Absolute Security - February 2026 Patch Tuesday](https://www.absolute.com/blog/microsoft-february-2026-patch-tuesday-critical-fixes-updates)
- [Zecurit - Patch Tuesday February 2026](https://zecurit.com/endpoint-management/patch-tuesday/)
- [2026 Data Breaches - PKWARE](https://www.pkware.com/blog/2026-data-breaches)
- [HIPAA Journal - MedRevenu & EyeCare Partners](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
