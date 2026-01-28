# Cyber Threat Intelligence Report
**Date:** January 28, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0128

---

## Executive Summary

- **NEW**: Google warns nation-state actors (Russia, China) actively exploiting WinRAR CVE-2025-8088 for initial access
- **NEW**: Phantom Taurus - new Chinese APT discovered targeting governments and military across Africa, Middle East, and Asia
- **NEW**: Russian Sandworm attributed to "largest cyber attack" on Poland's power grid (late December 2025)
- **NEW**: North Korean Konni group using AI-generated PowerShell malware targeting blockchain developers
- **NEW**: Brightspeed investigating breach claims - 1M+ customers allegedly affected by Crimson Collective
- **UPDATE**: CVE-2026-21509 Microsoft Office zero-day - CISA deadline February 16, 2026
- **UPDATE**: Secure Boot certificate expiration (June 2026) - CVE-2026-21265 requires urgent planning

---

## Critical Vulnerabilities

### NEW: WinRAR CVE-2025-8088 - Nation-State Exploitation

**Severity:** Critical (Actively Exploited by APTs)
**Product:** RARLAB WinRAR
**Status:** Patched - Active exploitation by Russia and China-linked actors

Google warned on January 28, 2026 that multiple threat actors, including nation-state adversaries from Russia and China, are exploiting this vulnerability to establish initial access and deploy payloads.

**Remediation:** Update WinRAR immediately; hunt for indicators of compromise

---

### NEW: Oracle Critical Patch Update - January 2026

**Total Patches:** 337 security patches addressing 158 unique CVEs
**Critical Highlights:**

| CVE | Product | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2026-21962 | Oracle HTTP Server / WebLogic Proxy | **10.0** | Maximum remote exploitation risk |
| CVE-2026-21945 | Java Environments | High | SSRF without authentication |

- 38 new patches for Oracle Financial Services Applications
- 33 vulnerabilities remotely exploitable without authentication

**Source:** [Oracle Critical Patch Update - January 2026](https://www.oracle.com/security-alerts/cpujan2026.html)

---

### NEW: n8n Workflow Automation - CVE-2025-68668

**Severity:** 9.9 CVSS (Critical)
**Product:** n8n workflow automation platform
**Affected Versions:** 1.0.0 to 2.0.0 (exclusive)
**Fixed Version:** 2.0.0

Authenticated attacker can execute arbitrary system commands on the underlying host.

**Remediation:** Upgrade to n8n version 2.0.0 immediately

**Source:** [The Hacker News - n8n Vulnerability](https://thehackernews.com/2026/01/new-n8n-vulnerability-99-cvss-lets.html)

---

### NEW: Fortinet Authentication Bypass

**Product:** FortiAnalyzer 7.6.0-7.6.5, FortiManager, FortiOS
**Type:** Authentication Bypass
**Condition:** FortiCloud SSO authentication enabled

Attacker with FortiCloud account and registered device can log into other devices registered to other accounts.

**Remediation:** Review FortiCloud SSO configuration; apply patches when available

---

### NEW: Secure Boot Certificate Expiration Warning - CVE-2026-21265

**Type:** Certificate Expiration (Operational Impact)
**Deadline:** June 2026
**Impact:** Critical operational disruption

Security experts warn CISOs must address this before certificates expire in June. Organizations that haven't prepared will find:
- Secure Boot no longer operational
- Windows boot manager vulnerabilities become exploitable
- Potential boot failures

**Action Required:** Begin remediation planning now

**Source:** [CrowdStrike Patch Tuesday Analysis](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/)

---

## Threat Actors

### NEW: Phantom Taurus - Chinese APT

**Attribution:** China (previously undocumented)
**Targets:** Government agencies, embassies, military operations
**Regions:** Africa, Middle East, Asia
**Status:** Active

**Distinctive Characteristics:**
- Surgical precision targeting high-value systems directly
- Unprecedented persistence
- Highly sophisticated, custom-built toolkit
- Bypasses typical social engineering of end users

"Phantom Taurus sets itself apart from other Chinese APTs through its surgical precision, unprecedented persistence, and sophisticated custom toolkit."

**Source:** [Dark Reading - New China APT](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)

---

### NEW: Sandworm - Poland Power Grid Attack

**Attribution:** Russia (GRU Unit 74455)
**Target:** Poland's power system
**Timing:** Last week of December 2025
**Status:** Attack unsuccessful

Described as "the largest cyber attack" targeting Poland's power system. Poland's energy minister confirmed the attack was unsuccessful.

**Significance:** Continued Russian targeting of critical infrastructure in NATO countries

---

### NEW: Konni - AI-Generated Malware Campaign

**Attribution:** North Korea
**Targets:** Developers and engineering teams in blockchain sector
**Regions:** Japan, Australia, India (expanded from traditional South Korea, Russia, Ukraine, Europe)
**Method:** Phishing with AI-generated PowerShell malware

First documented use of AI-generated malware by Konni group, indicating evolution in DPRK cyber capabilities.

---

### UPDATE: APT40 - Blue Pacific Region Advisory

**Attribution:** China
**Warning Issued By:** Government of Samoa
**Targets:** Sensitive networks in Blue Pacific region

Recent campaigns use:
- Stealthy fileless malware
- Registry-based loading techniques

---

### Iranian Threat Landscape Evolution

Iran now presents a coordinated cyber threat combining:
- State-sponsored APTs (IRGC and MOIS)
- Expanding hacktivist ecosystem

**June 2025 Israel-Iran Conflict Analysis:**
- 12-day conflict demonstrated Iran's hacktivist ecosystem at scale
- Analysis of 250,000+ Telegram messages from 178+ groups
- Rapid mobilization with kinetic hostilities
- Active groups: Fatimion Cyber Team, Cyber Fattah, Cyber Islamic Resistance

**Source:** [CSIS - Iran's Coordinated Cyber Threat](https://www.csis.org/blogs/strategic-technologies-blog/beyond-hacktivism-irans-coordinated-cyber-threat-landscape)

---

## Data Breaches

### NEW: Brightspeed - Under Investigation

**Victim:** Brightspeed (major US fiber broadband company)
**Threat Actor:** Crimson Collective (extortion gang)
**Status:** Investigation in progress
**Claimed Records:** 1+ million customers

**Alleged Data Exposed:**
- PII (personally identifiable information)
- Address information
- User account information (names, emails, phone numbers)
- Payment history
- Some payment card information
- Appointment/order records

**Source:** [SharkStriker - January 2026 Breaches](https://sharkstriker.com/blog/data-breaches-in-january-2026/)

---

### NEW: Manage My Health - 120K Patients

**Victim:** Manage My Health (healthcare platform)
**Date Discovered:** January 3, 2026
**Patients Affected:** 120,000
**Documents Compromised:** 400,000

**Data Exposed:**
- Hospital discharge summaries
- Specialist referrals
- Uploaded medical documents

**Source:** [Privacy Guides - Data Breach Roundup](https://www.privacyguides.org/news/2026/01/09/data-breach-roundup-jan-2-jan-8-2026/)

---

### NEW: Covenant Health - Revised Impact

**Victim:** Covenant Health organization
**Originally Reported:** May 2025
**Updated Impact:** ~500,000 individuals (revised upward)

---

### NEW: HealthBridge Chiropractic - Ransomware

**Victim:** HealthBridge Chiropractic (Philadelphia multispecialty hospital)
**Threat Actor:** Qilin ransomware group
**Date:** January 6, 2026
**Type:** Ransomware with data compromise

---

### Active Ransomware Groups This Week

| Group | Recent Activity |
|-------|-----------------|
| Qilin | HealthBridge Chiropractic |
| Akira | Multiple targets |
| LockBit | Active operations |
| INC_RANSOM | Observed Jan 15-16 |
| DragonForce | Observed Jan 15-16 |
| Crimson Collective | Brightspeed claims |

---

## Regulatory Updates

### NEW: Data Breach Notification Law Changes - January 1, 2026

**California:**
- Businesses must notify individuals within **30 calendar days** after breach discovery
- Previously no specific timeline

**Oklahoma:**
- Broadened definition of personal information triggering notification
- Now includes:
  - Government-issued identification numbers
  - Unique electronic identifiers
  - Biometric data (fingerprints, iris scans)

**Source:** [Eye On Privacy - 2026 Data Breach Laws](https://www.eyeonprivacy.com/2025/10/2026-data-breach-law-updates-california-and-oklahoma/)

---

## Vendor Advisories

### January 28, 2026 Priority Patches

| Vendor | Product | CVE | CVSS | Status |
|--------|---------|-----|------|--------|
| Oracle | HTTP Server/WebLogic | CVE-2026-21962 | **10.0** | Patch Available |
| Oracle | Java | CVE-2026-21945 | High | Patch Available |
| n8n | Workflow Automation | CVE-2025-68668 | **9.9** | Fixed in 2.0.0 |
| RARLAB | WinRAR | CVE-2025-8088 | Critical | **APT Exploitation** |
| Fortinet | FortiAnalyzer/Manager | TBD | High | Review SSO Config |
| Mozilla | Firefox | CVE-2026-0891/0892 | High | Update to 147 |

### Continuing KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | **February 3, 2026** |
| CVE-2026-20045 | Cisco Unified Communications | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-54313 | eslint-config-prettier | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| VMware | vCenter Server | February 13, 2026 |
| CVE-2026-21509 | Microsoft Office | **February 16, 2026** |

---

## Recommended Actions

### Immediate Priority (Critical)

1. **WinRAR** - Update immediately; nation-state actors actively exploiting CVE-2025-8088
2. **Oracle** - Apply January 2026 CPU patches, especially CVE-2026-21962 (CVSS 10.0)
3. **n8n** - Upgrade to version 2.0.0 to fix CVE-2025-68668 (CVSS 9.9)
4. **Microsoft DWM** - CISA KEV deadline **February 3, 2026** for CVE-2026-20805
5. **Fortinet** - Review FortiCloud SSO authentication configurations

### High Priority

6. **Secure Boot Planning** - Begin CVE-2026-21265 remediation before June 2026 deadline
7. **Firefox** - Update to version 147 or ESR 140.7
8. **Oracle Financial Services** - Prioritize 38 new patches

### Threat Hunting

9. **Phantom Taurus** - Government/military organizations should hunt for indicators
10. **Konni AI Malware** - Blockchain/developer teams in Japan, Australia, India should increase vigilance
11. **WinRAR Exploitation** - Search for post-exploitation indicators from RAR file payloads

### Compliance

12. **California/Oklahoma Businesses** - Update breach notification procedures to meet new 30-day timeline

---

## Sources

- [Google Warns of WinRAR Nation-State Exploitation](https://www.google.com/threat-analysis-group)
- [Dark Reading - New China APT Phantom Taurus](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)
- [Oracle Critical Patch Update - January 2026](https://www.oracle.com/security-alerts/cpujan2026.html)
- [The Hacker News - n8n Vulnerability](https://thehackernews.com/2026/01/new-n8n-vulnerability-99-cvss-lets.html)
- [CrowdStrike - January 2026 Patch Tuesday](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/)
- [Krebs on Security - Patch Tuesday January 2026](https://krebsonsecurity.com/2026/01/patch-tuesday-january-2026-edition/)
- [CSIS - Iran's Coordinated Cyber Threat](https://www.csis.org/blogs/strategic-technologies-blog/beyond-hacktivism-irans-coordinated-cyber-threat-landscape)
- [SharkStriker - January 2026 Data Breaches](https://sharkstriker.com/blog/data-breaches-in-january-2026/)
- [Privacy Guides - Data Breach Roundup](https://www.privacyguides.org/news/2026/01/09/data-breach-roundup-jan-2-jan-8-2026/)
- [Eye On Privacy - 2026 Data Breach Laws](https://www.eyeonprivacy.com/2025/10/2026-data-breach-law-updates-california-and-oklahoma/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Zero Day Initiative - January 2026 Review](https://www.thezdi.com/blog/2026/1/13/the-january-2026-security-update-review)
- [Cyble - Threat Actor Trends 2025/2026](https://cyble.com/knowledge-hub/top-10-threat-actor-trends-of-2025/)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in the January 27, 2026 report and are not repeated unless updated:
- CISA KEV January 26 additions (5 vulnerabilities)
- CVE-2026-21509 Microsoft Office zero-day (updated deadline only)
- ShinyHunters Okta SSO campaign
- Crunchbase, SoundCloud, Betterment breaches
- Under Armour / Everest ransomware breach
- BlackCat/Alphv affiliate arrests
- CVE-2026-0625 D-Link DSL router exploitation

---

*Report generated: 2026-01-28*
*Next report: 2026-01-29*
*Classification: TLP:CLEAR*
