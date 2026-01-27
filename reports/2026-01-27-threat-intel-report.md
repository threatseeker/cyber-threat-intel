# Cyber Threat Intelligence Report
**Date:** January 27, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0127

---

## Executive Summary

**CISA adds five vulnerabilities to KEV Catalog** (January 26) including Microsoft Office zero-day CVE-2026-21509, two SmarterMail flaws, Linux Kernel integer overflow, and GNU InetUtils argument injection. **Microsoft releases out-of-band patch** for actively exploited Office zero-day. **Crunchbase confirms breach** - ShinyHunters leaked 2M+ records after ransom refusal; part of broader Okta SSO credential theft campaign targeting ~100 organizations. **Under Armour breach disclosed** - Everest ransomware gang published 72.7M customer accounts from November 2025 attack. **ShinyHunters SSO campaign** using evolved voice-phishing techniques to compromise Okta credentials; Mandiant tracking active campaign.

**Key Highlights:**
- **NEW**: CISA KEV adds 5 vulnerabilities (Jan 26) - Microsoft Office, SmarterMail (2), Linux Kernel, GNU InetUtils
- **NEW**: CVE-2026-21509 - Microsoft Office zero-day actively exploited; out-of-band patch released
- **NEW**: Crunchbase breach confirmed - 2M+ records leaked by ShinyHunters
- **NEW**: Under Armour breach - 72.7M accounts exposed by Everest ransomware
- **NEW**: ShinyHunters Okta SSO campaign targeting ~100 high-value enterprises
- **NEW**: CVE-2025-52691 & CVE-2026-23760 - SmarterMail critical flaws added to KEV

---

## CISA KEV Updates

### January 26, 2026 - Five New Additions

| CVE | Product | Vulnerability Type | Status |
|-----|---------|-------------------|--------|
| CVE-2026-21509 | Microsoft Office | Security Feature Bypass | **Actively Exploited** |
| CVE-2025-52691 | SmarterTools SmarterMail | Unrestricted File Upload | Active Exploitation |
| CVE-2026-23760 | SmarterTools SmarterMail | Authentication Bypass | Active Exploitation |
| CVE-2018-14634 | Linux Kernel | Integer Overflow | Active Exploitation |
| CVE-2026-24061 | GNU InetUtils | Argument Injection | Active Exploitation |

**Active KEV Remediation Deadlines:**

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | February 3, 2026 |
| CVE-2026-20045 | Cisco Unified Communications | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-54313 | eslint-config-prettier | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| VMware vCenter | Out-of-bounds Write | February 13, 2026 |

**Source:** [CISA Adds Five Known Exploited Vulnerabilities](https://www.cisa.gov/news-events/alerts/2026/01/26/cisa-adds-five-known-exploited-vulnerabilities-catalog)

---

## Critical Vulnerabilities

### NEW: Microsoft Office Zero-Day - CVE-2026-21509

**Severity:** High (Actively Exploited)
**Type:** Security Feature Bypass
**Affected:** Microsoft Office 2016, 2019, LTSC 2021, LTSC 2024, Microsoft 365 Apps
**Status:** Out-of-band emergency patch released

Microsoft released emergency out-of-band security updates to patch a high-severity Microsoft Office zero-day vulnerability exploited in attacks. Added to CISA KEV on January 26, 2026.

**Impact:** Security feature bypass enabling further exploitation
**Remediation:** Apply out-of-band updates immediately

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-actively-exploited-office-zero-day-vulnerability/)

---

### NEW: SmarterMail Dual Vulnerabilities

**CVE-2025-52691** - Unrestricted Upload of Dangerous File Type
**CVE-2026-23760** - Authentication Bypass via Alternate Path

Both vulnerabilities in SmarterTools SmarterMail were added to CISA KEV on January 26, 2026, indicating active exploitation.

**Impact:**
- CVE-2025-52691: Arbitrary file upload leading to potential RCE
- CVE-2026-23760: Authentication bypass enabling unauthorized access

**Remediation:** Update SmarterMail immediately; audit for signs of compromise

**Source:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### NEW: Linux Kernel Integer Overflow - CVE-2018-14634

**Severity:** High
**Type:** Integer Overflow (privilege escalation)
**Note:** Legacy vulnerability from 2018 now confirmed under active exploitation

This 2018 Linux Kernel vulnerability has been added to CISA KEV, indicating renewed or ongoing exploitation in the wild. The integer overflow can lead to local privilege escalation.

**Remediation:** Ensure all Linux systems are running patched kernel versions

---

### NEW: GNU InetUtils Argument Injection - CVE-2026-24061

**Severity:** High
**Type:** Argument Injection
**Product:** GNU InetUtils

Added to CISA KEV January 26, 2026. GNU InetUtils includes common network utilities (ftp, telnet, rlogin, etc.).

**Remediation:** Update GNU InetUtils to patched version

---

## Threat Actors

### NEW: ShinyHunters Okta SSO Campaign

**Threat Actor:** ShinyHunters
**Campaign:** Credential theft via voice phishing
**Targets:** ~100 high-value enterprises
**Method:** Evolved voice-phishing to compromise Okta SSO credentials

**Key Details:**
- Silent Push researchers identified campaign targeting 100+ Okta SSO accounts
- Mandiant tracking as "new, ongoing ShinyHunters-branded campaign"
- Uses "evolved" voice-phishing techniques
- Enrolls attacker-controlled devices into victim MFA solutions
- Confirmed breaches: Crunchbase, SoundCloud, Betterment

**TTPs:**
1. Voice phishing to obtain Okta SSO codes
2. MFA bypass via device enrollment
3. Data exfiltration
4. Ransom demand followed by public leak

**Indicators:** Unexpected MFA enrollment requests, voice calls requesting SSO codes

**Source:** [The Register](https://www.theregister.com/2026/01/26/shinyhunters_okta_sso_campaign/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/shinyhunters-claim-to-be-behind-sso-account-data-theft-attacks/)

---

### [UPDATE] Everest Ransomware Group

**Status:** Active since 2020
**Recent Victim:** Under Armour (72.7M accounts)
**Business Model:** Triple-threat operation

According to Halcyon, Everest operates three distinct revenue streams:
1. Double extortion ransomware
2. Network access brokerage
3. Insider recruitment program

**Significance:** Veteran group with unusual longevity in ransomware ecosystem

**Source:** [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/01/under-armour-ransomware-breach-data-of-72-million-customers-appears-on-the-dark-web)

---

## Data Breaches

### NEW: Crunchbase - ShinyHunters

**Victim:** Crunchbase (market intelligence firm)
**Threat Actor:** ShinyHunters
**Attack Date:** ~January 23, 2026
**Records Exposed:** 2+ million
**Data Size:** 400 MB (compressed)

**Attack Vector:** Voice phishing of Okta SSO credentials

**Data Exposed:**
- PII (personally identifiable information)
- Signed contracts
- Corporate data

**Status:** Crunchbase confirmed breach; under investigation by Schubert Jonckheer & Kolbe LLP

**Crunchbase Statement:** "Crunchbase detected a cybersecurity incident where a threat actor exfiltrated certain documents from our corporate network."

**Source:** [TechStartups](https://techstartups.com/2026/01/26/crunchbase-hacked-crunchbase-confirms-january-2026-data-breach-after-shinyhunters-leak-millions-of-records/), [Security Affairs](https://securityaffairs.com/187340/data-breach/shinyhunters-claims-2-million-crunchbase-records-company-confirms-breach.html)

---

### NEW: Under Armour - Everest Ransomware

**Victim:** Under Armour
**Threat Actor:** Everest ransomware gang
**Attack Date:** November 2025
**Disclosure Date:** January 21, 2026 (via Have I Been Pwned)
**Accounts Affected:** 72.7 million
**Data Stolen:** 343 GB

**Data Exposed:**
- Names
- Email addresses
- Dates of birth
- Genders
- Geographic locations
- Purchase history

**NOT Exposed (per Under Armour):**
- Passwords
- Financial/payment information

**Timeline:**
- November 16, 2025: Everest posted breach claims, gave 7-day ultimatum
- January 18, 2026: Data leaked on cybercrime forum
- January 21, 2026: HIBP ingested leaked data
- January 22, 2026: Under Armour acknowledged investigation

**Source:** [The Register](https://www.theregister.com/2026/01/21/under_armour_everest/), [TechRepublic](https://www.techrepublic.com/article/news-under-armour-ransomware-attack/), [ABC News](https://abcnews.go.com/Technology/wireStory/armour-data-breach-affecting-customers-email-addresses-129469278)

---

### NEW: SoundCloud & Betterment - ShinyHunters

**Victims:** SoundCloud, Betterment
**Threat Actor:** ShinyHunters
**Method:** Okta SSO credential theft via voice phishing
**Status:** Data leaked alongside Crunchbase

Part of the broader ShinyHunters campaign targeting ~100 organizations.

**Source:** [Hackread](https://hackread.com/shinyhunters-leak-soundcloud-crunchbase-betterment-data/)

---

## Malware & Ransomware

### Ransomware Trends - January 2026

**Key Statistics (2025 Final):**
- ~6,500 incidents (47% increase over 2023)
- 8,000+ organizations targeted (Emsisoft)
- 57 new ransomware groups
- 27 new extortion groups
- 350+ new ransomware strains
- Revenue dropped 35% ($1.25B → $814M)
- Payment rate below 25% in Q4 2025

**2026 Trend: Ransomware Without Encryption**
Pure exfiltration attacks surging - attackers steal data over weeks/months, then extort. No encryption means:
- Lower risk for attackers
- Harder for defenders to detect
- Nearly impossible to investigate once logs age out

**Active Groups:** Qilin, Akira, Cl0p, Play, SafePay, Everest

**Source:** [Cyble Research](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/), [Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)

---

### Legal Actions - BlackCat/Alphv Affiliates

**Development:** Two US cybersecurity professionals pleaded guilty to BlackCat ransomware charges

**Suspect:** Ryan Goldberg (40, Georgia) - former incident response manager at Sygnia
**Charges:** Ransomware deployment, data theft
**Ransom Received:** $1.2 million Bitcoin from one victim
**Sentencing:** March 12, 2026
**Maximum Penalty:** 20 years

**Significance:** Insider threat from cybersecurity industry

**Source:** [SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)

---

## Vendor Advisories

### January 27, 2026 Priority Patches

| Vendor | Product | CVE | Severity | Status |
|--------|---------|-----|----------|--------|
| Microsoft | Office | CVE-2026-21509 | High | **CISA KEV** - Out-of-band patch |
| SmarterTools | SmarterMail | CVE-2025-52691 | High | **CISA KEV** |
| SmarterTools | SmarterMail | CVE-2026-23760 | High | **CISA KEV** |
| GNU | InetUtils | CVE-2026-24061 | High | **CISA KEV** |
| Linux | Kernel | CVE-2018-14634 | High | **CISA KEV** |
| VMware | vCenter Server | TBD | Critical | **CISA KEV** - Feb 13 |
| Mozilla | Firefox | CVE-2026-0891/0892 | High | Suspected Exploitation |
| D-Link | DSL Routers | CVE-2026-0625 | 9.3 | **NO PATCH** |

---

## Recommended Actions

### Immediate Priority (Critical)

1. **Microsoft Office** - Apply out-of-band patch for CVE-2026-21509 (actively exploited zero-day)
2. **SmarterMail** - Patch both CVE-2025-52691 and CVE-2026-23760 (CISA KEV)
3. **Okta SSO** - Alert security teams to ShinyHunters voice-phishing campaign; audit MFA enrollments
4. **Microsoft CVE-2026-20805** - CISA KEV deadline February 3, 2026

### High Priority

5. **VMware vCenter Server** - Patch out-of-bounds write (CISA KEV deadline: Feb 13)
6. **GNU InetUtils** - Update for CVE-2026-24061
7. **Linux Kernel** - Verify CVE-2018-14634 patched on all systems
8. **Firefox** - Update to version 147 or ESR 140.7

### Threat Hunting

9. **Voice Phishing Detection** - Monitor for unusual calls requesting SSO/MFA codes
10. **MFA Audit** - Review recent device enrollments for unauthorized entries
11. **Okta Logs** - Analyze for ShinyHunters TTPs
12. **Exfiltration Detection** - Pure data theft attacks leave minimal footprint

### Breach Response

13. **Under Armour Customers** - Monitor for credential stuffing; change passwords if reused
14. **Crunchbase Users** - Expect phishing attempts using leaked data

---

## Sources

- [CISA Adds Five Known Exploited Vulnerabilities (Jan 26)](https://www.cisa.gov/news-events/alerts/2026/01/26/cisa-adds-five-known-exploited-vulnerabilities-catalog)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [BleepingComputer - Microsoft Office Zero-Day](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-actively-exploited-office-zero-day-vulnerability/)
- [BleepingComputer - ShinyHunters SSO Campaign](https://www.bleepingcomputer.com/news/security/shinyhunters-claim-to-be-behind-sso-account-data-theft-attacks/)
- [The Register - ShinyHunters Okta Campaign](https://www.theregister.com/2026/01/26/shinyhunters_okta_sso_campaign/)
- [The Register - Under Armour Breach](https://www.theregister.com/2026/01/21/under_armour_everest/)
- [TechStartups - Crunchbase Breach](https://techstartups.com/2026/01/26/crunchbase-hacked-crunchbase-confirms-january-2026-data-breach-after-shinyhunters-leak-millions-of-records/)
- [Security Affairs - Crunchbase](https://securityaffairs.com/187340/data-breach/shinyhunters-claims-2-million-crunchbase-records-company-confirms-breach.html)
- [Malwarebytes - Under Armour](https://www.malwarebytes.com/blog/news/2026/01/under-armour-ransomware-breach-data-of-72-million-customers-appears-on-the-dark-web)
- [TechRepublic - Under Armour](https://www.techrepublic.com/article/news-under-armour-ransomware-attack/)
- [SecurityWeek - BlackCat Arrests](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [Cyble Research - Ransomware Trends](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)
- [Morphisec - Exfiltration Attacks](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Hackread - ShinyHunters Leaks](https://hackread.com/shinyhunters-leak-soundcloud-crunchbase-betterment-data/)

---

## Appendix: CVE Tracking

### CVEs Added Today (2026-01-27)

| CVE ID | Product | CVSS | Status |
|--------|---------|------|--------|
| CVE-2026-21509 | Microsoft Office | High | **CISA KEV - Actively Exploited** |
| CVE-2025-52691 | SmarterMail | High | **CISA KEV** |
| CVE-2026-23760 | SmarterMail | High | **CISA KEV** |
| CVE-2018-14634 | Linux Kernel | High | **CISA KEV** |
| CVE-2026-24061 | GNU InetUtils | High | **CISA KEV** |

### Active CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | February 3, 2026 |
| CVE-2026-20045 | Cisco Unified Communications | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-54313 | eslint-config-prettier | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| VMware vCenter | Out-of-bounds Write | February 13, 2026 |

---

*Report generated: 2026-01-27*
*Next report: 2026-01-28*
*Classification: TLP:CLEAR*
