# Cyber Threat Intelligence Report
**Date:** 2026-02-24
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0224

---

## Executive Summary

- **CRITICAL**: BeyondTrust CVE-2026-1731 (CVSS 9.9) now actively exploited in ransomware campaigns; CISA KEV updated with ransomware flag
- **HIGH**: Microsoft February 2026 Patch Tuesday addressed 6 actively exploited zero-days across Windows Shell, MSHTML, Office Word, DWM, and RDS components
- **HIGH**: Google Chrome CVE-2026-2441 (use-after-free in CSS font handling) - first Chrome zero-day of 2026, actively exploited in the wild
- **HIGH**: CISA added Roundcube Webmail vulnerabilities (CVE-2025-49113, CVE-2025-68461) to KEV on Feb 20 with active exploitation confirmed
- **HIGH**: Singapore's UNC3886 (China-nexus APT) campaign against all four major telecom operators disclosed Feb 9; used zero-day to bypass perimeter firewalls and deployed rootkits
- **MEDIUM**: Advantest (chip testing giant) hit by ransomware on Feb 15; network portions compromised
- **MEDIUM**: Conduent govtech breach balloons, affecting millions more Americans; Odido telecom breach exposes 6M+ accounts

---

## Critical Vulnerabilities

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-1731 | BeyondTrust Remote Support / PRA | OS Command Injection / RCE | 9.9 | KEV - Ransomware campaigns confirmed |
| CVE-2026-25049 | n8n workflow automation | System Command Execution | 9.4 | Public PoC available |
| CVE-2026-26119 | Windows Admin Center | Privilege Escalation | Critical | Patched Feb 2026 |
| CVE-2026-21510 | Windows Shell | Security Feature Bypass / SmartScreen Bypass | 8.8 | Actively Exploited - KEV |
| CVE-2026-21513 | MSHTML Framework | Security Feature Bypass | N/A | Actively Exploited - KEV |
| CVE-2026-21514 | Microsoft Office Word | Security Feature Bypass | 5.5 | Actively Exploited - KEV |
| CVE-2026-21519 | Windows Desktop Window Manager | Local EoP (Type Confusion) | 7.8 | Actively Exploited - KEV → SYSTEM |
| CVE-2026-21525 | Windows Remote Access Connection Manager | DoS (NULL Pointer) | 6.2 | Actively Exploited - KEV |
| CVE-2026-21533 | Windows Remote Desktop Services | Local EoP (Privilege Mgmt) | 7.8 | Actively Exploited - KEV → SYSTEM |
| CVE-2026-2441 | Google Chrome | Use-After-Free in CSS Font Handling | Critical | Actively Exploited - First Chrome 0-day of 2026 |
| CVE-2025-49113 | Roundcube Webmail | Deserialization of Untrusted Data | N/A | KEV Added Feb 20 |
| CVE-2025-68461 | Roundcube Webmail | Cross-Site Scripting | N/A | KEV Added Feb 20 |

### February 2026 CISA KEV Additions Summary

**Feb 3:** CVE-2019-19006 (Sangoma FreePBX Auth Bypass), CVE-2021-39935 (GitLab SSRF), CVE-2025-40551 (SolarWinds WHD Deserialization), CVE-2025-64328 (Sangoma FreePBX OS Command Injection)

**Feb 10:** CVE-2026-21510, CVE-2026-21513, CVE-2026-21514, CVE-2026-21519, CVE-2026-21525, CVE-2026-21533 (all Microsoft - see above)

**Feb 13:** CVE-2026-1731 (BeyondTrust - RANSOMWARE CAMPAIGNS CONFIRMED)

**Feb 20:** CVE-2025-49113, CVE-2025-68461 (Roundcube Webmail - active exploitation confirmed)

---

## Exploits & Zero-Days

### Chrome CVE-2026-2441 - Actively Exploited
- **Type:** Use-after-free in Chrome CSS font feature handling
- **Impact:** Remote code execution within Chrome sandbox environment
- **Mechanism:** Chrome iterates over font feature values while modifying the set concurrently, leaving stale pointer data exploitable for code execution
- **Action:** Update Chrome immediately via Settings > Help > About Google Chrome

### Microsoft February 2026 - Six Zero-Days Patched
All six are confirmed as actively exploited in the wild prior to patching. Notably:
- CVE-2026-21510 (Windows Shell SmartScreen Bypass) - requires user to open malicious link/shortcut
- CVE-2026-21519 & CVE-2026-21533 both elevate to SYSTEM from standard low-privilege accounts with no user interaction required

### BeyondTrust CVE-2026-1731 - Mass Exploitation Underway
- watchTowr and Arctic Wolf confirmed mass exploitation by Feb 12
- Now attributed to ransomware campaigns in CISA KEV
- Affects BeyondTrust Remote Support <= 25.3.1 and PRA <= 24.3.4

### n8n CVE-2026-25049 - Critical Workflow RCE
- Allows system command execution via malicious n8n workflows
- CVSS 9.4; PoC circulating
- Self-hosted n8n instances are highest risk

---

## Malware & Ransomware

### BeyondTrust Exploitation Linked to Ransomware Groups
CISA confirmed ransomware operators are leveraging CVE-2026-1731 as an initial access vector. Organizations using BeyondTrust RS or PRA should treat this as an active incident response situation if unpatched.

### Hellcat Ransomware - Ascom Breach
- Exfiltrated 44GB of sensitive data from Ascom's ticketing infrastructure
- Initial access vector: Jira credentials harvested by infostealer malware
- Highlights ongoing credential-theft-to-ransomware pipeline

### Advantest Ransomware Incident (Feb 15)
- Japanese chip testing giant Advantest hit by ransomware
- Unauthorized third party accessed portions of network and deployed ransomware
- Investigation ongoing; semiconductor supply chain implications being assessed

### Space Bears Ransomware - Emerging Threat
- Associated with Phobos ransomware operations
- Employs double-extortion tactics (encrypt + exfiltrate)
- Increasingly targeting enterprise environments

### Pro-Russian Hacktivist Surge (Winter Olympics)
- Since Winter Olympics opened Feb 6 (Milan/Cortina d'Ampezzo), researchers tracking noticeable uptick in pro-Russian hacktivist activity
- DDoS and defacement attacks elevated; critical infrastructure operators should monitor

### Ransomware Without Encryption - Rising Trend
- Pure exfiltration attacks (no encryption) surging as they avoid detection by backup/recovery defenses
- Harder to detect without DLP and egress monitoring

---

## Threat Actors

### UNC3886 (China-Nexus APT) - Singapore Telecom Campaign
- **Disclosed:** February 9, 2026 by Cyber Security Agency of Singapore
- **Targets:** All four major Singapore telecom operators: M1, SIMBA Telecom, Singtel, StarHub
- **TTPs:**
  - Zero-day exploit used to bypass perimeter firewalls
  - Rootkits deployed for persistent, undetected access
  - Deliberate, targeted, and well-planned campaign
- **Data Exfiltrated:** Small amount of technical/network data (no customer records confirmed)
- **Response:** Singapore's largest-ever multi-agency cyber operation mounted to counter threat
- **Attribution:** UNC3886 is a suspected China-nexus cyber espionage group (Mandiant designation)
- **Significance:** Telecom sector targeting aligns with intelligence collection objectives; similar playbook to prior UNC3886 activity against network edge devices

### Iran - Coordinated Cyber Threat Landscape
- CSIS reporting on Iran's coordinated cyber operations beyond hacktivism
- Increasingly sophisticated coordinated campaigns against Western infrastructure

---

## Data Breaches

| Organization | Records/Impact | Data Exposed | Date |
|---|---|---|---|
| Odido (Dutch Telecom) | 6M+ accounts | Names, phone numbers, emails, bank account numbers, passport numbers | Investigated Feb 7 |
| Conduent (GovTech) | Millions (ballooning) | Government contractor data affecting millions of Americans | Feb 5 update |
| IRS (USG Disclosure) | Thousands of individuals | Confidential tax information disclosed to DHS for immigration enforcement | Feb 2026 |
| Cottage Hospital | 1,600+ current/former employees | SSNs, driver's license numbers, bank account info | Letters sent Feb 6 |
| Nova Biomedical Corp. | 10,764 victims | Sensitive/confidential personal information | Breach July 2025, disclosed Feb 2026 |
| MedRevenu & EyeCare Partners | TBD | Healthcare data | Feb 2026 |
| NationStates (gaming) | TBD | User account data | Feb 2026 |

**Notable:** The IRS disclosure to DHS is generating significant legal and congressional scrutiny - this is a policy/regulatory risk for organizations handling government data under current administration.

---

## Vendor Advisories

### Microsoft - February 2026 Patch Tuesday (Feb 11)
- 58 total vulnerabilities patched (5 Critical, 6 actively exploited zero-days)
- **Priority patches:** All 6 zero-days (CVE-2026-21510, -21513, -21514, -21519, -21525, -21533)
- Outlook Preview Pane attack vectors in CVE-2026-21260 & CVE-2026-21511 (spoofing/info disclosure without opening message)
- Reference: [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/) | [SecurityWeek](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)

### Google - Chrome Emergency Update
- CVE-2026-2441 zero-day patched via out-of-band release (not waiting for major release cycle)
- Update Chrome immediately: stable channel update released
- Reference: [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)

### Apple - CVE-2026-20700 Zero-Day
- Apple pushed critical security updates addressing CVE-2026-20700 zero-day
- All Apple device users should update immediately
- Reference: [Tech-Channels](https://www.tech-channels.com/breaking-news/apple-and-google-push-out-security-patches-as-zero-day-threats-persist-into-2026)

### Cisco - February 2026 Advisories
- Security updates for Secure Web Appliance and Cisco Meeting Management
- Reference: [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)

### Broader February 2026 Patch Cycle
- 60+ vendors issued security fixes this cycle
- SAP, Intel, Adobe, VMware, Fortinet, Check Point also released updates
- Reference: [Rescana Patch Report](https://www.rescana.com/post/february-2026-security-patch-report-microsoft-sap-intel-adobe-and-60-vendors-address-critical)

---

## Recommended Actions

### Immediate (24-48 Hours)

1. **BeyondTrust CVE-2026-1731** - EMERGENCY PATCH OR ISOLATE
   - Patch Remote Support to > 25.3.1 and PRA to > 24.3.4 immediately
   - Review logs for exploitation indicators (watchTowr IoCs available)
   - Ransomware attribution escalates this to incident-response priority

2. **Google Chrome CVE-2026-2441** - UPDATE ALL BROWSERS
   - Deploy Chrome update via endpoint management
   - Validate update completion with compliance reporting

3. **Apple CVE-2026-20700** - PUSH MDM UPDATE
   - Enforce update via MDM for all managed Apple devices

### This Week

4. **Microsoft February Patch Tuesday** - DEPLOY ALL 6 ZERO-DAYS FIRST
   - Prioritize: CVE-2026-21519 and CVE-2026-21533 (local → SYSTEM, no user interaction)
   - Second priority: CVE-2026-21510 (SmartScreen bypass - phishing enabler)
   - Patch Outlook to mitigate Preview Pane attack vectors

5. **Roundcube Webmail** - PATCH OR DISABLE IF INTERNET-EXPOSED
   - CVE-2025-49113 (deserialization) and CVE-2025-68461 (XSS) actively exploited
   - If unable to patch immediately, restrict to internal access only

6. **n8n Self-Hosted Instances** - AUDIT AND PATCH
   - CVE-2026-25049 CVSS 9.4 with PoC circulating
   - Review workflow permissions; isolate from internet if unpatched

### Ongoing

7. **Roundcube / Webmail Servers** - Enable WAF rules for deserialization and XSS patterns
8. **Infostealer Credential Hygiene** - Rotate Jira, Confluence, and enterprise tool credentials; enable MFA everywhere (Hellcat/Ascom attack vector)
9. **Egress Monitoring** - Implement DLP to detect pure-exfiltration ransomware attacks (no encryption pattern)
10. **Telecom/ISP Sector** - Review network device firmware and firewall configurations for UNC3886 TTPs (rootkit persistence on edge devices)
11. **Pro-Russian Hacktivist DDoS** - Ensure DDoS mitigation is active for public-facing infrastructure through Olympics period (through late Feb)

---

## Sources

- [CISA KEV - Feb 20 Roundcube Addition](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 10 Microsoft Zero-Days](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 13 BeyondTrust](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV - Feb 3 Additions](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA Roundcube Vulnerabilities Warning](https://cybersecuritynews.com/roundcube-vulnerabilities-exploited/)
- [BeyondTrust CVE-2026-1731 - Orca Security](https://orca.security/resources/blog/cve-2026-1731-beyondtrust-vulnerability/)
- [BleepingComputer - Microsoft Feb Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [SecurityWeek - 6 Zero-Days Patched](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)
- [Malwarebytes - Feb Patch Tuesday Zero-Days](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)
- [SecPod - Feb 2026 Patch Tuesday](https://www.secpod.com/blog/microsofts-february-2026-patch-tuesday-six-zero-days-patched-amid-growing-exploit-activity/)
- [Zero Day Initiative - Feb 2026 Review](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
- [Krebs on Security - Patch Tuesday Feb 2026](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [Help Net Security - Windows Admin Center CVE-2026-26119](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)
- [The Hacker News - n8n CVE-2026-25049](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [Absolute Security - Feb Patch Tuesday](https://www.absolute.com/blog/microsoft-february-2026-patch-tuesday-critical-fixes-updates)
- [CrowdStrike - Feb Patch Tuesday Analysis](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-february-2026/)
- [SecPod - Chrome CVE-2026-2441](https://www.secpod.com/blog/google-addresses-actively-exploited-chrome-vulnerability-cve-2026-2441/)
- [Malwarebytes - Chrome Zero-Day](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)
- [BleepingComputer - BeyondTrust Ransomware](https://www.bleepingcomputer.com/news/security/cisa-beyondtrust-rce-flaw-now-exploited-in-ransomware-attacks/)
- [SecurityWeek - Advantest Ransomware](https://www.securityweek.com/chip-testing-giant-advantest-hit-by-ransomware/)
- [CYFIRMA - Weekly Intel Report Feb 20](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [Computer Weekly - Singapore UNC3886 Operation](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [CSA Singapore - UNC3886 Press Release](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [SecurityWeek - Nation-State Threats 2026](https://www.securityweek.com/cyber-insights-2026-cyberwar-and-rising-nation-state-threats/)
- [TechCrunch - Conduent Breach](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [Privacy Guides - Breach Roundup Jan 30 - Feb 5](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [HIPAA Journal - MedRevenu & EyeCare Partners](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [Valley News - Cottage Hospital Breach](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [PKWARE - 2026 Data Breaches](https://www.pkware.com/blog/2026-data-breaches)
- [Rescana - Feb 2026 Security Patch Report](https://www.rescana.com/post/february-2026-security-patch-report-microsoft-sap-intel-adobe-and-60-vendors-address-critical)
- [Tech-Channels - Apple/Google Zero-Day Patches](https://www.tech-channels.com/breaking-news/apple-and-google-push-out-security-patches-as-zero-day-threats-persist-into-2026)
- [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/publicationListing.x)
- [Morphisec - Ransomware Without Encryption](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [WEF - Cyber Threats 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [Cybersecurity News Weekly Roundup](https://cybersecuritynews.com/cybersecurity-news-weekly/)
