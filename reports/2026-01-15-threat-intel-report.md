# Cyber Threat Intelligence Report
**Date:** 2026-01-15
**Report Period:** January 14-15, 2026
**Classification:** TLP:CLEAR

---

## Executive Summary

This report covers new cyber threat developments from January 15, 2026. Key highlights include:

- **[UPDATE]** Microsoft's CVE-2026-20805 zero-day actively exploited in the wild - CISA mandated remediation by Feb 3
- **NEW** Critical jsPDF vulnerability (CVE-2025-68428, CVSS 9.2) enables arbitrary file read in Node.js deployments
- **NEW** RondoDox botnet exploiting React2Shell (CVE-2025-55182, CVSS 10.0) across 90,000+ exposed systems
- **NEW** Multiple major data breaches: SoundCloud (20% user base), Instagram (17.5M accounts), European Space Agency
- **[UPDATE]** D-Link zero-day (CVE-2026-0625, CVSS 9.3) exploitation ongoing - no patch available for EOL devices
- **[UPDATE]** China-nexus APT group UAT-7290 targeting South Asian telecommunications with custom malware arsenal
- **NEW** Two US cybersecurity professionals plead guilty in BlackCat/Alphv ransomware case

Organizations should prioritize patching Microsoft CVE-2026-20805, updating n8n and jsPDF libraries, and monitoring for indicators of RondoDox botnet activity.

---

## Critical Vulnerabilities

### [UPDATE] Microsoft Windows Desktop Window Manager - CVE-2026-20805
- **Severity:** CVSS 5.5 (Medium) - Actively Exploited Zero-Day
- **Status:** CISA KEV - Federal agencies must patch by February 3, 2026
- **Impact:** Information disclosure vulnerability allowing attackers to leak memory addresses, potentially weakening system protections for follow-on attacks
- **Affected:** Windows Desktop Window Manager (DWM)
- **Remediation:** Apply Microsoft January 2026 Patch Tuesday updates immediately
- **Note:** This is the first information disclosure zero-day bug in DWM; attackers already exploiting in the wild

### NEW - Critical jsPDF Vulnerability - CVE-2025-68428
- **Severity:** CVSS 9.2 (Critical)
- **Impact:** Arbitrary file read in Node.js deployments
- **Affected:** jsPDF versions prior to 4.0.0 (server-side Node.js deployments)
- **Remediation:** Update to jsPDF version 4.0.0 or later immediately
- **Details:** Critical security vulnerability affecting server-side Node.js deployments disclosed in January 2026

### NEW - React2Shell/Next.js - CVE-2025-55182
- **Severity:** CVSS 10.0 (Critical)
- **Status:** Active exploitation by RondoDox botnet
- **Impact:** Remote code execution without authentication
- **Affected:** React Server Components and Next.js applications
- **Exploitation:** Over 90,000 exposed systems targeted worldwide for cryptocurrency mining and malware deployment
- **Remediation:** Apply Next.js security updates immediately; implement network segmentation

### [UPDATE] Microsoft Office Remote Code Execution - CVE-2026-20952, CVE-2026-20953
- **Severity:** CVSS 8.4 (High)
- **Impact:** Critical remote code execution vulnerabilities in Microsoft Office
- **Affected:** Microsoft Office applications
- **Remediation:** Apply January 2026 Patch Tuesday updates

### [UPDATE] Microsoft Word RCE - CVE-2026-20944
- **Severity:** CVSS 8.4 (High)
- **Impact:** Critical remote code execution vulnerability
- **Affected:** Microsoft Word
- **Remediation:** Apply January 2026 Patch Tuesday updates

---

## Zero-Day Vulnerabilities

### [UPDATE] D-Link Router Zero-Day - CVE-2026-0625
- **Severity:** CVSS 9.3 (Critical)
- **Status:** Actively exploited since late November 2025
- **Impact:** Remote code execution allowing unauthenticated attackers to inject and execute arbitrary shell commands
- **Affected:** Discontinued D-Link DSL router models (end-of-life)
- **Remediation:** NO PATCH AVAILABLE - Replace affected devices immediately with supported models
- **Exploitation Timeline:** Active exploitation detected since November 2025 per Shadowserver Foundation data

### [UPDATE] VMware ESXi Zero-Days - CVE-2025-22224, CVE-2025-22225, CVE-2025-22226
- **Severity:** CVSS 9.3, 8.2, 7.1 respectively
- **Status:** Exploited by China-linked threat actors
- **Impact:** Virtual machine escape allowing attackers to gain hypervisor control
- **Attack Vector:** Chinese-linked attackers exploited these vulnerabilities (initially disclosed as zero-days in March 2025) to escape VMs, potentially using exploit toolkit built as zero-day over a year before VMware's disclosure
- **Initial Access:** Leveraged SonicWall VPN access
- **Remediation:** Apply VMware patches; audit SonicWall VPN access controls

---

## Exploits & Active Campaigns

### NEW - RondoDox Botnet Campaign
- **Vulnerability Exploited:** CVE-2025-55182 (React2Shell)
- **Scale:** 90,000+ exposed systems worldwide
- **Objective:** Deploy cryptocurrency miners and malware
- **Impact:** Critical remote code execution in React Server Components and Next.js
- **Recommended Actions:**
  - Patch Next.js installations immediately
  - Search for IoCs associated with RondoDox botnet
  - Implement network monitoring for suspicious mining activity

### [UPDATE] Cisco ISE Vulnerability - CVE-2026-20029
- **Severity:** CVSS 4.9 (Medium)
- **Status:** Public PoC exploit available
- **Impact:** Allows authenticated attackers with administrative privileges to access sensitive information
- **Affected:** Cisco Identity Services Engine licensing feature
- **Remediation:** Apply Cisco security updates immediately

---

## Malware & Ransomware

### NEW - BlackCat/Alphv Ransomware Case - Legal Development
- **Date:** Announced this week (January 2026)
- **Incident:** Two US cybersecurity professionals plead guilty to conspiracy to commit extortion
- **Charges:** Both individuals face up to 20 years in prison
- **Sentencing:** Scheduled for March 12, 2026
- **Significance:** Rare case of cybersecurity professionals involved in ransomware operations; highlights insider threat risks

### Ransomware Trends (2025-2026)
- **Volume Increase:** Ransomware attacks up nearly 50% in North Carolina (843 to 1,215 incidents)
- **Global Trend:** 8,000+ claimed victims on leak sites in 2025, representing 50% increase from 2023
- **New Groups:** Cyble tracked 57 new ransomware groups and 27 new extortion groups emerging in 2025
- **Attack Evolution:** Shift toward pure exfiltration attacks without encryption (harder to detect)

### Recent Ransomware Activity (January 14, 2026)
Multiple ransomware attacks discovered on January 14, 2026:
- INC_RANSOM
- Akira
- Qilin
- Various other threat actors targeting multiple organizations

---

## Threat Actors & APT Activity

### NEW - UAT-7290 (China-nexus APT)
- **Disclosed:** January 8, 2026 by Cisco Talos
- **Attribution:** High confidence China-nexus APT
- **Active Since:** At least 2022
- **Target:** Critical infrastructure entities in South Asia, primarily telecommunications providers
- **Objective:** Espionage-focused intrusions and initial access operations
- **Malware Arsenal:**
  - RushDrop
  - DriveSwitch
  - SilentRaid
- **TTPs:**
  - Exploiting one-day vulnerabilities
  - Target-specific SSH brute force attacks
  - Compromising public-facing edge devices
  - Privilege escalation on compromised systems
- **Assessment:** Sophisticated threat actor with persistent access to telecommunications infrastructure

### [UPDATE] APT28/Fancy Bear (Russia-linked)
- **Activity:** Credential harvesting campaign
- **Attribution:** Russian Federation GRU
- **Targets:**
  - IT integrator in Uzbekistan
  - European think tank
  - Military organization in North Macedonia
  - Scientists and researchers at Turkish energy and nuclear research organization
- **Geographic Focus:** Balkans, Middle East, Central Asia
- **Capability:** One of the world's most capable threat actors

---

## Vendor Security Advisories

### Cisco (January 2026)
- **CVE-2025-20393 (CVSS 10.0):** Actively exploited zero-day in AsyncOS Software for Secure Email Gateway and Secure Email and Web Manager products; improper input validation vulnerability
- **CVE-2026-20029 (CVSS 4.9):** Identity Services Engine licensing feature vulnerability; public PoC exploit available

### Adobe (January 2026)
- **Scope:** 11 security advisories addressing 25 vulnerabilities
- **Products Affected:**
  - Adobe DreamWeaver
  - Adobe InDesign
  - Adobe Illustrator
  - Adobe InCopy
  - Adobe Bridge
  - Adobe Substance 3D Modeler
  - Adobe Substance 3D Painter
  - Adobe Substance 3D Sampler
  - Adobe Coldfusion
  - Adobe Substance 3D Designer
- **Severity:** 17 vulnerabilities rated critical
- **Remediation:** Apply Adobe security updates immediately

### VMware/Broadcom (January 2026)
- **Product:** Tanzu Greenplum Backup and Restore component
- **Severity:** Multiple high severity flaws
- **Impact:** Unauthenticated remote attackers could trigger denial-of-service conditions
- **Remediation:** Apply VMware Product Security Advisory patches

### ServiceNow (January 2026)
- **CVE-2025-12420 (CVSS 9.3):** Critical flaw in AI Platform
- **Impact:** Unauthenticated user impersonation
- **Remediation:** Apply ServiceNow security updates

---

## Data Breaches & Incidents

### NEW - SoundCloud Data Breach
- **Date:** Disclosed January 2026
- **Scope:** Approximately 20% of user base (~28 million accounts out of 140 million total users)
- **Data Compromised:** Email addresses and information visible on public user profiles
- **Attack Vector:** Unauthorized activity in ancillary service dashboard
- **Impact:** Tens of millions of accounts affected
- **Recommended Actions:** Users should monitor for phishing attempts using compromised email addresses

### NEW - Instagram Data Leak
- **Date:** January 9-10, 2026
- **Scope:** 17.5 million user accounts
- **Data Compromised:** Sensitive personal information
- **Distribution:** Data circulating on dark web forums (BreachForums)
- **Indicator:** Spike in password reset emails beginning January 9, 2026
- **Impact:** Large-scale credential compromise
- **Recommended Actions:**
  - Instagram users should reset passwords immediately
  - Enable multi-factor authentication
  - Monitor for account takeover attempts

### NEW - European Space Agency Cyber Attack
- **Date:** January 2026
- **Target:** European Space Agency (ESA)
- **Impact:** Compromise of servers used for collaborative engineering solutions within scientific community
- **Status:** Confirmed by ESA
- **Implications:** Potential compromise of sensitive space research and engineering data

### NEW - Ledger (via Global-e)
- **Date:** January 2026
- **Vector:** Third-party payment processor Global-e compromise
- **Impact:** Ledger customer data exposed
- **Data at Risk:** Customer information including payment details
- **Recommended Actions:** Ledger customers should monitor financial accounts for fraudulent activity

### NEW - Gulshan Management Services
- **Date:** January 2026
- **Data Compromised:** Social Security Numbers and additional personal information
- **Impact:** Identity theft risk for affected individuals

### NEW - Monroe University
- **Date:** January 2026
- **Scope:** 320,000 individuals affected
- **Status:** Attorneys investigating
- **Data Compromised:** Personal and educational records

---

## CISA Known Exploited Vulnerabilities (KEV) Catalog

### [UPDATE] Recent KEV Additions (January 7, 2026)
CISA added two vulnerabilities to the KEV catalog:

1. **CVE-2009-0556** - Microsoft Office PowerPoint Code Injection Vulnerability
2. **CVE-2025-37164** - HPE OneView Code Injection Vulnerability

**Federal Agency Deadline:** January 28, 2026

### KEV Catalog Statistics
- **Total Entries:** 1,484 known exploited vulnerabilities
- **2025 Growth:** 245 security defects added (20% increase, largest expansion in 3-year period)
- **Ransomware-Related:** 24 vulnerabilities exploited in ransomware attacks during 2025
- **Global Impact:** 8,000+ ransomware victims on leak sites in 2025 (50% increase from 2023)

---

## Recommended Actions

### Immediate Priority (24-48 hours)
1. **Patch Microsoft CVE-2026-20805** - Zero-day actively exploited; CISA mandates federal agency remediation by Feb 3, 2026
2. **Update jsPDF to version 4.0.0+** - Critical file read vulnerability (CVE-2025-68428, CVSS 9.2)
3. **Patch Next.js installations** - RondoDox botnet actively exploiting CVE-2025-55182 (CVSS 10.0)
4. **Replace EOL D-Link routers** - CVE-2026-0625 has no patch available; devices must be retired
5. **Apply Cisco security updates** - CVE-2025-20393 (CVSS 10.0) actively exploited
6. **Review n8n installations** - Multiple critical vulnerabilities including CVE-2026-21858 (CVSS 10.0)

### High Priority (This Week)
1. **Deploy January 2026 Patch Tuesday updates** - Address 114 Microsoft vulnerabilities including 3 zero-days
2. **Apply Adobe security updates** - 17 critical vulnerabilities across multiple products
3. **Patch VMware Tanzu Greenplum** - Multiple high severity DoS vulnerabilities
4. **Update ServiceNow AI Platform** - CVE-2025-12420 allows unauthenticated user impersonation
5. **Audit SonicWall VPN access controls** - Used in VMware ESXi zero-day attacks

### Ongoing Security Measures
1. **Monitor for RondoDox IoCs** - 90,000+ systems compromised for cryptocurrency mining
2. **Hunt for UAT-7290 indicators** - Sophisticated China-nexus APT targeting telecommunications
3. **Review credential harvesting attempts** - APT28/Fancy Bear active in Balkans, Middle East, Central Asia
4. **Implement MFA on all critical accounts** - Response to SoundCloud and Instagram breaches
5. **Enhanced monitoring for ransomware activity** - 50% increase in global attacks
6. **Insider threat detection** - Following BlackCat/Alphv case involving security professionals

### Strategic Recommendations
1. **Asset Inventory Review:** Identify and retire all end-of-life devices (especially D-Link routers)
2. **Supply Chain Security:** Assess third-party payment processors and service providers following Global-e/Ledger incident
3. **Vulnerability Management:** Prioritize CISA KEV catalog items - 1,484 known exploited vulnerabilities require attention
4. **Incident Response Planning:** Test ransomware recovery procedures given 50% attack increase
5. **APT Threat Hunting:** Organizations in South Asia, Balkans, Middle East should hunt for UAT-7290 and APT28 indicators
6. **React/Next.js Security Audit:** Review all React Server Components and Next.js deployments for CVE-2025-55182

---

## Intelligence Gaps & Monitoring Requirements

1. **CVE-2025-20393 Exploitation Details:** Limited public information on Cisco email security exploitation; continue monitoring for attack patterns
2. **RondoDox Botnet Attribution:** No clear attribution for RondoDox operators; monitor for infrastructure and TTP evolution
3. **Instagram Breach Vector:** Attack methodology for 17.5M account compromise not fully disclosed; await Meta security advisory
4. **UAT-7290 Targeting Expansion:** Current intelligence limited to South Asia telecom; monitor for geographic/sectoral expansion
5. **BlackCat/Alphv Case Details:** Limited technical details from guilty pleas; await court documents for TTP insights

---

## Indicators of Compromise (IoCs)

Organizations should monitor for IoCs associated with:

1. **RondoDox Botnet** - React2Shell exploitation attempts, cryptocurrency mining processes
2. **UAT-7290 Malware** - RushDrop, DriveSwitch, SilentRaid indicators
3. **APT28/Fancy Bear** - Credential harvesting campaigns, phishing infrastructure
4. **D-Link CVE-2026-0625 Exploitation** - Shell command injection attempts on legacy DSL routers
5. **VMware ESXi Attacks** - Virtual machine escape attempts, unusual hypervisor access patterns

Detailed IoC lists should be obtained from:
- CISA alerts and advisories
- Vendor security bulletins
- Threat intelligence platforms
- ISAC/ISAO sharing communities

---

## Sources

### Vulnerability Advisories
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft Patch Tuesday January 2026 - Tenable](https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805)
- [CrowdStrike Patch Tuesday Analysis January 2026](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/)
- [The Register: Windows Zero-Day Bug Gets Fix and CISA Alert](https://www.theregister.com/2026/01/14/patch_tuesday_january_2026/)
- [Dark Reading: Microsoft's Patch Tuesday Starts 2026 With a Bang](https://www.darkreading.com/application-security/microsofts-starts-2026-bang-zero-day)
- [SecurityWeek: Critical n8n Vulnerability Exposes Instances to Takeover](https://www.securityweek.com/critical-vulnerability-exposes-n8n-instances-to-takeover-attacks/)
- [The Hacker News: Critical n8n Vulnerability (CVSS 10.0)](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html)
- [Security Boulevard: Critical jsPDF Vulnerability](https://securityboulevard.com/2026/01/critical-jspdf-vulnerability-enables-arbitrary-file-read-in-node-js-cve-2025-68428/)

### Zero-Day & Exploits
- [Dark Reading: Attackers Exploit Zero-Day in EOL D-Link Routers](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)
- [SecurityWeek: Hackers Exploit Zero-Day in Discontinued D-Link Devices](https://www.securityweek.com/hackers-exploit-zero-day-in-discontinued-d-link-devices/)
- [The Hacker News: China-Linked Hackers Exploit VMware ESXi Zero-Days](https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html)
- [The Hacker News: RondoDox Botnet Exploits Critical React2Shell Flaw](https://thehackernews.com/2026/01/rondodox-botnet-exploits-critical.html)
- [Huntress: ESXi Exploitation in the Wild](https://www.huntress.com/blog/esxi-vm-escape-exploit)

### Threat Actor Activity
- [Cisco Talos: UAT-7290 Targets High Value Telecommunications](https://blog.talosintelligence.com/uat-7290/)
- [Dark Reading: Russia's Fancy Bear APT Doubles Down on Global Secrets Theft](https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-credentials-global-targets)

### Vendor Advisories
- [The Hacker News: Cisco Patches ISE Security Vulnerability](https://thehackernews.com/2026/01/cisco-patches-ise-security.html)
- [GovInfoSecurity: No Rest in 2026 as Patch Alerts Amass](https://www.govinfosecurity.com/no-rest-in-2026-as-patch-alerts-amass-for-cisco-hpe-n8n-a-30482)
- [Qualys: Microsoft and Adobe Patch Tuesday January 2026](https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review)

### Data Breaches
- [CyberPress: 17.5 Million Instagram Accounts Exposed](https://cyberpress.org/instagram-data-leak/)
- [The CyberSec Guru: Instagram Breach 2026](https://thecybersecguru.com/news/instagram-data-breach-17-million/)
- [SharkStriker: Top Data Breaches of January 2026](https://sharkstriker.com/blog/data-breaches-in-january-2026/)
- [Privacy Guides: Data Breach Roundup Jan 2-8, 2026](https://www.privacyguides.org/news/2026/01/09/data-breach-roundup-jan-2-jan-8-2026/)
- [Ledger Support: Global-e Incident January 2026](https://support.ledger.com/article/Global-e-Incident-to-Order-Data---January-2026)

### Ransomware
- [SecurityWeek: Two US Cybersecurity Pros Plead Guilty Over Ransomware](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [Security Affairs: BlackCat/Alphv Ransomware Case](https://securityaffairs.com/186446/cyber-crime/two-u-s-cybersecurity-professionals-plead-guilty-in-blackcat-alphv-ransomware-case.html)
- [The Register: Ransomware Attacks Kept Climbing in 2025](https://www.theregister.com/2026/01/08/ransomware_2025_emsisoft/)
- [Cyble: 10 New Ransomware Groups of 2025](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)

### CISA Updates
- [CISA: Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/01/07/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [SecurityWeek: CISA KEV Catalog Expanded 20% in 2025](https://www.securityweek.com/cisa-kev-catalog-expanded-20-in-2025-topping-1480-entries/)
- [CybersecurityNews: CISA Expands KEV Catalog](https://cybersecuritynews.com/cisa-expands-kev-catalog/)
- [The Hacker News: CISA Flags Microsoft Office and HPE OneView Bugs](https://thehackernews.com/2026/01/cisa-flags-microsoft-office-and-hpe.html)

---

## Report Metadata

- **Generated:** 2026-01-15
- **Coverage Period:** January 14-15, 2026 (24-hour cycle)
- **Sources Consulted:** 50+ open-source intelligence sources
- **CVEs Analyzed:** 30+ vulnerabilities
- **Data Breaches Tracked:** 6 major incidents
- **APT Groups Profiled:** 2 active campaigns
- **Next Report:** 2026-01-16

---

**Report Classification:** TLP:CLEAR
**Distribution:** Unrestricted
**Prepared by:** Cyber Threat Intelligence Team
**Contact:** [Security Operations Center]

---

*This report contains information from open-source intelligence (OSINT) and publicly available security advisories. Organizations should validate findings against their specific environment and threat model.*
