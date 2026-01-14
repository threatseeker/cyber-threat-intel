# Cyber Threat Intelligence Report
**Date:** January 14, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-014

---

## Executive Summary

This report provides a comprehensive overview of the current cyber threat landscape as of January 14, 2026. Key highlights include:

- **Microsoft Patch Tuesday** (Jan 13): 114 vulnerabilities patched including 3 zero-days, one actively exploited (CVE-2026-20805)
- **Critical n8n Vulnerability** (CVE-2026-21858): CVSS 10.0 RCE affecting ~100,000 servers globally
- **CISA KEV Updates**: 4 new vulnerabilities added to the Known Exploited Vulnerabilities catalog in January
- **VMware ESXi Zero-Days**: Chinese-linked threat actors exploiting VM escape vulnerabilities
- **Apple Emergency Updates**: Two WebKit zero-days (CVE-2025-43529, CVE-2025-14174) exploited in targeted attacks
- **Major Data Breaches**: 17.5M Instagram accounts exposed; ManageMyHealth (NZ) breach affecting 126K patients
- **Ransomware Trends**: 8,000+ organizations targeted in 2025; Qilin, Akira, and Cl0p most active groups

**Risk Level: HIGH** - Multiple actively exploited vulnerabilities require immediate patching.

---

## Critical Vulnerabilities

### CVSS 10.0 - Maximum Severity

| CVE | Product | Description | Status |
|-----|---------|-------------|--------|
| CVE-2026-21858 | n8n Workflow Automation | Unauthenticated RCE via Content-Type confusion ("Ni8mare") | Patch Available |
| CVE-2026-21877 | n8n Workflow Automation | Unrestricted file upload leading to code execution | Fixed in v1.121.3 |
| CVE-2025-37164 | HPE OneView | Code injection - remote unauthenticated RCE | Patched Dec 17, 2025 |

### CVSS 9.0+ - Critical Severity

| CVE | CVSS | Product | Description |
|-----|------|---------|-------------|
| CVE-2025-68668 | 9.9 | n8n (N8scape) | Sandbox bypass allowing OS command execution |
| CVE-2026-0501 | 9.9 | SAP S/4HANA | SQL injection in RFC-enabled module |
| CVE-2026-0500 | 9.6 | SAP Wily Introscope | RCE via malicious JNLP files |
| CVE-2026-0625 | 9.3 | D-Link DSL Routers | Command injection (EOL devices - unpatchable) |
| CVE-2026-21440 | 9.2 | AdonisJS Bodyparser | Path traversal enabling arbitrary file write |
| CVE-2026-0498 | 9.1 | SAP S/4HANA | Code injection leading to OS command execution |
| CVE-2025-59470 | 9.0 | Veeam Backup | RCE as postgres user |

---

## Exploits & Zero-Days

### Actively Exploited Zero-Days

#### Microsoft Windows (CVE-2026-20805)
- **CVSS:** 5.5 | **Type:** Information Disclosure
- **Component:** Desktop Window Manager (DWM)
- **Impact:** Leaks memory addresses used for exploit chain reliability
- **Status:** Patched in January 2026 Patch Tuesday
- **CISA KEV Due Date:** February 3, 2026

#### VMware ESXi (Multiple CVEs)
Chinese-linked threat actors are actively exploiting VMware ESXi zero-days to escape virtual machines:
- **CVE-2025-22224** (CVSS 9.3) - Memory corruption
- **CVE-2025-22225** (CVSS 8.2) - Sandbox escape
- **CVE-2025-22226** (CVSS 7.1) - Information leak

Attack chain allows full hypervisor compromise from guest VM.

#### Apple WebKit (CVE-2025-43529 & CVE-2025-14174)
- **Impact:** Arbitrary code execution via malicious web content
- **Target:** Specific individuals in "extremely sophisticated" attacks
- **Status:** Patched in iOS 26.2, macOS Tahoe 26.2, Safari 26.2

#### D-Link DSL Routers (CVE-2026-0625)
- **CVSS:** 9.3 | **Type:** Command Injection
- **Status:** End-of-life devices - NO PATCH AVAILABLE
- **Impact:** DNS hijacking affecting all downstream devices

#### Firefox (CVE-2026-0891 & CVE-2026-0892)
- **Status:** Suspected exploitation; fixed in Firefox 147, ESR 140.7
- **Impact:** Sandbox escape and arbitrary code execution

---

## Malware & Ransomware

### Ransomware Landscape Overview
- **8,000+ organizations** claimed as victims in 2025 (up from 6,000 in 2024)
- **30% increase** in active ransomware groups
- **57 new ransomware groups** emerged in 2025
- **350+ new ransomware strains** discovered

### Most Active Ransomware Groups (January 2026)
1. **Qilin** - Targeted CSV Group (Italy), HealthBridge Chiropractic
2. **Akira** - Continued operations across multiple sectors
3. **Cl0p** - Mass exploitation campaigns
4. **Play** - Active in North America and Europe
5. **Safepay** - Emerging threat actor
6. **Shinobi** - Targeted M&M Auto Parts
7. **Incransom** - Targeted 3GH Informatica Integral (Spain)
8. **Crimson Collective** - Claims Brightspeed breach (1M+ customers)

### Notable January 2026 Ransomware Incidents
| Date | Victim | Threat Actor | Data Claimed |
|------|--------|--------------|--------------|
| Jan 2 | CSV Group (Italy) | Qilin | Corporate data |
| Jan 6 | HealthBridge Chiropractic | Qilin | Healthcare records |
| Jan 2026 | European Space Agency | Unknown | 200GB (API tokens, source code) |
| Jan 2026 | M&M Auto Parts | Shinobi | Encrypted systems |

### Enforcement Actions
Two US cybersecurity professionals (Ryan Goldberg, Georgia-based incident response manager) pleaded guilty to BlackCat/Alphv ransomware conspiracy. Sentencing scheduled for March 12, 2026, facing up to 20 years.

---

## Threat Actors

### Nation-State Activity

#### China (APT)
- **VMware ESXi Exploitation:** Sophisticated multi-stage attack chain exploiting zero-days
- **Focus:** Critical infrastructure, semiconductor manufacturers, AI ecosystem
- **Tactics:** Long-dwell operations for IP theft, "most persistent, long-term threat"

#### Russia
- **Focus:** Ukraine operations, global information operations
- **Targeting:** Western nations, election interference campaigns
- **Priority:** Long-term strategic goals

#### North Korea
- **Focus:** Cryptocurrency theft, IT supply chain compromise
- **Notable:** Scattered Spider teenage hacking group targeting Fortune 500 ($1T+ targeted since 2022)

#### Iran
- **Current Focus:** Domestic dissidents
- **Outlook:** Expected large cyber-attacks to maintain regional influence

### Emerging Threat: AI-Powered Attacks
- AI agents capable of coordinating attacks without human intervention
- "AI poisoning" attacks targeting ML training datasets
- Autonomous attack scaling expected to increase in 2026

---

## Vendor Advisories

### Microsoft - Patch Tuesday (January 13, 2026)
**114 vulnerabilities patched** including:
- 8 Critical (6 RCE, 2 EoP)
- 3 Zero-days (1 actively exploited)
- 57 Elevation of Privilege (50%)
- 22 Remote Code Execution (19%)
- 22 Information Disclosure (19%)

**Priority Patches:**
| CVE | Component | Severity | Notes |
|-----|-----------|----------|-------|
| CVE-2026-20805 | DWM | High | Actively exploited |
| CVE-2026-20854 | LSASS | Critical | Network exploitable use-after-free |
| CVE-2026-20944 | Word | Critical | RCE via malicious documents |
| CVE-2026-20953 | Office | Critical | Use-after-free |
| CVE-2026-20955 | Excel | Critical | Pointer manipulation |

**Windows Update KB Numbers:**
- Windows 11: KB5074109, KB5073455
- Windows 10: KB5073724

### Apple Security Updates
**iOS 26.2 / macOS Tahoe 26.2** (Emergency Release)
- Two actively exploited WebKit zero-days
- Affects iPhone 11+, iPad (3rd gen Air+, 8th gen+, mini 5th gen+)
- iOS 26.3 beta testing background security improvements

### Google Chrome
**Version 143.0.7499.192/.193** (January 6, 2026)
- CVE-2026-0628: High-severity WebView policy enforcement bypass
- Affects ~3 billion users across desktop and Android
- Chrome 144 releasing January 13, 2026

### Mozilla Firefox
**Firefox 147 / ESR 140.7** (January 13, 2026)
- CVSS 10.0 sandbox escape vulnerability
- Use-after-free in JavaScript engine
- Memory safety bugs with evidence of exploitation
- Migrated to Safe Browsing V5 protocol

### SAP - January 2026 Security Patch Day
4 Critical vulnerabilities (CVSS 9.0+):
- CVE-2026-0501: SQL injection in S/4HANA (9.9)
- CVE-2026-0500: RCE in Wily Introscope (9.6)
- CVE-2026-0498: Code injection in S/4HANA (9.1)
- CVE-2026-0491: Code injection in Landscape Transformation (9.1)

### Veeam Backup & Replication
**Version 13.0.1.1071** - Addresses CVE-2025-59470 (CVSS 9.0) RCE vulnerability

---

## Industry News

### Data Breaches

| Organization | Records Affected | Data Exposed | Status |
|--------------|------------------|--------------|--------|
| Instagram (Meta) | 17.5 million | Account data | Circulating on dark web |
| ManageMyHealth (NZ) | 108K-126K | Patient portal data | Disclosed Jan 2, 2026 |
| Brightspeed | 1+ million | PII, billing, partial payment | Claimed by Crimson Collective |
| WIRED (Condé Nast) | 2.3 million | Subscriber information | Leaked |
| Ledger (via Global-e) | Customer orders | Order data only | Confirmed Jan 5, 2026 |

### Regulatory & Enforcement
- North Carolina: 50% increase in ransomware attacks (843 to 1,215 incidents)
- BlackCat/Alphv operators facing sentencing in March 2026
- FCEB agencies required to patch CISA KEV vulnerabilities by specified due dates

### Industry Trends
- Europe: 22% of global ransomware attacks, 3.2M DDoS attacks recorded
- 60% of breaches involve human element (phishing, credentials)
- Average breach cost: $4.44 million
- AI-driven attacks and autonomous agents emerging as primary concern

---

## Recommended Actions

### Immediate (24-48 Hours)

1. **Apply Microsoft January 2026 Patches**
   - Priority: CVE-2026-20805 (actively exploited)
   - Focus on LSASS and Office vulnerabilities

2. **Update Apple Devices**
   - Deploy iOS 26.2 / macOS Tahoe 26.2 immediately
   - Two WebKit zero-days actively exploited

3. **Update Browsers**
   - Chrome 143.0.7499.193+ (CVE-2026-0628)
   - Firefox 147 / ESR 140.7 (sandbox escape)

4. **n8n Workflow Automation**
   - Update to version 1.121.3 or later immediately
   - CVE-2026-21858 allows unauthenticated RCE

5. **Check for D-Link DSL Routers**
   - EOL devices vulnerable to CVE-2026-0625
   - No patch available - replace immediately

### Short-Term (1-2 Weeks)

6. **Patch SAP Systems**
   - Four critical vulnerabilities in January Patch Day
   - SQL injection and RCE risks

7. **Update Veeam Backup**
   - Deploy version 13.0.1.1071
   - Addresses critical RCE vulnerability

8. **Review HPE OneView**
   - Ensure December 2025 patch applied
   - CVE-2025-37164 (CVSS 10.0) in CISA KEV

9. **VMware ESXi**
   - Verify March 2025 patches applied
   - Chinese APT actively exploiting VM escape chain

### Ongoing

10. **Monitor for Ransomware IOCs**
    - Qilin, Akira, Cl0p groups actively targeting organizations
    - Healthcare and services sectors at elevated risk

11. **Credential Hygiene**
    - Infostealer-harvested credentials driving initial access
    - Implement MFA, monitor for leaked credentials

12. **AI Security Posture**
    - Review AI/ML pipeline security
    - Monitor for training data poisoning attempts

---

## Sources

### CISA & Government
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds One KEV - January 12, 2026](https://www.cisa.gov/news-events/alerts/2026/01/12/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA Adds Two KEVs - January 7, 2026](https://www.cisa.gov/news-events/alerts/2026/01/07/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Vulnerability Summary - Week of Jan 5](https://www.cisa.gov/news-events/bulletins/sb26-012)

### Vendor Advisories
- [Microsoft Patch Tuesday January 2026](https://www.bleepingcomputer.com/news/microsoft/microsoft-january-2026-patch-tuesday-fixes-3-zero-days-114-flaws/)
- [Apple Security Releases](https://support.apple.com/en-us/100100)
- [Chrome Releases Blog](https://chromereleases.googleblog.com/2026/01/stable-channel-update-for-desktop.html)
- [Mozilla Security Advisories - Firefox 147](https://www.mozilla.org/en-US/security/advisories/mfsa2026-01/)
- [SAP January 2026 Security Updates](https://www.securityweek.com/saps-january-2026-security-updates-patch-critical-vulnerabilities/)

### Threat Intelligence
- [The Hacker News - n8n Critical Vulnerability](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html)
- [The Hacker News - VMware ESXi Zero-Days](https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html)
- [Cyera Research - Ni8mare RCE](https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858)
- [Dark Reading - D-Link Zero-Day](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)
- [CYFIRMA Weekly Intelligence Report](https://www.cyfirma.com/news/weekly-intelligence-report-09-january-2026/)

### Data Breaches
- [SharkStriker - January 2026 Data Breaches](https://sharkstriker.com/blog/data-breaches-in-january-2026/)
- [CyberPress - Instagram Data Leak](https://cyberpress.org/instagram-data-leak/)
- [SecurityWeek - Data Breaches Linked to Single Threat Actor](https://www.securityweek.com/dozens-of-major-data-breaches-linked-to-single-threat-actor/)

### Ransomware & Malware
- [Cyble - Ransomware Trends 2026](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)
- [SecurityWeek - 8,000 Ransomware Attacks](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)
- [Fortune - Scattered Spider Investigation](https://fortune.com/2026/01/01/feds-hunt-teenagers-hacking-crypto-gaming/)

### Analysis & Research
- [Zero Day Initiative - January 2026 Review](https://www.thezdi.com/blog/2026/1/13/the-january-2026-security-update-review)
- [CrowdStrike - Patch Tuesday Analysis](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/)
- [Qualys - Microsoft Patch Tuesday Review](https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review)
- [IT Pro - Nation State Threats 2026](https://www.itpro.com/security/cyber-attacks/crink-attacks-nation-state-hackers--threat-2026)

---

*Report generated: January 14, 2026*
*Next scheduled update: January 15, 2026*
