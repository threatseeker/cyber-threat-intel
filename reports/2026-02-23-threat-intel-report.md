# Cyber Threat Intelligence Report
**Date:** 2026-02-23
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0223

---

## Executive Summary

- **CRITICAL:** BeyondTrust Remote Support CVE-2026-1731 (CVSS 9.9) confirmed actively exploited with VShell/SparkRAT payloads being deployed post-exploitation; 170+ SolarWinds WHD installs remain unpatched
- **CRITICAL:** Microsoft February 2026 Patch Tuesday resolved 58 flaws including **6 actively exploited zero-days** in Windows Shell, MSHTML, Office Word, and Remote Desktop Services
- **ACTIVE:** UNC3886 (China-nexus APT) conducted targeted campaign against all four major Singapore telecom operators; Singapore launched its largest-ever multi-agency counter-operation (Operation CYBER GUARDIAN)
- **ACTIVE:** Hellcat ransomware breached Ascom via Jira credentials harvested by infostealers; Space Bears ransomware escalating with Phobos-linked double extortion
- **BREACH:** Odido (Netherlands) - 6M+ customer records exposed including bank account numbers and passport data; IRS improperly disclosed 1.28M individual records to DHS/ICE
- **KEV UPDATES:** CISA added 13 new entries to the Known Exploited Vulnerabilities catalog in February 2026, including RoundCube Webmail XSS/deserialization and BeyondTrust RCE
- **TREND:** "Ransomware without encryption" (pure exfiltration) attacks surging - lower risk for attackers, harder to detect with traditional controls

---

## Critical Vulnerabilities

### CISA KEV Additions - February 2026

| CVE | Product | Type | CVSS | KEV Added | FCEB Deadline |
|-----|---------|------|------|-----------|---------------|
| CVE-2026-1731 | BeyondTrust Remote Support / PRA | OS Command Injection / RCE | 9.9 | 2026-02-13 | 2026-03-06 |
| CVE-2026-21510 | Windows Shell | Security Feature Bypass | 8.8 | 2026-02-10 | 2026-03-03 |
| CVE-2026-21513 | Microsoft MSHTML | Security Feature Bypass | 8.4 | 2026-02-10 | 2026-03-03 |
| CVE-2026-21514 | Microsoft Office Word | Security Feature Bypass | 7.8 | 2026-02-10 | 2026-03-03 |
| CVE-2026-21519 | Windows Desktop Window Manager | Type Confusion / EoP to SYSTEM | 7.8 | 2026-02-10 | 2026-03-03 |
| CVE-2026-21525 | Windows Remote Access Conn. Mgr | NULL Pointer Dereference / DoS | 7.5 | 2026-02-10 | 2026-03-03 |
| CVE-2026-21533 | Windows Remote Desktop Services | Elevation of Privilege to SYSTEM | 7.8 | 2026-02-10 | 2026-03-03 |
| CVE-2025-40551 | SolarWinds Web Help Desk | Deserialization / Unauthenticated RCE | 9.8 | 2026-02-03 | 2026-02-06 |
| CVE-2019-19006 | Sangoma FreePBX | Improper Authentication | N/A | 2026-02-03 | - |
| CVE-2021-39935 | GitLab | SSRF | N/A | 2026-02-03 | - |
| CVE-2025-64328 | Sangoma FreePBX | OS Command Injection | N/A | 2026-02-03 | - |
| CVE-2025-49113 | RoundCube Webmail | Deserialization of Untrusted Data | N/A | 2026-02-20 | - |
| CVE-2025-68461 | RoundCube Webmail | Cross-site Scripting | N/A | 2026-02-20 | - |

### Critical CVEs Requiring Immediate Attention

**CVE-2026-1731 - BeyondTrust Remote Support & PRA (CVSS 9.9)**
- Unauthenticated OS command injection in `thin-scc-wrapper` component
- First exploitation observed February 10, 2026; PoC published same day
- Palo Alto Unit42 confirmed post-exploitation delivery of VShell backdoor and SparkRAT
- Affected: all versions prior to patch; upgrade immediately
- 170+ public-facing SolarWinds WHD installs remain exposed per threat intelligence

**CVE-2025-40551 - SolarWinds Web Help Desk (CVSS 9.8)**
- Unauthenticated Java deserialization via AjaxProxy endpoint
- Enables full system compromise, persistent access, lateral movement
- Patched in SolarWinds WHD v2026.1 (released Jan 28, 2026); no workaround available
- Over 170 vulnerable installations detected exposed online as of mid-February

**CVE-2026-2441 - Google Chrome (CVSS TBD)**
- Critical zero-day actively exploited in wild
- Allows remote code execution within Chrome sandbox
- Patch released; update Chrome immediately to latest stable

**CVE-2026-25049 - n8n Workflow Automation (CVSS 9.4)**
- Inadequate sanitization bypasses protections from CVE-2025-68613 fix
- Enables system command execution via malicious workflows
- Critical for self-hosted n8n deployments; patch immediately

**CVE-2026-24300 - Azure Front Door (CVSS 9.8)**
- Unauthenticated remote elevation of privilege via improper access control
- Patched via February Patch Tuesday; verify Azure environments updated

---

## Exploits & Zero-Days

### Microsoft February 2026 Patch Tuesday - 6 Actively Exploited Zero-Days

All six zero-days were patched on February 10, 2026:

| CVE | Component | Impact | Publicly Disclosed |
|-----|-----------|--------|-------------------|
| CVE-2026-21510 | Windows Shell | Security Feature Bypass (single-click exploit) | Yes |
| CVE-2026-21513 | MSHTML Framework | Security Feature Bypass | Yes |
| CVE-2026-21514 | Microsoft Word | Security Feature Bypass | Yes |
| CVE-2026-21519 | Desktop Window Manager | Type Confusion -> SYSTEM | No |
| CVE-2026-21533 | Remote Desktop Services | EoP -> SYSTEM | No |
| CVE-2026-21525 | Remote Access Conn. Mgr | Denial of Service | No |

**CVE-2026-21510** is of particular concern - a single click on a malicious link silently bypasses Windows protections and executes attacker-controlled content without warning dialogs.

### Chrome Zero-Day - CVE-2026-2441
- Actively exploited in the wild before patch availability
- Successful exploitation allows arbitrary code execution within browser sandbox
- Patch available; deploy immediately across endpoints

### BeyondTrust CVE-2026-1731 - Public PoC Available
- Public proof-of-concept published February 10, 2026
- Exploitation attempts confirmed in the wild; threat actors moving fast
- Palo Alto Unit42 attribution research ongoing; VShell and SparkRAT observed

---

## Malware & Ransomware

### Active Ransomware Campaigns

**Hellcat Ransomware - Ascom Breach**
- Hellcat breached Ascom's ticketing infrastructure, exfiltrating 44GB of sensitive data
- Data stolen: source code, project details, invoices, confidential documents
- Initial access vector: Jira credentials harvested by Infostealer malware
- Demonstrates the infostealer-to-ransomware kill chain gaining operational maturity

**Space Bears Ransomware - Escalating Activity**
- Associated with established Phobos ransomware operations
- Aggressive double extortion: encrypt + threaten data leak
- Focus on mid-market organizations with inadequate backup/recovery

**"Ransomware Without Encryption" - Emerging Trend**
- Pure data exfiltration + extortion model growing rapidly
- Lower operational risk for attackers (no encryption tooling needed)
- Significantly harder for defenders to detect with traditional EDR/AV focused on encryption behavior
- Recommends: DLP controls, network egress monitoring, user behavior analytics

### Winter Olympics Hacktivist Activity
- Since the 2026 Winter Olympics opened in Milan/Cortina d'Ampezzo (Feb 6), researchers tracked increased pro-Russian hacktivist activity
- DDoS campaigns targeting European infrastructure; likely opportunistic

---

## Threat Actors

### UNC3886 (China-Nexus APT) - Singapore Telecom Campaign

**Operation CYBER GUARDIAN** - Singapore's largest-ever multi-agency counter-operation

- **Attribution:** UNC3886 - China-nexus cyber espionage group (Mandiant designation)
- **Targets:** All four major Singapore telecom operators: M1, SIMBA Telecom, Singtel, StarHub
- **TTPs:**
  - Zero-day exploit used to bypass perimeter firewalls
  - Rootkit deployment for persistent, undetected access
  - Deliberate, targeted, long-duration campaign
- **Disclosed:** February 9, 2026 by Singapore's Cyber Security Agency (CSA) and IMDA
- **Data Impact:** No evidence of sensitive or personal customer data exfiltration confirmed
- **Significance:** Targeting all major telcos in a single nation simultaneously is highly aggressive; likely intelligence collection on communications metadata

### Iranian APT Activity
- Iran's coordinated cyber threat landscape expanding beyond hacktivism (CSIS analysis)
- Iranian nation-state APTs actively targeting vital infrastructure sectors
- Coordinated campaigns combining destructive attacks with intelligence collection

---

## Data Breaches

### High-Impact Breaches - February 2026

| Organization | Records Affected | Data Exposed | Disclosure Date |
|-------------|-----------------|--------------|-----------------|
| Odido (Netherlands Telecom) | 6M+ accounts | Names, phone, email, bank accounts, passport numbers | ~Feb 7, 2026 |
| IRS (US Government) | 1.28M individuals | Names + addresses disclosed to DHS/ICE | Feb 12, 2026 |
| Conduent (GovTech) | Millions (expanding) | Government services data | ~Feb 5, 2026 |
| Cottage Hospital | 1,600+ | SSNs, driver's licenses, bank account info | Notified Feb 6 |
| EyeCare Partners | TBD | Healthcare email account contents | Disclosed Feb 2026 |
| MedRevenu | TBD | Healthcare financial data | Disclosed Feb 2026 |

**Odido Breach Details:**
- Dutch telecom impacted; 6M+ account records exposed
- Stolen data includes bank account numbers and passport numbers - high identity theft risk
- Attack first investigated February 7, 2026

**IRS/DHS Data Sharing:**
- IRS Chief Risk Officer confirmed 1.28M individual records shared with ICE via improper process
- Legal challenges filed; significant taxpayer privacy implications
- Secondary risk: exposed data now a high-value target for nation-state and criminal actors

**Conduent Breach Expansion:**
- Government technology giant's breach is expanding in scope, now affecting millions of Americans
- Conduent provides critical payment and benefit administration services to US government agencies

---

## Vendor Advisories

### Microsoft - February 2026 Patch Tuesday (Released Feb 10, 2026)
- **Total CVEs patched:** 58 | **Critical:** 5 | **Exploited Zero-Days:** 6 | **Publicly Disclosed:** 3
- **Breakdown:** EoP (42%), RCE (20%), Spoofing (14%)
- Key products: Windows Shell, MSHTML, Office, Remote Desktop Services, Azure Front Door, Azure Arc
- **Action:** Deploy immediately; prioritize KEV-listed CVEs

### Adobe - February 2026
- 9 security updates resolving **43 CVEs** released alongside Patch Tuesday
- Patch Adobe Reader/Acrobat, Creative Cloud, and other Adobe products

### Google Chrome
- Emergency patch for CVE-2026-2441 (actively exploited zero-day)
- Update to latest Chrome stable immediately across all endpoints

### SolarWinds Web Help Desk
- v2026.1 released January 28, 2026 - patches CVE-2025-40551 (CVSS 9.8)
- No workaround available; upgrade is the only remediation
- Verify no public-facing WHD instances remain on affected versions

### BeyondTrust Remote Support / PRA
- Patch for CVE-2026-1731 available; CISA FCEB deadline March 6, 2026
- All organizations should treat as Priority 1 given active exploitation

### n8n
- Patch for CVE-2026-25049 (CVSS 9.4) available
- Self-hosted deployments require immediate update

---

## Recommended Actions

### Priority 1 - Immediate (Within 24-48 Hours)

1. **Patch BeyondTrust Remote Support/PRA** (CVE-2026-1731, CVSS 9.9) - actively exploited with VShell/SparkRAT post-exploitation; CISA FCEB deadline Mar 6
2. **Upgrade SolarWinds Web Help Desk to v2026.1** (CVE-2025-40551, CVSS 9.8) - scan for exposed instances; 170+ remain vulnerable
3. **Deploy Microsoft February Patch Tuesday** - 6 zero-days actively exploited; prioritize CVE-2026-21510 (single-click Windows Shell bypass) and CVE-2026-21519/21533 (SYSTEM escalation)
4. **Update Google Chrome** on all endpoints - CVE-2026-2441 zero-day actively exploited

### Priority 2 - Within 1 Week

5. **Audit RoundCube Webmail deployments** - CVE-2025-49113 (deserialization) and CVE-2025-68461 (XSS) in CISA KEV; common in government/NGO environments
6. **Patch n8n instances** - CVE-2026-25049 (CVSS 9.4); self-hosted workflow automation
7. **Deploy Adobe February patches** - 43 CVEs addressed
8. **Audit Sangoma FreePBX and GitLab** - older CVEs (2019, 2021) added to KEV indicate active exploitation resumption

### Priority 3 - Within 30 Days

9. **Deploy DLP and network egress monitoring** - counter "ransomware without encryption" trend; traditional AV/EDR blind to pure exfiltration
10. **Audit infostealer credential exposure** - Hellcat/Ascom breach via stolen Jira creds highlights need for credential hygiene; run dark web monitoring
11. **Telecom supply chain review** - UNC3886 targeting of full Singapore telecom sector suggests expanded nation-state interest in telco infrastructure; assess own exposure
12. **IRS/Government data recipients** - verify legal basis for inter-agency PII disclosures; harden access controls on government-sourced data

---

## Sources

- [CISA - Adds Two Known Exploited Vulnerabilities (Feb 20)](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA - Adds Six Known Exploited Vulnerabilities (Feb 10)](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA - Adds Four Known Exploited Vulnerabilities (Feb 3)](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA - Adds One Known Exploited Vulnerability (Feb 13 - BeyondTrust)](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA - Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News - CISA Adds Actively Exploited SolarWinds Web Help Desk RCE to KEV](https://thehackernews.com/2026/02/cisa-adds-actively-exploited-solarwinds.html)
- [Palo Alto Unit42 - VShell and SparkRAT in BeyondTrust CVE-2026-1731](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [Orca Security - CVE-2026-1731 BeyondTrust Vulnerability Analysis](https://orca.security/resources/blog/cve-2026-1731-beyondtrust-vulnerability/)
- [Help Net Security - Windows Admin Center CVE-2026-26119](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)
- [SecPod - Google Chrome Zero-Day CVE-2026-2441](https://www.secpod.com/blog/google-addresses-actively-exploited-chrome-vulnerability-cve-2026-2441/)
- [The Hacker News - Critical n8n Flaw CVE-2026-25049](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [BleepingComputer - Microsoft February 2026 Patch Tuesday: 6 zero-days, 58 flaws](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [SecPod - Microsoft February 2026 Patch Tuesday: Six Zero-Days](https://www.secpod.com/blog/microsofts-february-2026-patch-tuesday-six-zero-days-patched-amid-growing-exploit-activity/)
- [Infosecurity Magazine - Microsoft Fixes Six Zero-Day Vulnerabilities Feb 2026](https://www.infosecurity-magazine.com/news/microsoft-six-zero-day-feb-2026/)
- [Malwarebytes - February 2026 Patch Tuesday Six Zero-Days](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)
- [Zero Day Initiative - February 2026 Security Update Review](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
- [Krebs on Security - Patch Tuesday February 2026](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [Tenable - Microsoft February 2026 Patch Tuesday](https://www.tenable.com/blog/microsofts-february-2026-patch-tuesday-addresses-54-cves-cve-2026-21510-cve-2026-21513)
- [Qualys - Microsoft and Adobe Patch Tuesday February 2026](https://blog.qualys.com/vulnerabilities-threat-research/2026/02/10/microsoft-patch-tuesday-february-2026-security-update-review)
- [Horizon3.ai - CVE-2025-40551 SolarWinds WHD RCE](https://horizon3.ai/attack-research/cve-2025-40551-another-solarwinds-web-help-desk-deserialization-issue/)
- [BleepingComputer - CISA Flags Critical SolarWinds RCE as Exploited](https://www.bleepingcomputer.com/news/security/cisa-flags-critical-solarwinds-rce-flaw-as-actively-exploited/)
- [Bitsight - CVE-2025-40551 SolarWinds Analysis](https://www.bitsight.com/blog/cve-2025-40551-solarwinds-critical-vulnerability)
- [CyberSecurity News - 170+ SolarWinds WHD Installations Vulnerable](https://cybersecuritynews.com/solarwinds-help-desk-installations-vulnerable/)
- [Computer Weekly - Singapore Mounts Largest Cyber Operation vs UNC3886](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [CSA Singapore - Operation CYBER GUARDIAN Press Release](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [CYFIRMA - Weekly Intelligence Report Feb 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [Morphisec - Ransomware Without Encryption: Pure Exfiltration Attacks Surging](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [The Hacker News - From Ransomware to Residency](https://thehackernews.com/2026/02/from-ransomware-to-residency-inside.html)
- [World Economic Forum - Cyber Threats to Watch in 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [TechCrunch - Conduent Data Breach Balloons, Affecting Millions](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [Privacy Guides - Data Breach Roundup Jan 30 - Feb 5, 2026](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [HIPAA Journal - Data Breaches at MedRevenu and EyeCare Partners](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [Valley News - Cottage Hospital Data Breach](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [Evrimagaci - IRS Data Breach and Immigration Deal](https://evrimagaci.org/gpt/irs-data-breach-sparks-outcry-over-immigration-deal-528626)
- [Malwarebytes - Chrome Zero-Day Code Execution](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)
- [SecurityWeek - 6 Actively Exploited Zero-Days Patched by Microsoft](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)
- [Zecurit - Patch Tuesday February 2026 CVE Analysis](https://zecurit.com/endpoint-management/patch-tuesday/)
