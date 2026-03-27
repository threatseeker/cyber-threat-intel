# Cyber Threat Intelligence Report
**Date:** 2026-03-27
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0327

---

## Executive Summary

- **CISA adds Langflow code injection (CVE-2026-33017) and Aqua Trivy malicious code (CVE-2026-33634) to KEV catalog** -- active exploitation confirmed within 20 hours of Langflow disclosure
- **Iranian cyber retaliation campaign escalates** -- Handala Hack (IRGC-linked) wipes 200K+ Stryker medical devices across 79 countries; Seedworm (MuddyWater) compromises US bank, airport, and software company networks
- **Microsoft March Patch Tuesday fixes 79 flaws including 2 zero-days** -- CVE-2026-21262 (SQL Server EoP) and CVE-2026-26127 (.NET DoS); critical Excel Copilot exfiltration flaw (CVE-2026-26144) also patched
- **Critical RCE in GNU Telnetd (CVE-2026-32746, CVSS 9.8)** and Oracle Fusion Middleware (CVE-2026-21992, CVSS 9.8) disclosed
- **Medusa ransomware hits University of Mississippi Medical Center** -- 1TB+ patient data exfiltrated, $800K ransom demanded
- **ShinyHunters breaches Crunchyroll and Woflow** -- 100GB data exfiltrated from Crunchyroll including credit card details and PII
- **Tycoon 2FA phishing-as-a-service platform disrupted** -- 330 control panel domains seized in coordinated takedown

---

## Critical Vulnerabilities

### CISA KEV Additions (March 2026)

| Date | CVE | Product | Type | CVSS |
|------|-----|---------|------|------|
| Mar 26 | CVE-2026-33634 | Aqua Security Trivy | Embedded Malicious Code | TBD |
| Mar 25 | CVE-2026-33017 | Langflow | Code Injection (Unauth) | 9.3 |
| Mar 20 | CVE-2025-31277 | Apple Multiple Products | Buffer Overflow | High |
| Mar 20 | CVE-2025-32432 | Craft CMS | Code Injection | High |
| Mar 20 | CVE-2025-43510 | Apple Multiple Products | Improper Locking | High |
| Mar 20 | CVE-2025-43520 | Apple Multiple Products | Buffer Overflow | High |
| Mar 20 | CVE-2025-54068 | Laravel Livewire | Code Injection | High |
| Mar 03 | 2 additional | Various | Various | High |

### Other Critical CVEs

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-32746 | GNU Telnetd | Unauth RCE (Buffer Overflow) | 9.8 | Disclosed |
| CVE-2026-21992 | Oracle Fusion Middleware | Unauth RCE via HTTP | 9.8 | Disclosed |
| CVE-2026-3055 | Citrix NetScaler ADC/Gateway | OOB Memory Read | Critical | Disclosed |
| CVE-2026-26144 | Microsoft Excel | Copilot Data Exfiltration | Critical | Patched |
| CVE-2026-26110 | Microsoft Office | RCE (Preview Pane) | 8.4 | Patched |
| CVE-2026-26113 | Microsoft Office | RCE (Preview Pane) | 8.4 | Patched |
| CVE-2026-1731 | BeyondTrust Remote Support | Pre-Auth RCE | Critical | Active Exploitation |

---

## Exploits & Zero-Days

### Langflow CVE-2026-33017 -- Exploited Within 20 Hours
- **CVSS:** 9.3
- **Impact:** Missing authentication + code injection allows unauthenticated RCE on public-facing Langflow instances
- **Timeline:** Disclosed -> exploited in the wild within 20 hours -> CISA KEV on March 25
- **Action:** Patch immediately or restrict network access to Langflow instances

### Microsoft March 2026 Zero-Days
- **CVE-2026-21262** (CVSS 8.8): SQL Server elevation of privilege -- authenticated user can escalate to sysadmin
- **CVE-2026-26127** (CVSS 7.5): .NET denial of service -- remote crash of .NET applications
- Both were publicly disclosed prior to patch; no confirmed active exploitation at time of patching

### Aqua Security Trivy Supply Chain Attack
- **CVE-2026-33634**: Embedded malicious code vulnerability in Aqua Security Trivy
- Added to CISA KEV March 26 -- indicates active exploitation
- Supply chain implications for organizations using Trivy for container scanning

---

## Malware & Ransomware

### Medusa Ransomware -- Healthcare Sector Targeting
- **Target:** University of Mississippi Medical Center (UMMC)
- **Date:** Listed on Medusa leak site March 12, 2026
- **Impact:** 1TB+ exfiltrated including patient health information and employee records
- **Demand:** $800,000 ransom
- **Also targeted:** Passaic County, New Jersey government systems

### BeyondTrust Exploitation in Ransomware Campaigns
- CVE-2026-1731 (pre-auth RCE in BeyondTrust Remote Support) actively used in ransomware operations
- CISA issued three-day patch mandate for federal agencies

### Tycoon 2FA Takedown
- Coordinated disruption announced March 4, 2026
- 330 Tycoon 2FA phishing-as-a-service control panel domains seized
- Platform was a prolific adversary-in-the-middle (AiTM) phishing service

### Threat Landscape Trends
- Significant wave of attacks tied to North Korea, Russia, and Iran -- potentially coordinated with geopolitical tensions
- Healthcare sector remains primary target for ransomware operators

---

## Threat Actors

### Handala Hack (IRGC-linked) -- Operation Against Stryker
- **Aliases:** Void Manticore, Storm-842
- **Attribution:** Islamic Revolutionary Guard Corps (IRGC)
- **Action:** Destructive wipe of 200,000+ Stryker medical devices across 79 countries on March 11
- **Method:** Compromised Microsoft Intune admin credentials -> remote wipe command
- **Motivation:** Claimed retaliation for February 28 military strikes (Operation Epic Fury / Operation Roaring Lion)
- **Additional targets:** Sharjah National Oil Corporation, Israel Opportunity Energy

### Seedworm / MuddyWater (Iranian APT)
- **Aliases:** Temp Zagros, Static Kitten
- **Activity:** Active on US networks since February 2026, continuing post-military strikes
- **Confirmed targets:** US bank, US airport, non-profit organization, Israeli operations of a US software company
- **TTPs:** AI-enhanced spear-phishing, exploitation of known vulnerabilities, covert infrastructure

### ShinyHunters
- **Crunchyroll breach** (March 12): ~100GB exfiltrated via compromised Telus employee
- **Woflow breach** (March 3): Network systems disabled, data posted to dark web
- Continues to be one of the most active data theft groups

---

## Data Breaches

| Date | Organization | Records/Impact | Details |
|------|-------------|----------------|---------|
| Mar 12 | Crunchyroll (Sony) | ~100GB data | ShinyHunters via compromised Telus employee; includes credit cards, PII, analytics |
| Mar 13 | Navia Benefit Solutions | 2,697,540 individuals | Substitute breach notice posted |
| Mar 12 | UMMC | 1TB+ patient data | Medusa ransomware; PHI and employee records |
| Mar 3 | Woflow | Undisclosed | ShinyHunters; data posted to dark web |
| Mar | Aura (identity protection) | ~900,000 records | Names and email addresses compromised |
| Mar | Deaconess Health System | Under investigation | Breach investigation launched |
| Mar | Intuitive Surgical | Under investigation | Cybersecurity incident disclosed |

---

## Vendor Advisories

### Microsoft -- March 2026 Patch Tuesday (March 11)
- **79 vulnerabilities** patched (3 Critical, 2 zero-days)
- Critical: CVE-2026-26144 (Excel Copilot exfiltration), CVE-2026-26110 & CVE-2026-26113 (Office RCE)
- Six flaws flagged as "more likely" to be exploited

### Apple
- Emergency security updates for iOS/iPadOS targeting legacy devices (pre-iOS 16/17)
- Four high-severity patches

### Google
- Android March security bulletin with multiple vulnerability patches
- Edge 145.0.3800.97 (Chromium 145.0.7632.160) fixing 10 vulnerabilities

### Adobe
- Security updates for Commerce, Illustrator, Substance 3D Painter, Acrobat Reader, Premiere Pro

### Cisco
- Multiple product security updates released; review advisory portal for specifics

### Oracle
- CVE-2026-21992 affecting Identity Manager and Web Services Manager (CVSS 9.8)

---

## Recommended Actions

1. **IMMEDIATE: Patch Langflow** (CVE-2026-33017) -- active exploitation confirmed; restrict public access to Langflow instances
2. **IMMEDIATE: Audit Aqua Trivy installations** (CVE-2026-33634) -- supply chain risk; verify integrity of container scanning infrastructure
3. **IMMEDIATE: Patch BeyondTrust Remote Support** (CVE-2026-1731) -- active ransomware exploitation
4. **HIGH: Apply Microsoft March Patch Tuesday** -- prioritize CVE-2026-26144 (Excel Copilot exfiltration) and Office RCE flaws
5. **HIGH: Patch Oracle Fusion Middleware** (CVE-2026-21992) and GNU Telnetd (CVE-2026-32746) -- both CVSS 9.8 unauth RCE
6. **HIGH: Review Intune and MDM security** -- Handala attack leveraged compromised Intune admin credentials for mass device wipe
7. **MEDIUM: Monitor for Iranian APT indicators** -- Seedworm/MuddyWater active against US infrastructure; review Unit42 threat brief for IOCs
8. **MEDIUM: Assess third-party vendor risk** -- ShinyHunters breached Crunchyroll via Telus employee; review vendor access controls
9. **ONGOING: Healthcare sector -- heightened alert** -- Medusa and state-sponsored actors actively targeting healthcare organizations

---

## Sources

- [CISA Adds Five KEV - March 20](https://www.cisa.gov/news-events/alerts/2026/03/20/cisa-adds-five-known-exploited-vulnerabilities-catalog)
- [CISA Adds Langflow KEV - March 26](https://www.cisa.gov/news-events/alerts/2026/03/26/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA Adds Trivy KEV - March 25](https://therealistjuggernaut.com/2026/03/25/active-exploitation-confirmed-cisa-adds-langflow-code-injection-flaw-to-kev-catalog-signaling-immediate-risk-to-federal-and-private-systems/)
- [Critical Langflow Flaw - The Hacker News](https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html)
- [Oracle CVE-2026-21992 - Sophos](https://www.sophos.com/en-us/blog/oracle-vulnerability-cve-2026-21992-impacts-core-products)
- [GNU Telnetd CVE-2026-32746 - The Hacker News](https://thehackernews.com/2026/03/critical-telnetd-flaw-cve-2026-32746.html)
- [Citrix CVE-2026-3055 - Arctic Wolf](https://arcticwolf.com/resources/blog/cve-2026-3055/)
- [Microsoft March 2026 Patch Tuesday - BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/)
- [Microsoft Patch Tuesday - Krebs on Security](https://krebsonsecurity.com/2026/03/microsoft-patch-tuesday-march-2026-edition/)
- [March 2026 Patch Tuesday Zero-Days - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/03/march-2026-patch-tuesday-fixes-two-zero-day-vulnerabilities)
- [SQL Server Zero-Day - SOC Prime](https://socprime.com/blog/cve-2026-21262-vulnerability/)
- [CrowdStrike Patch Tuesday Analysis](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-march-2026/)
- [Iranian Cyber Escalation - Unit42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [Stryker Attack - Cyber Magazine](https://cybermagazine.com/news/iran-war-cyber-front-stryker-cyber-attack)
- [Seedworm Iranian APT - Security.com](https://www.security.com/threat-intelligence/iran-cyber-threat-activity-us)
- [Iranian Cyber Capability 2026 - Trellix](https://www.trellix.com/blogs/research/the-iranian-cyber-capability-2026/)
- [Ransomware US 2026 Insights - Security Boulevard](https://securityboulevard.com/2026/03/ransomware-attacks-against-the-us-2026-insights/)
- [Medusa Ransomware - SWK Technologies](https://www.swktech.com/swk-technologies-march-2026-cybersecurity-news-recap/)
- [Monthly Threat Report March 2026 - Hornetsecurity](https://www.hornetsecurity.com/en/blog/monthly-threat-report/)
- [Crunchyroll Breach - Cybernews](https://cybernews.com/security/crunchyroll-data-breach-telus-hack-users/)
- [Crunchyroll Breach Analysis - SOCRadar](https://socradar.io/blog/crunchyroll-data-breach-what-to-know/)
- [Navia Benefit Solutions Breach - HIPAA Journal](https://www.hipaajournal.com/navia-benefit-solutions-data-breach/)
- [Woflow Breach - ClassAction.org](https://www.classaction.org/news/woflow-hit-with-class-action-over-march-2026-data-breach-allegedly-affecting-thousands)
- [2026 Data Breaches - PKWARE](https://www.pkware.com/blog/2026-data-breaches)
- [Intuitive Surgical Incident](https://www.intuitive.com/en-us/about-us/newsroom/Intuitive-statement-on-cybersecurity-incident)
- [Vendor Advisories - CSC Gov](https://csc.gov.im/news-advisories/vulnerability-notice-microsoft-apple-security-releases-march-2026/)
- [Qualys Patch Tuesday Review](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/10/microsoft-patch-tuesday-march-2026-security-update-review)
