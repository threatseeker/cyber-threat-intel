# Cyber Threat Intelligence Report
**Date:** 2026-02-21
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0221

---

## Executive Summary

- **NEW - CRITICAL**: Two CVSS 10.0 flaws in Linux Cyber Protect (CVE-2025-30411, CVE-2025-30412) disclosed Friday Feb 20 - maximum severity, patch immediately
- **NEW - CRITICAL**: Microsoft Semantic Kernel Python SDK CVE-2026-26030 (CVSS 9.9) - AI/ML supply chain risk for organizations using this SDK
- **NEW**: Linux Kernel patches published Feb 20 for WWAN subsystem and DAMON memory monitoring interface vulnerabilities
- **NEW**: Odido (Dutch telecom) breach - 6+ million customer accounts exposed including bank account numbers and passport numbers
- **NEW**: Figure fintech company breached by Shiny Hunterz ransomware group - internal documents and client PII compromised
- **NEW**: Cisco patches for Meeting Management and Secure Web Appliance released; Fortinet FortiOS/FortiSandbox advisories issued
- **[UPDATE] URGENT**: CISA KEV deadline for FreePBX (CVE-2019-19006), Sangoma (CVE-2025-64328), and GitLab (CVE-2021-39935) is **Monday February 24** - 3 days remaining
- **[UPDATE]**: Winter Olympics closes tomorrow (Feb 22) - pro-Russian hacktivist activity expected at peak; remain on elevated alert

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2025-30411 | Linux Cyber Protect | **10.0** | Remote Code Execution | Disclosed Feb 20 - patch immediately |
| CVE-2025-30412 | Linux Cyber Protect | **10.0** | Remote Code Execution | Disclosed Feb 20 - patch immediately |
| CVE-2026-26030 | Microsoft Semantic Kernel (Python SDK) | **9.9** | AI/ML Code Execution | Newly disclosed |
| CVE-2019-19006 | Sangoma FreePBX | High | Improper Authentication | **CISA KEV - deadline Feb 24 (3 days!)** |
| CVE-2025-64328 | Sangoma FreePBX | High | OS Command Injection | **CISA KEV - deadline Feb 24 (3 days!)** |
| CVE-2021-39935 | GitLab CE/EE | High | SSRF | **CISA KEV - deadline Feb 24 (3 days!)** |

### CVE-2025-30411 & CVE-2025-30412 - Linux Cyber Protect (CVSS 10.0 each)

**Product:** Linux Cyber Protect
**CVSS:** 10.0 (maximum severity) - both vulnerabilities
**Disclosed:** February 20, 2026

Two maximum-severity remote code execution flaws in Linux Cyber Protect were publicly disclosed on Friday. CVSS 10.0 ratings indicate unauthenticated, network-accessible, low-complexity exploitation with complete impact on confidentiality, integrity, and availability.

- **Action**: Apply vendor patches immediately; isolate Linux Cyber Protect systems from untrusted networks pending patch
- **Source**: [Zecurit - February 2026 Patch Tuesday CVE Analysis](https://zecurit.com/endpoint-management/patch-tuesday/)

### CVE-2026-26030 - Microsoft Semantic Kernel Python SDK (CVSS 9.9)

**Product:** Microsoft Semantic Kernel Python SDK
**CVSS:** 9.9
**Type:** Code execution via AI/ML workflow pipeline

A critical vulnerability in the Microsoft Semantic Kernel Python SDK (a widely used AI/LLM orchestration framework) enables near-maximal code execution. Organizations integrating Semantic Kernel into AI pipelines or agentic workflows are at risk. This represents a supply chain risk for the growing AI developer ecosystem.

- **Action**: Update Semantic Kernel Python SDK to latest patched version; audit AI application pipelines that incorporate this SDK; review input validation in any user-facing AI integrations
- **Source**: [Zecurit - February 2026 Patch Tuesday CVE Analysis](https://zecurit.com/endpoint-management/patch-tuesday/)

### [UPDATE] CISA KEV Deadlines - Critical 3-Day Warning

Federal agencies must remediate the following by **Monday, February 24, 2026**:

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2019-19006 | Sangoma FreePBX - Improper Authentication | **Feb 24 (3 DAYS)** |
| CVE-2025-64328 | Sangoma FreePBX - OS Command Injection | **Feb 24 (3 DAYS)** |
| CVE-2021-39935 | GitLab CE/EE - SSRF | **Feb 24 (3 DAYS)** |

Non-federal organizations should treat these as high-priority regardless of KEV mandate.

- **Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Exploits & Zero-Days

### Linux Kernel - WWAN Subsystem & DAMON Memory Monitoring Vulnerabilities

**Disclosed:** February 20, 2026
**Components Affected:** WWAN (Wireless Wide Area Network) subsystem; DAMON (Data Access MONitor) memory monitoring interface

The Linux kernel security team published patches on February 20 for two newly disclosed vulnerabilities:
- **WWAN subsystem vulnerability**: Affects drivers for cellular modem modules common in IoT and enterprise laptops
- **DAMON interface vulnerability**: Affects kernel memory management monitoring interface

- **Action**: Apply latest Linux kernel security updates; particularly prioritize for kernel 6.x deployments with WWAN hardware or DAMON enabled
- **Source**: [Linux Kernel - Notable Vulnerabilities Feb 2026](https://pbxscience.com/linux-kernel-patches-two-notable-vulnerabilities-in-february-2026/)

---

## Malware & Ransomware

### NEW: Shiny Hunterz Ransomware - Figure Fintech Breach

**Victim:** Figure (Nevada-based fintech company)
**Threat Actor:** Shiny Hunterz ransomware group
**Data Compromised:** Internal corporate documents; personal information of clients

Shiny Hunterz - not to be confused with the better-known ShinyHunters - compromised Figure's systems and exfiltrated internal documents along with client PII. Figure provides financial services including home equity lines of credit. Client financial records may be among the exposed data.

- **Action**: If you are a Figure customer, monitor for phishing and credential stuffing attacks using exposed PII; change passwords on any accounts where Figure credentials were reused
- **Source**: [SharkStriker - February 2026 Data Breaches](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)

### [UPDATE] Ransomware Landscape - State of Play Feb 21

- BlackFog's 2026 State of Ransomware report (Feb 12) confirms **49% increase in attacks YoY**
- Most active groups currently: Qilin, Akira, Cl0p, Play, Shiny Hunterz
- Ongoing: Qilin's attack on Conpet (Romanian oil pipeline) - operational impact still being assessed
- Ongoing: Advantest (semiconductor testing) - no ransomware group has claimed responsibility as of Feb 21

- **Source**: [BlackFog State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/)

---

## Threat Actors

### [UPDATE] Pro-Russian Hacktivists - Winter Olympics Closing Ceremony Alert

**Context:** 2026 Winter Olympics (Milan/Cortina d'Ampezzo) closes **tomorrow, February 22**
**Pattern:** Pro-Russian hacktivist groups have been intensifying DDoS and defacement activity since opening day (Feb 6) due to Russia's exclusion from the Games

Closing ceremonies typically represent a peak moment for protest-motivated hacktivist activity. Organizations with Italian presence, Olympic sponsors, and organizations in Western nations supporting the Games should remain on elevated alert through February 22-23.

**Targets to Monitor:** Italian government infrastructure; Olympic broadcast systems; major Western media organizations; Olympic corporate sponsors

- **Source**: [CYFIRMA Weekly Intelligence - Feb 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)

---

## Data Breaches

| Organization | Records Affected | Data Exposed | Threat Actor | Notes |
|-------------|-----------------|--------------|--------------|-------|
| Odido (Dutch Telecom) | **6+ million** | Names, phone, email, bank accounts, passport numbers | Unknown | Unauthorized access confirmed Feb 7-2026; terminated |
| Figure (Fintech) | Unknown | Internal documents, client PII | Shiny Hunterz | Ransomware exfiltration |

### NEW: Odido - 6 Million Customer Accounts Exposed

**Organization:** Odido (Netherlands' third-largest telecommunications provider)
**Accounts Affected:** Over 6 million customers
**Data Exposed:** Customer names, telephone numbers, email addresses, **bank account numbers**, **passport numbers**
**Attack Timeline:** Unauthorized access first detected February 7, 2026; access terminated upon discovery

The breadth of data exposed is severe - passport numbers and bank account information enable identity fraud and financial crimes. With 6 million accounts representing a significant portion of the Netherlands' 17.9 million population, this breach has national-scale impact.

- **Action**: Organizations with Dutch operations or Odido integrations should alert affected employees/customers; watch for BEC and identity fraud using Odido customer data
- **Source**: [SharkStriker - February 2026 Data Breaches](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)

---

## Vendor Advisories

### Cisco - New Patches (February 2026)

**Products:** Cisco Secure Web Appliance, Cisco Meeting Management
**Status:** Security updates released

Cisco released security updates for:
- **Cisco Secure Web Appliance**: Web proxy/content filtering appliance used in enterprise environments
- **Cisco Meeting Management**: Video conferencing management platform

- **Action**: Apply Cisco patches; review Cisco PSIRT advisories for full CVE details
- **Source**: [GovInfoSecurity - Cisco HPE n8n Patch Alerts](https://www.govinfosecurity.com/no-rest-in-2026-as-patch-alerts-amass-for-cisco-hpe-n8n-a-30482)

### Fortinet - FortiOS and FortiSandbox Advisories

**Products:** FortiOS (firewall/VPN OS), FortiSandbox (threat analysis sandbox)
**Status:** Security advisories issued

Fortinet released advisories covering FortiOS and FortiSandbox. Given Fortinet's prevalence in enterprise perimeter security, these advisories should be treated as high priority.

- **Action**: Review Fortinet PSIRT advisories; apply patches per vendor guidance; FortiOS patches are particularly critical given widespread deployment
- **Source**: [GovInfoSecurity - Cisco HPE n8n Patch Alerts](https://www.govinfosecurity.com/no-rest-in-2026-as-patch-alerts-amass-for-cisco-hpe-n8n-a-30482)

### Linux Kernel
- WWAN subsystem and DAMON memory interface patches published February 20 - apply via standard kernel update process
- **Source**: [Linux Kernel Patches Feb 2026](https://pbxscience.com/linux-kernel-patches-two-notable-vulnerabilities-in-february-2026/)

---

## CISA KEV Deadline Tracker (Updated Feb 21)

| CVE | Product | CISA Deadline | Status |
|-----|---------|---------------|--------|
| CVE-2019-19006 | FreePBX | **Feb 24** | **URGENT - 3 DAYS** |
| CVE-2025-64328 | Sangoma FreePBX | **Feb 24** | **URGENT - 3 DAYS** |
| CVE-2021-39935 | GitLab CE/EE | **Feb 24** | **URGENT - 3 DAYS** |
| CVE-2026-21510/21513/21514/21519/21525/21533 | Microsoft (6 zero-days) | Mar 3 | 10 days |
| CVE-2026-1731 | BeyondTrust RS/PRA | ~Mar 6 | 13 days |
| CVE-2025-49113 | RoundCube Webmail | TBD | ACTIVELY EXPLOITED |
| CVE-2025-68461 | RoundCube Webmail | TBD | ACTIVELY EXPLOITED |
| CVE-2026-22769 | Dell RecoverPoint | TBD | ACTIVELY EXPLOITED (UNC6201) |
| CVE-2025-30411 | Linux Cyber Protect | TBD | **NEW - CVSS 10.0** |
| CVE-2025-30412 | Linux Cyber Protect | TBD | **NEW - CVSS 10.0** |

---

## Recommended Actions

### Priority 1 - Patch Within 24 Hours
1. **Linux Cyber Protect**: Apply vendor patches for CVE-2025-30411 and CVE-2025-30412 (CVSS 10.0 each - maximum severity RCE)
2. **Microsoft Semantic Kernel Python SDK**: Update to latest patched version (CVE-2026-26030, CVSS 9.9) - critical for AI/ML engineering teams

### Priority 2 - Before Monday Feb 24 (CISA KEV Deadline)
3. **Sangoma FreePBX**: Patch CVE-2019-19006 (Improper Auth) and CVE-2025-64328 (OS Command Injection) - deadline in 3 days
4. **GitLab CE/EE**: Patch CVE-2021-39935 (SSRF) - deadline in 3 days

### Priority 3 - This Week
5. **Cisco**: Apply patches for Secure Web Appliance and Meeting Management
6. **Fortinet**: Apply FortiOS and FortiSandbox security advisories
7. **Linux Kernel**: Apply Feb 20 kernel security updates (WWAN + DAMON)
8. **AI/ML Supply Chain Audit**: Inventory use of Microsoft Semantic Kernel SDK across development and production AI pipelines; validate input sanitization

### Priority 4 - Process & Awareness
9. **Odido Breach Response**: Alert employees and business partners about potential targeting using exposed Dutch telecom customer data (names, bank accounts, passports)
10. **Winter Olympics Hacktivist Peak (Feb 22)**: If operating in Italy, as an Olympic sponsor, or in critical infrastructure - maintain elevated monitoring through Feb 23
11. **BeyondTrust Implant Hunt**: Continue hunting for VShell/SparkRAT artifacts on previously exposed BeyondTrust RS/PRA systems even if patched
12. **Figure Customer Alerts**: If your organization uses Figure for financial services, issue phishing awareness guidance to employees

---

## Sources

- [Zecurit - February 2026 Patch Tuesday CVE Analysis](https://zecurit.com/endpoint-management/patch-tuesday/)
- [Linux Kernel - Notable Vulnerabilities Feb 2026](https://pbxscience.com/linux-kernel-patches-two-notable-vulnerabilities-in-february-2026/)
- [GovInfoSecurity - Cisco, HPE, n8n Patch Alerts](https://www.govinfosecurity.com/no-rest-in-2026-as-patch-alerts-amass-for-cisco-hpe-n8n-a-30482)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CYFIRMA Weekly Intelligence Report - February 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [SharkStriker - Top Data Breaches February 2026](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)
- [BlackFog - State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [WEF - 2026 Cyberthreats to Watch](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [Bleeping Computer - February 2026 Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [Help Net Security - February 2026 Patch Tuesday](https://www.helpnetsecurity.com/2026/02/11/february-2026-patch-tuesday/)
- [Malwarebytes - Six Zero-Days Patch Tuesday](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)

---

*Report generated: 2026-02-21*
*Next report: 2026-02-22*
*Classification: TLP:CLEAR*
*Deduplication: Items from Feb 18 and Feb 20 reports not repeated unless marked [UPDATE]. See previous reports for: BeyondTrust CVE-2026-1731, Microsoft Patch Tuesday zero-days, Chrome CVE-2026-2441, Dell RecoverPoint CVE-2026-22769, RoundCube KEV additions, Windows Admin Center CVE-2026-26119, Advantest/Qilin/Conpet ransomware, MedRevenu/EyeCare healthcare breaches, UNC3886/UNC6201 campaigns, Conduent/Harvard/IRS breaches.*
