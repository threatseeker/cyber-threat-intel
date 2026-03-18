# Cyber Threat Intelligence Report
**Date:** 2026-03-17
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0317

---

## Executive Summary

- **CRITICAL [NEW]:** CVE-2026-25769 (CVSS 9.1) - Wazuh cluster RCE via insecure deserialization; affects versions 4.0.0-4.14.2; attacker on compromised worker node gains root RCE on master; disclosed March 17
- **CRITICAL [NEW]:** CVE-2026-23813 (CVSS 9.8) - HPE Aruba AOS-CX unauthenticated admin password reset via web management interface; affects CX 4100i through CX 10000 series switches; patches available
- **CRITICAL [NEW]:** CVE-2026-4182 (CVSS 9.8) - D-Link DIR-816 stack buffer overflow; unauthenticated RCE; EoL product, no patch expected; public exploit available
- **HIGH [NEW]:** CISA adds CVE-2025-47813 (Wing FTP Server) to KEV on March 16 - actively exploited for Lua-based malware delivery and RMM tool installation; FCEB deadline March 30
- **HIGH [NEW]:** LeakNet ransomware adopts ClickFix social engineering via compromised websites with Deno-based in-memory loader - evading most endpoint security tools
- **HIGH [NEW]:** Intuitive Surgical (da Vinci robotics) discloses phishing-based breach on March 13 - healthcare provider PII and employee data compromised; second major medtech breach after Stryker
- **HIGH [NEW]:** TELUS Digital confirms ShinyHunters breach - nearly 1 petabyte of data stolen including source code, FBI background checks, voice recordings, and BPO customer data for 28+ companies
- **HIGH [NEW]:** DOGE/SSA whistleblower investigation deepens - former DOGE engineer allegedly exfiltrated 500M+ Americans' Social Security records on thumb drive; DOJ confirmed data mishandling
- **HIGH [NEW]:** Infutor/Verisk alleged breach - 676M consumer records (names, SSNs, DOBs) posted on dark web by threat actor "Spirigatito"; unconfirmed by vendor
- **HIGH [NEW]:** CarGurus breach linked to ShinyHunters - 12.4M records exposed including finance pre-qualification data; class action filed

---

## Critical Vulnerabilities

### CISA KEV - New Addition March 16, 2026

| CVE | Product | Type | CVSS | KEV Date | FCEB Due |
|-----|---------|------|------|----------|----------|
| CVE-2025-47813 | Wing FTP Server (< 7.4.4) | Information Disclosure (path leak via UID cookie) | 4.3 | 2026-03-16 | 2026-03-30 |

> **Note:** While the CVSS is moderate, active exploitation involves chaining the path disclosure with Lua file execution, reconnaissance, and RMM software installation. Treat as high-priority.

### New Critical/High CVEs

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-25769 | Wazuh (4.0.0-4.14.2) | RCE via Insecure Deserialization (cluster protocol) | 9.1 | Disclosed March 17; patch in 4.14.3 |
| CVE-2026-23813 | HPE Aruba AOS-CX Switches | Unauthenticated Admin Password Reset | 9.8 | Patches available (10.17.1001+) |
| CVE-2026-23814/15/16 | HPE Aruba AOS-CX Switches | Authenticated Command Injection (3 CVEs) | High | Patched alongside CVE-2026-23813 |
| CVE-2026-4182 | D-Link DIR-816 v1.10CNB05 | Stack Buffer Overflow (RCE, no auth) | 9.8 | EoL, no patch; public exploit |

---

## Exploits & Zero-Days

### CVE-2025-47813 - Wing FTP Server Actively Exploited (CISA KEV March 16)
Originally disclosed in May 2025 by researcher Julien Ahrens (RCE Security), this vulnerability in Wing FTP Server's `/loginok.html` endpoint leaks the server installation path via oversized UID cookie values. While initially rated CVSS 4.3, real-world exploitation has been observed since July 2025. Attackers chain the path disclosure to download and execute malicious Lua scripts, conduct reconnaissance, and install remote monitoring/management (RMM) software for persistent access. Patched in version 7.4.4. **FCEB agencies must remediate by March 30, 2026.**

### CVE-2026-25769 - Wazuh Cluster RCE (Disclosed March 17)
A critical deserialization vulnerability in Wazuh's cluster communication protocol allows an attacker with access to any worker node to achieve root-level RCE on the master node. This is particularly dangerous because Wazuh is a security monitoring platform - compromising the SIEM itself provides attackers with visibility into defender operations and the ability to suppress alerts. Affects all cluster-mode deployments running versions 4.0.0 through 4.14.2. **Update to 4.14.3 immediately.**

### CVE-2026-23813 - HPE Aruba AOS-CX Admin Takeover (CVSS 9.8)
A critical authentication bypass in the web-based management interface of HPE Aruba Networking AOS-CX switches allows remote unauthenticated attackers to reset administrator passwords. Affects CX 4100i, 6000, 6100, 6200, 6300, 6400, 8320, 8325, 8360, 9300, and 10000 series. Three additional high-severity command injection flaws (CVE-2026-23814/15/16) were patched simultaneously. HPE released updated firmware versions 10.17.1001, 10.16.1030, 10.13.1161, and 10.10.1180.

### CVE-2026-4182 - D-Link DIR-816 Stack Buffer Overflow (Public Exploit)
Critical stack-based buffer overflow in the D-Link DIR-816 router's `form2Wl5RepeaterStep2.cgi` endpoint. Remote unauthenticated attackers can trigger the overflow via manipulated key1-key4 or pskValue arguments to achieve arbitrary code execution. A public exploit is available. This is an end-of-life product with no expected patch - **replace immediately.**

---

## Malware & Ransomware

### LeakNet Ransomware - ClickFix + Deno In-Memory Loader [NEW]
ReliaQuest published research in mid-March 2026 detailing a significant evolution in LeakNet ransomware operations:

- **Initial access:** ClickFix social engineering via compromised legitimate websites - victims tricked into running malicious commands through fake error prompts
- **Loader:** Deno JavaScript runtime-based in-memory loader that evades most endpoint detection tools
- **Post-exploitation chain:** jli.dll side-loading into Java (USOShared directory), PsExec lateral movement, S3 bucket payload staging
- **Scale:** Currently ~3 victims/month but actively scaling up
- **Significance:** Shift from IAB-purchased credentials to self-sufficient initial access indicates operational maturation

**Recommendation:** Implement ClickFix-aware user training. Monitor for Deno runtime execution in enterprise environments. Hunt for jli.dll side-loading in USOShared directories.

### GlassWorm Campaign - Python Repository Poisoning [UPDATE]
The GlassWorm supply chain campaign has expanded beyond VS Code extensions and npm packages to now include Python repositories. Attackers are using stolen GitHub tokens to inject obfuscated code into Django apps, ML research code, Streamlit dashboards, and PyPI packages. This significantly broadens the attack surface beyond the previously reported Open VSX and npm vectors.

---

## Threat Actors

### ShinyHunters - Multi-Target Breach Spree [NEW]
ShinyHunters is conducting an aggressive multi-target campaign leveraging SaaS platform credentials:

- **TELUS Digital:** Confirmed breach of nearly 1 petabyte of data including source code, FBI background checks, voice recordings, financial data, and Salesforce data for 28+ named companies. Entry vector traced to Google Cloud Platform credentials discovered in data from the Salesloft Drift breach.
- **CarGurus:** 12.4M records exposed including names, phone numbers, emails, addresses, and auto finance pre-qualification details. 3.7M records are newly unique (not in prior breaches). Class action lawsuit filed March 6.
- **TTP:** Voice phishing (vishing) to credential-harvesting pages targeting SaaS platforms (Salesforce, Okta, Microsoft 365); cascading access from one breach to enable the next.

### DOGE/SSA - Insider Threat Investigation [NEW]
The Social Security Administration's Inspector General is investigating whistleblower allegations that a former DOGE engineer:

- Exfiltrated SSA "Numident" and "Master Death File" databases containing records on 500M+ living and dead Americans (SSNs, DOBs, citizenship, race/ethnicity, parents' names)
- Stored data on a personal thumb drive
- Retained "God-level" access to SSA systems after departure
- Allegedly planned to share data with private-sector employer

DOJ has confirmed data mishandling occurred. Senator Wyden characterized this as potentially "one of the largest known data breaches in American history." Investigation is ongoing across multiple Congressional committees.

---

## Data Breaches

### Intuitive Surgical - Phishing-Based Breach (March 13) [NEW]
The da Vinci surgical robotics manufacturer disclosed that on March 13, unauthorized actors accessed internal IT business applications after stealing employee credentials via phishing:

- **Exposed data:** Healthcare provider names, titles, specialties, emails, phone numbers, facility addresses, plus Intuitive employee and corporate data
- **Operations impact:** None - da Vinci, Ion, and digital platforms unaffected due to segmented network architecture
- **Context:** Second major medtech breach within one week (following Stryker's Handala wiper attack)

### Infutor/Verisk - Alleged 676M Record Exposure (March 8-9) [NEW]
Threat actor "Spirigatito" posted an alleged 676,798,866-record dataset from Infutor (consumer identity management platform, now under Verisk/ActiveProspect) on underground forums:

- **Claimed data:** Full names, DOBs, physical addresses, phone numbers, Social Security numbers
- **Root cause (alleged):** Misconfigured Elasticsearch database (per SOCRadar analysis)
- **Status:** Unconfirmed by vendor; no regulatory filings as of reporting date
- **Scale:** If verified, would be one of the largest consumer data exposures in history

### TELUS Digital - 1PB Breach Confirmed (March 12) [NEW]
TELUS Digital confirmed unauthorized access after ShinyHunters claimed nearly 1 petabyte of stolen data:

- **Stolen data:** Customer support recordings, source code, employee records (including FBI background checks), financial information, Salesforce data
- **Scope:** 28+ BPO customer companies potentially affected
- **Entry vector:** GCP credentials from Salesloft Drift breach
- **Response:** Forensic investigation with law enforcement engagement ongoing

### CarGurus - 12.4M Records (Disclosed February, Updated March) [NEW]
ShinyHunters published 6.1GB archive containing 12.4M CarGurus user records on February 21:

- **Exposed data:** Names, phone numbers, emails, physical addresses, finance pre-qualification details
- **Unique records:** ~3.7M not previously in breach databases
- **Legal action:** Class action filed March 6 (Campbell v. CarGurus, Inc.)

---

## Vendor Advisories

| Vendor | Release Date | Key Items |
|--------|-------------|-----------|
| HPE Aruba | March 2026 | CVE-2026-23813 (CVSS 9.8, admin password reset) + 3 high-severity command injection flaws in AOS-CX; firmware updates available |
| Wing FTP Server | May 2025 (patch); March 16 KEV | CVE-2025-47813 actively exploited; update to 7.4.4+ |
| Wazuh | March 17, 2026 | CVE-2026-25769 (CVSS 9.1, cluster RCE); update to 4.14.3 |
| D-Link | N/A (EoL) | CVE-2026-4182 (CVSS 9.8, DIR-816 stack overflow); CVE-2026-0625 (DSL gateways); no patches - replace devices |

---

## Recommended Actions

1. **IMMEDIATE (24h):** Update Wazuh cluster deployments to 4.14.3 - CVE-2026-25769 allows root RCE on master from any compromised worker node; compromising SIEM infrastructure is catastrophic
2. **IMMEDIATE (24h):** Patch HPE Aruba AOS-CX switches to firmware 10.17.1001+ - CVE-2026-23813 (CVSS 9.8) allows unauthenticated admin password reset; restrict management interface access pending patching
3. **IMMEDIATE (24h):** Update Wing FTP Server to 7.4.4+ - actively exploited (CISA KEV); FCEB deadline March 30; attackers deploying Lua-based malware and RMM tools
4. **URGENT (48h):** Replace D-Link DIR-816 and DSL gateway devices affected by CVE-2026-4182 and CVE-2026-0625 - public exploits available, no patches forthcoming
5. **HIGH (7 days):** Assess TELUS Digital supply chain exposure - if TELUS Digital is a BPO/service provider in your chain, assume data compromise of source code, customer records, and credentials; rotate affected credentials
6. **HIGH (7 days):** Hunt for ShinyHunters indicators - group is actively exploiting cascading SaaS credential theft (Salesforce, Okta, M365); audit OAuth tokens and GCP service accounts
7. **HIGH (7 days):** Brief security teams on LeakNet's ClickFix+Deno TTPs - hunt for Deno runtime processes, jli.dll side-loading in USOShared, and S3 bucket staging in network logs
8. **HIGH (7 days):** Audit Python dependencies for GlassWorm indicators - campaign has expanded from VS Code/npm to Django, ML, Streamlit, and PyPI packages via stolen GitHub tokens
9. **MEDIUM (14 days):** Verify Infutor/Verisk exposure - if your organization uses Infutor consumer identity data, assume potential compromise of 676M records including SSNs; monitor for downstream fraud
10. **MEDIUM (14 days):** Review Intuitive Surgical communication if you are a healthcare provider customer - phishing attack exposed provider PII (names, specialties, contact info)
11. **MEDIUM (30 days):** Assess CarGurus exposure for employees or fleet programs - 12.4M records with auto finance pre-qualification data may enable targeted financial fraud

---

## Sources

- [CISA Adds One KEV - Wing FTP Server (March 16)](https://www.cisa.gov/news-events/alerts/2026/03/16/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA Flags Wing FTP Vulnerability - The Hacker News](https://thehackernews.com/2026/03/cisa-flags-actively-exploited-wing-ftp.html)
- [Wing FTP Server Vulnerability Exploited - CybersecurityNews](https://cybersecuritynews.com/wing-ftp-server-vulnerability-exploited-2/)
- [CISA Flags Year-Old Wing FTP Vulnerability - SecurityWeek](https://www.securityweek.com/cisa-flags-year-old-wing-ftp-vulnerability-as-exploited/)
- [Wazuh RCE CVE-2026-25769 - TheHackerWire](https://www.thehackerwire.com/wazuh-rce-via-deserialization-of-untrusted-data-cve-2026-25769/)
- [CVE-2026-25769 - Hakai Security Research](https://hakaisecurity.io/cve-2026-25769-rce-via-insecure-deserialization-in-wazuh-cluster-remote-command-execution-through-cluster-protocol/research-blog/)
- [Wazuh Security Advisory GHSA-hcrc-79hj-m3qh - GitHub](https://github.com/wazuh/wazuh/security/advisories/GHSA-hcrc-79hj-m3qh)
- [Critical HPE AOS-CX Vulnerability - SecurityWeek](https://www.securityweek.com/critical-hpe-aos-cx-vulnerability-allows-admin-password-resets/)
- [HPE AOS-CX Flaw Allowing Admin Password Resets - BleepingComputer](https://www.bleepingcomputer.com/news/security/hpe-warns-of-critical-aos-cx-flaw-allowing-admin-password-resets/)
- [Critical Vulnerabilities in Aruba AOS-CX - CSA Singapore](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-023/)
- [D-Link DIR-816 CVE-2026-4182 - TheHackerWire](https://www.thehackerwire.com/d-link-dir-816-critical-stack-buffer-overflow-cve-2026-4182/)
- [LeakNet Ransomware ClickFix + Deno - The Hacker News](https://thehackernews.com/2026/03/leaknet-ransomware-uses-clickfix-via.html)
- [LeakNet ClickFix Threat Spotlight - ReliaQuest](https://reliaquest.com/blog/threat-spotlight-casting-a-wider-net-clickfix-deno-and-leaknets-scaling-threat)
- [LeakNet ClickFix + Deno - BleepingComputer](https://www.bleepingcomputer.com/news/security/leaknet-ransomware-uses-clickfix-and-deno-runtime-for-stealthy-attacks/)
- [TELUS Digital Confirms Breach - BleepingComputer](https://www.bleepingcomputer.com/news/security/telus-digital-confirms-breach-after-hacker-claims-1-petabyte-data-theft/)
- [TELUS Digital ShinyHunters Breach - The Register](https://www.theregister.com/2026/03/15/telus_breach_starbucks_attack/)
- [TELUS Digital Breach - Hackread](https://hackread.com/shinyhunters-1-petabyte-data-breach-telus-digital/)
- [Intuitive Surgical Cyberattack - The Register](https://www.theregister.com/2026/03/16/robotics_surgical_biz_intuitive_discloses/)
- [Intuitive Surgical Cyberattack - Cybersecurity Dive](https://www.cybersecuritydive.com/news/intuitive-surgical-cyberattack-phishing/814746/)
- [Intuitive Surgical Statement](https://www.intuitive.com/en-us/about-us/newsroom/Intuitive-statement-on-cybersecurity-incident)
- [Intuitive Surgical - Second Medtech Breach - MDDIOnline](https://www.mddionline.com/robotics/intuitive-surgical-2nd-major-medtech-company-hit-with-cybersecurity-breach-in-1-week)
- [DOGE SSA Data Breach - Washington Post](https://www.washingtonpost.com/politics/2026/03/10/social-security-data-breach-doge-2/)
- [DOGE SSA Investigation - NPR](https://www.npr.org/2026/03/11/nx-s1-5745153/doge-social-security-data-whistleblower-investigation)
- [DOGE SSA Thumb Drive - TechCrunch](https://techcrunch.com/2026/03/10/doge-employee-stole-social-security-data-and-put-it-on-a-thumb-drive-report-says/)
- [DOGE SSA DOJ Confirmation - PBS](https://www.pbs.org/newshour/show/whistleblower-responds-after-doj-confirms-doge-mishandled-social-security-data)
- [DOGE Probe Deepens - Washington Today](https://nationaltoday.com/us/dc/washington/news/2026/03/15/probe-into-trumps-doge-program-deepens-after-alleged-leak-of-500m-americans-social-security-data/)
- [Infutor 676M Record Breach - ClassAction.org](https://www.classaction.org/data-breach-lawsuits/infutor-march-2026)
- [Infutor Breach - DarknetSearch](https://darknetsearch.com/knowledge/news/en/infutor-data-breach-revealed-676m-records-allegedly-leaked-online/)
- [CarGurus 12.4M Breach - BleepingComputer](https://www.bleepingcomputer.com/news/security/cargurus-data-breach-exposes-information-of-124-million-accounts/)
- [CarGurus Breach - SecurityWeek](https://www.securityweek.com/over-12-million-users-impacted-by-cargurus-data-breach/)
- [CarGurus Breach ShinyHunters - Fox News](https://www.foxnews.com/tech/cargurus-breach-linked-shinyhunters-exposes-12-4m-records)
- [Top Data Breaches March 2026 - SharkStriker](https://sharkstriker.com/blog/march-data-breaches-today-2026/)
- [CVE Watchtower Report March 2026 - SecurityOnline](https://securityonline.info/cve-watchtower-report-chrome-zero-days-cvss-10-vulnerabilities-march-2026/)

---

*Report generated by CTI Sensei | TLP:CLEAR*
