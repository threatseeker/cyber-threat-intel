# Cyber Threat Intelligence Report
**Date:** February 2, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0202

---

## Executive Summary

- **NEW**: n8n Critical RCE (CVE-2026-21858, CVSS 10.0) - Unauthenticated attackers can take full control of workflow automation instances
- **NEW**: SimonMed Imaging ransomware - Medusa group compromised 1.27M patient records; ransom likely paid
- **NEW**: Illinois DHS breach - 600K+ patients' data exposed through misconfigured maps (2021-2025)
- **NEW**: China-linked APT UAT-8837 exploiting Sitecore zero-day (CVE-2025-53690) targeting critical infrastructure
- **NEW**: VMware ESXi zero-days weaponized - Chinese actors had exploit toolkit since Feb 2024, a year before disclosure
- **NEW**: Sedgwick Government Solutions hit by ransomware - Claims administrator for DHS, CISA affected
- **DEADLINE PASSED**: Fortinet CVE-2026-24858 - CISA deadline was January 30, 2026
- **DEADLINE TOMORROW**: Microsoft DWM CVE-2026-20805 - CISA deadline **February 3, 2026**

---

## Critical Vulnerabilities

### NEW: n8n Critical RCE - CVSS 10.0

**CVE:** CVE-2026-21858
**Codename:** Ni8mare
**Severity:** Critical (CVSS 10.0)
**Discovered by:** Cyera Research Labs

**Details:**
The vulnerability occurs when a file-handling function runs without first verifying that the content-type is "multipart/form-data," allowing attackers to override req.body.files. This enables unauthenticated remote code execution.

**Impact:** Attackers can take full control of n8n workflow automation instances, potentially accessing credentials, API keys, and connected systems.

**Remediation:** Update n8n immediately. Review logs for exploitation attempts.

**Source:** [The Hacker News](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html)

---

### DEADLINE TOMORROW: Microsoft DWM CVE-2026-20805

**CISA Remediation Deadline:** February 3, 2026 (TOMORROW)
**Status:** Actively exploited zero-day

Organizations running Windows must patch CVE-2026-20805, an information disclosure vulnerability in Desktop Window Manager (CVSS 5.5), by end of day tomorrow.

**Source:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### VMware ESXi Zero-Days - Pre-Disclosure Exploitation

**CVEs:** CVE-2025-22224 (9.3), CVE-2025-22225 (8.2), CVE-2025-22226 (7.1)
**Status:** Actively exploited by China-linked threat actors

Huntress discovered in December 2025 that Chinese-speaking threat actors possessed a packaged exploit toolkit for VMware ESXi dating back to February 2024—over a year before Broadcom publicly disclosed these vulnerabilities in March 2025.

**Attack Chain:**
1. Initial access via compromised SonicWall VPN appliance
2. Lateral movement to VMware environment
3. ESXi virtual machine escape

**Toolkit Evidence:** Folder named "All version escape - delivery" with path date February 19, 2024, targeting ESXi 8.0 Update 3.

**Remediation:** Ensure all VMware ESXi instances are patched to latest versions. Review for indicators of compromise.

**Source:** [Huntress](https://www.huntress.com/blog/esxi-vm-escape-exploit), [The Hacker News](https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html)

---

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | **February 3, 2026** |
| CVE-2026-20045 | Cisco Unified Communications | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |

---

## Ransomware Activity

### NEW: SimonMed Imaging - 1.27 Million Patients

**Victim:** SimonMed Imaging (outpatient radiology, 170+ centers across 11 states)
**Threat Actor:** Medusa ransomware group
**Attack Window:** January 21 - February 5, 2025 (16 days)
**Disclosed:** April 2025
**Affected:** 1,275,669 individuals

**Ransom Demand:**
- $1 million initial demand
- $10,000/day extension fee
- February 21, 2025 deadline

**Data Exposed:**
- Names, addresses, DOB
- Medical record numbers, diagnoses, imaging
- SSNs, driver's licenses
- Financial account numbers
- Authentication credentials
- Biometric identifiers

**Status:** SimonMed no longer listed on Medusa leak site, suggesting ransom was paid. Company declined to comment.

**Source:** [SecurityWeek](https://www.securityweek.com/simonmed-imaging-data-breach-impacts-1-2-million/), [HIPAA Journal](https://www.hipaajournal.com/simonmed-imaging-confirms-january-2025-cyberattack/)

---

### NEW: Sedgwick Government Solutions Ransomware

**Victim:** Sedgwick Government Solutions (subsidiary of Sedgwick)
**Clients Affected:** US Government agencies including DHS, CISA, municipalities
**Status:** Investigation ongoing

Sedgwick Government Solutions provides claims and risk management services to federal agencies. The parent company confirmed a cyberattack after a ransomware group claimed responsibility.

**Significance:** Potential exposure of government employee claims data, disability records, and personal information.

**Source:** [SecurityWeek](https://www.securityweek.com/sedgwick-confirms-cyberattack-on-government-subsidiary/)

---

### Ransomware Trend: Pure Exfiltration Surging

Attackers increasingly skip encryption, opting for data theft and extortion alone:

- **Azure Copy abuse:** Attackers use Azure Copy to blend data theft with normal cloud operations, avoiding detection
- **Speed advantage:** No encryption overhead means faster attacks
- **Detection evasion:** Data movement to Azure endpoints doesn't trigger traditional ransomware alerts

**Source:** [Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)

---

### 2025 Ransomware Statistics

- **8,000+ organizations** claimed as victims (up from ~6,000 in 2024)
- **57 new ransomware groups** observed
- **27 new extortion groups** emerged
- **Most active groups:** Qiling, Akira, Cl0p, Play, Safepay

**Source:** [SecurityWeek](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)

---

## Data Breaches

### NEW: Illinois Department of Human Services - 600K+ Patients

**Victim:** Illinois DHS healthcare programs
**Exposure Period:** 2021-2025 (multiple years)
**Affected:** 600,000+ patients (32,000+ with publicly viewable data)
**Root Cause:** Misconfigured privacy settings on mapping applications

Maps created to assist the agency were inadvertently made public, exposing patient names and addresses.

**Source:** [Chicago Sun-Times](https://chicago.suntimes.com/illinois/2026/01/02/illinois-department-human-services-data-incident-hipa)

---

### NEW: University of Phoenix - 3.5 Million People

**Victim:** University of Phoenix
**Attack Date:** August 2025
**Discovered:** November 21, 2025
**Affected:** ~3.5 million individuals
**Root Cause:** Zero-day in Oracle E-Business Suite

**Attribution:** Security researchers believe tactics align with Clop ransomware gang.

**Source:** [Fox News](https://www.foxnews.com/tech/university-phoenix-data-breach-hits-3-5m-people)

---

### NEW: 1st MidAmerica Credit Union

**Victim:** 1st MidAmerica Credit Union (MACU)
**Attack Date:** August 14, 2025
**Root Cause:** Vendor compromise (Marquis Software Solutions)
**Status:** Class action investigation underway

**Source:** [GlobeNewswire](https://www.globenewswire.com/news-release/2026/02/02/3229938/0/en/DATA-BREACH-ALERT-Edelson-Lechtzin-LLP-is-Investigating-Claims-on-Behalf-of-1st-MidAmerica-Credit-Union-Customers-Whose-Data-May-Have-Been-Compromised.html)

---

### Instagram/BreachForums Incident

**Reported:** January 10, 2026
**Claims:** 17.5 million Instagram accounts posted on BreachForums
**Evidence:** Spike in password reset emails beginning January 9, 2026
**Status:** Meta has not confirmed an internal breach

**Source:** [Privacy Guides](https://www.privacyguides.org/news/2026/01/09/data-breach-roundup-jan-2-jan-8-2026/)

---

## APT & Threat Actor Activity

### NEW: China-Linked APT UAT-8837 - Critical Infrastructure Targeting

**Tracked by:** Cisco Talos
**Attribution:** China-nexus (medium confidence)
**Current Campaign:** Exploiting Sitecore zero-day (CVE-2025-53690, CVSS 9.0)

**Objectives:**
- Initial access to high-value organizations
- Credential harvesting
- Security configuration reconnaissance
- Active Directory enumeration

**Targets:** Critical infrastructure, government organizations

**International Response:** Australia, Germany, Netherlands, New Zealand, UK, and US cybersecurity agencies issued joint warnings about Chinese threats to OT environments.

**Source:** [The Hacker News](https://thehackernews.com/2026/01/china-linked-apt-exploits-sitecore-zero.html)

---

### Russian APT28 (Fancy Bear) - Credential Harvesting Campaign

**Tracked as:** BlueDelta
**Attribution:** Russia's GRU
**Campaign Period:** February - September 2025
**Discovered by:** Recorded Future

**Targets:**
- IT integrator in Uzbekistan
- European think tank
- Military organization in North Macedonia
- Turkish energy and nuclear research organization

**Technique:** Credential harvesting attacks across Balkans, Middle East, and Central Asia.

**Source:** [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-credentials-global-targets)

---

### Iranian APT Infy Returns

**Threat Actor:** Infy (aka Prince of Persia)
**Status:** Active, relevant, dangerous
**History:** One of the oldest APTs, dating back to December 2004

SafeBreach is warning of renewed activity from this long-dormant Iranian threat actor.

**Source:** [CISO Series](https://cisoseries.com/cybersecurity-news-presidents-cyber-bill-iranian-apt-resurfaces-kimwolf-ddos-attack/)

---

### ClickFix Attacks Adopted by Multiple APTs

Nation-state actors from **North Korea, Iran, and Russia** are now using ClickFix social engineering attacks to breach networks.

**Technique:** Victims are tricked into copying and pasting malicious commands, believing they're fixing a technical issue.

**Source:** [Cyble](https://cyble.com/knowledge-hub/top-10-threat-actor-trends-of-2025/)

---

## 2026 Threat Predictions

### AI-Driven Attack Acceleration

Agentic AI threatens to automate attack chains at speeds far exceeding human operators. Organizations inadequately prepared for AI-assisted attacks face overwhelming response challenges.

### Ransomware Evolution

- Fewer incidents but higher severity
- RaaS platforms operating modularly for efficiency
- Focus on precision targeting over volume
- Non-Russian ransomware actors expected to exceed Russian actors for first time

### Critical Infrastructure Focus

Europe faces heightened risk of:
- Cyber-physical attacks
- Information operations
- Combined nation-state campaigns

**Sources:** [The Hacker News](https://thehackernews.com/2026/01/cybersecurity-predictions-2026-hype-we.html), [Recorded Future](https://www.recordedfuture.com/blog/ransomware-tactics-2026)

---

## Recommended Actions

### Immediate Priority (Next 24 Hours)

1. **Microsoft DWM** - Patch CVE-2026-20805 before **February 3, 2026** CISA deadline
2. **n8n Users** - Update immediately; CVSS 10.0 vulnerability allows unauthenticated RCE
3. **VMware ESXi** - Verify patches applied for CVE-2025-22224/22225/22226

### High Priority (This Week)

4. **Sitecore** - Patch CVE-2025-53690 (9.0 CVSS) being exploited by Chinese APT
5. **D-Link legacy routers** - Replace EOL devices; no patches available for CVE-2026-0625
6. **Microsoft Office** - Patch CVE-2026-21509 before February 16 CISA deadline

### Threat Hunting

7. **VMware environments** - Hunt for ESXi escape indicators; review SonicWall VPN logs
8. **Cloud egress** - Monitor Azure Copy operations for anomalous data transfer
9. **Credential systems** - Review authentication logs for APT28-style harvesting

### Healthcare Organizations

10. **SimonMed lessons** - Review third-party vendor access; implement MFA everywhere
11. **Map/GIS applications** - Audit privacy settings on any patient-related mapping tools

---

## Sources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News - n8n Critical Vulnerability](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html)
- [The Hacker News - China APT Sitecore](https://thehackernews.com/2026/01/china-linked-apt-exploits-sitecore-zero.html)
- [Huntress - ESXi Exploitation](https://www.huntress.com/blog/esxi-vm-escape-exploit)
- [SecurityWeek - SimonMed Breach](https://www.securityweek.com/simonmed-imaging-data-breach-impacts-1-2-million/)
- [SecurityWeek - Sedgwick Attack](https://www.securityweek.com/sedgwick-confirms-cyberattack-on-government-subsidiary/)
- [Morphisec - Exfiltration Attacks](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Dark Reading - Fancy Bear Campaign](https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-credentials-global-targets)
- [Chicago Sun-Times - Illinois DHS](https://chicago.suntimes.com/illinois/2026/01/02/illinois-department-human-services-data-incident-hipa)
- [Fox News - University of Phoenix](https://www.foxnews.com/tech/university-phoenix-data-breach-hits-3-5m-people)
- [Recorded Future - 2026 Ransomware Tactics](https://www.recordedfuture.com/blog/ransomware-tactics-2026)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in January 29-30, 2026 reports:

- SolarWinds Web Help Desk CVE-2025-40551/52/53/54
- eScan antivirus supply chain compromise
- 700Credit breach (5.6M affected)
- Blue Shield of California record merge issue
- Google disruption of IPIDEA botnet
- GhostChat Android spyware
- Malicious VSCode extension "ClawdBot Agent"
- Fortinet CVE-2026-24858 (deadline passed Jan 30)
- Atlassian January 2026 Security Bulletin
- CISA 2015 extension expiration
- OT network cybersecurity gaps study

---

*Report generated: 2026-02-02*
*Next report: 2026-02-03*
*Classification: TLP:CLEAR*
