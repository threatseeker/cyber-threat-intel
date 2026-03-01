# Cyber Threat Intelligence Report
**Date:** March 1, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0301

---

## Executive Summary

- **Critical n8n RCE (CVE-2026-21858 "Ni8mare")**: CVSS 10.0 unauthenticated RCE affecting ~100,000 self-hosted instances globally - patch to v1.121.0 immediately
- **Cisco SD-WAN Zero-Day (CVE-2026-20127)**: CVSS 10.0 auth bypass exploited in the wild since 2023, added to CISA KEV Feb 25 - patch now
- **Apple iOS Zero-Day (CVE-2026-20700)**: Actively exploited; CISA deadline for federal agencies March 5, 2026
- **Microsoft Feb 2026 Patch Tuesday**: 6 actively exploited zero-days patched across Windows Shell, MSHTML, Word, RDS - CISA deadline March 3, 2026
- **Conduent Breach Expanded**: Now confirmed 25M+ victims with SSNs, medical records, insurance data - class action ongoing
- **BlackCat/Alphv Affiliates Plead Guilty**: Two US-based cybersecurity professionals admitted roles in ransomware attacks, sentencing March 12, 2026
- **CVE volume on track for 50,000+ in 2026**: Record-breaking vulnerability publication rate signals worsening attack surface

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2026-20127 | Cisco Catalyst SD-WAN | 10.0 | Auth Bypass | CISA KEV - Exploited since 2023 |
| CVE-2026-21858 | n8n workflow platform | 10.0 | Unauth RCE | Actively exploited, PoC public |
| CVE-2026-20700 | Apple iOS | Critical | RCE | CISA KEV - Deadline March 5 |
| CVE-2026-2441 | Google Chrome/Chromium | High | Use-After-Free RCE | CISA KEV - Deadline March 10 |
| CVE-2026-21510 | Windows Shell | High | Security Feature Bypass | CISA KEV - Deadline March 3 |
| CVE-2026-21513 | Windows MSHTML | High | Security Bypass | CISA KEV - Deadline March 3 |
| CVE-2026-21514 | Microsoft Word | High | Security Feature Bypass | CISA KEV - Deadline March 3 |
| CVE-2026-21533 | Windows RDS | High | Local Privilege Escalation to SYSTEM | CISA KEV - Deadline March 3 |
| CVE-2022-20775 | Cisco Catalyst SD-WAN | Medium | Path Traversal | CISA KEV added Feb 25 |
| CVE-2026-1731 | BeyondTrust Remote Support | Critical | OS Command Injection | CISA KEV added Feb 13 |

### CISA KEV - Recent Additions (Feb 25, 2026)
- **CVE-2022-20775** - Cisco Catalyst SD-WAN Path Traversal
- **CVE-2026-20127** - Cisco Catalyst SD-WAN Authentication Bypass (CVSS 10.0)

### CVE-2026-21858 "Ni8mare" - n8n Unauthenticated RCE
**CVSS: 10.0 | Impact: ~100,000 servers globally**

Content-Type confusion flaw in n8n webhook request handling (`prepareFormReturnItem` function). Attackers can forge file uploads, read arbitrary local files, steal credentials and encryption keys, forge admin session cookies, and achieve full server RCE - all without authentication. Primarily affects self-hosted instances.

**Remediation:** Upgrade to n8n v1.121.0 or later immediately.

### CVE-2026-20127 - Cisco SD-WAN Authentication Bypass
**CVSS: 10.0 | Exploited since 2023**

Unauthenticated remote attacker can bypass authentication and obtain administrative privileges via a crafted request. Evidence of exploitation dating back to 2023 suggests persistent threat actor presence in affected networks.

**Remediation:** Apply Cisco patches; audit for indicators of long-term compromise.

---

## Exploits & Zero-Days

### CVE-2026-0625 - D-Link DSL Gateway Zero-Day
Attackers are actively exploiting a zero-day in multiple discontinued D-Link DSL gateway devices to execute arbitrary shell commands. **No patch available** - devices are end-of-life.
- **Action:** Replace affected hardware immediately. No remediation path exists.

### CVE-2026-2441 - Google Chrome Zero-Day
First zero-day of 2026 for Chrome. High-severity use-after-free vulnerability enabling arbitrary code execution via malicious web content. Patched; CISA deadline **March 10, 2026**.

### CVE-2026-20700 - Apple iOS Zero-Day
Apple's first zero-day of 2026. Successful exploitation leads to arbitrary code execution. Patched via Apple security advisory. CISA deadline **March 5, 2026**.

### Microsoft February Patch Tuesday Zero-Days (6 actively exploited)
Released February 10, 2026. CISA deadline for federal remediation: **March 3, 2026**.

| CVE | Component | Type |
|-----|-----------|------|
| CVE-2026-21510 | Windows Shell | Security Feature Bypass (single-click exploit) |
| CVE-2026-21513 | Windows MSHTML | Security Feature Bypass |
| CVE-2026-21514 | Microsoft Word | Security Feature Bypass |
| CVE-2026-21533 | Windows RDS | Local Privilege Escalation to SYSTEM |

---

## Malware & Ransomware

### Legal Action: BlackCat/Alphv Affiliates Plead Guilty
Two US-based cybersecurity professionals - Ryan Goldberg and Kevin Martin - pleaded guilty to conspiracy to commit extortion for their roles as BlackCat/Alphv ransomware affiliates. Sentencing is scheduled **March 12, 2026**; maximum penalty 20 years.

### 2026 Ransomware Trends
- **Exfiltration-only attacks surging**: Many ransomware groups have abandoned encryption in favor of silent data theft followed by extortion - making attacks harder to detect
- **Zero-day adoption by ransomware operators**: VulnCheck reports ransomware groups increasingly leveraging zero-days, raising OT/ICS sector risk
- **Non-Russian actors now dominant**: 2026 marks the first year new ransomware actors outside Russia exceed those emerging within it
- **Revenue declining despite volume growth**: Groups earned less in 2025 despite a 47% attack increase, driving adoption of DDoS-as-a-Service, insider recruitment, and gig worker exploitation

---

## Threat Actors

### UNC3886 (China-Nexus) - Singapore Espionage Campaign
Singapore's Cyber Security Agency disclosed on February 9, 2026 that UNC3886, a suspected Chinese espionage group first flagged in July 2025, leveraged a zero-day exploit to bypass perimeter firewalls and deployed rootkits for persistent, undetected access. Singapore executed its largest-ever offensive cyber operation in response.

**TTPs:**
- Zero-day perimeter firewall bypass
- Rootkit deployment for persistence
- Extended dwell time (months to years)

### Phantom Taurus (New China-Nexus APT)
A previously undocumented Chinese nation-state actor targeting government agencies, embassies, military operations, and entities across Africa, the Middle East, and Asia.

**Characteristics:**
- Surgical precision targeting
- Custom-built toolkit (not relying on commodity malware)
- Cyber-espionage focus

### Broader Nation-State Threat Landscape (2026)
- Nation-state proxies increasingly mixing with financially motivated APTs, blurring espionage/sabotage/profit lines
- Critical infrastructure embedding attacks expected - adversaries pre-positioning for months or years
- Iran expanding coordinated cyber operations beyond hacktivism into more structured APT campaigns

---

## Data Breaches

### Conduent Business Services - 25M+ Victims (EXPANDED)
**Breach window:** October 2024 - January 2025 | **Disclosed/Expanded:** February 24, 2026

Now ranked the **8th largest healthcare data breach in US history**. Exposed data includes:
- Social Security numbers
- Medical records
- Health insurance details

**Affected organizations:** Blue Cross Blue Shield Texas, Blue Cross Blue Shield Montana, Premera Blue Cross, Humana, and multiple state Medicaid programs.

**Action deadline:** Free credit monitoring enrollment by **March 31, 2026**. Class action litigation ongoing (10+ lawsuits filed, 25M+ victims).

### Panera Bread - ~5.1M Accounts
ShinyHunters claimed theft in late January 2026. Analysis indicates approximately 5.1 million unique accounts exposed. Panera has confirmed the cybersecurity incident.

### PayPal Working Capital Breach
Breach window July 1 - December 12, 2025. Threat actor accessed PayPal systems tied to Working Capital loan applications. PayPal has confirmed the incident.

### HIPAA Reporting Deadline (Action Required)
Healthcare providers: Small healthcare data breaches (affecting <500 individuals) discovered in calendar year 2025 must be reported to HHS Office for Civil Rights by **March 1, 2026** (today).

---

## Vendor Advisories

### Microsoft - February 2026 Patch Tuesday (Released Feb 10, 2026)
- **58 total vulnerabilities patched**, including 6 actively exploited zero-days and 5 Critical-rated flaws
- Affected components: Windows Shell, MSHTML, Microsoft Word, Windows RDS, Exchange Server, NTLM, Remote Access Connection Manager, Graphics Component
- **Federal deadline: March 3, 2026** for KEV-listed vulnerabilities

### Apple (February 2026)
- Patched CVE-2026-20700 (iOS zero-day RCE)
- **Federal deadline: March 5, 2026**

### Google Chrome
- Patched CVE-2026-2441 (Chrome zero-day use-after-free RCE)
- **Federal deadline: March 10, 2026**

### Cisco
- Patches available for CVE-2026-20127 (SD-WAN Auth Bypass, CVSS 10.0) and CVE-2022-20775 (SD-WAN Path Traversal)
- Both added to CISA KEV February 25, 2026

### BeyondTrust
- Patched CVE-2026-1731 (Remote Support OS Command Injection) - CISA KEV added February 13, 2026

---

## Recommended Actions

### Immediate (24-48 hours)

1. **Patch Cisco SD-WAN** (CVE-2026-20127, CVSS 10.0) - audit for indicators of long-term compromise dating to 2023
2. **Upgrade n8n to v1.121.0+** (CVE-2026-21858, CVSS 10.0) - if self-hosting, treat as actively compromised until patched
3. **Apply Apple iOS patches** for CVE-2026-20700 - federal deadline March 5
4. **Apply Google Chrome updates** for CVE-2026-2441 - federal deadline March 10
5. **Replace end-of-life D-Link DSL gateways** - no patch available for CVE-2026-0625

### Short-Term (This week)

6. **Verify Microsoft February Patch Tuesday** rollout is complete - federal deadline was March 3
7. **Apply BeyondTrust patches** for CVE-2026-1731 if running Remote Support or Privileged Remote Access
8. **Audit for UNC3886 / Phantom Taurus TTPs** if operating in government, defense, or critical infrastructure sectors
9. **Check Conduent breach exposure** - verify if any healthcare vendor relationships exist; enroll affected individuals in credit monitoring before March 31
10. **HIPAA compliance check** - ensure all sub-500 breaches from 2025 were reported to HHS OCR by March 1

### Strategic

11. **Assume breach posture for long-dwell threats** - nation-state actors embedding for months/years; baseline network activity and hunt for anomalies
12. **Prepare for exfiltration-only ransomware** - DLP and UEBA controls are now as critical as backup/recovery
13. **Monitor CVE velocity** - with 50,000+ CVEs projected for 2026, prioritize CISA KEV and CVSS 9+ as triage filters

---

## Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds Two Known Exploited Vulnerabilities (Feb 25, 2026)](https://www.cisa.gov/news-events/alerts/2026/02/25/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Adds One Known Exploited Vulnerability (Feb 13, 2026)](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA Adds Six Known Exploited Vulnerabilities (Feb 10, 2026)](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA Flags Four Security Flaws - The Hacker News](https://thehackernews.com/2026/02/cisa-flags-four-security-flaws-under.html)
- [Cisco SD-WAN Zero-Day CVE-2026-20127 - The Hacker News](https://thehackernews.com/2026/02/cisco-sd-wan-zero-day-cve-2026-20127.html)
- [CVE-2026-20127 - SOC Prime](https://socprime.com/blog/cve-2026-20127-vulnerability/)
- [CVE-2026-2441 Chrome Zero-Day - Orca Security](https://orca.security/resources/blog/cve-2026-2441-chrome-chromium-zero-day-vulnerability/)
- [Google Patches First Zero-Day CVE-2026-2441 - Qualys](https://threatprotect.qualys.com/2026/02/16/google-patches-its-first-zero-day-vulnerability-of-the-year-cve-2026-2441/)
- [Apple iOS Zero-Day CVE-2026-20700 - Qualys](https://threatprotect.qualys.com/2026/02/12/apple-ios-zero-day-vulnerability-exploited-in-attacks-cve-2026-20700/)
- [Microsoft Patches 59 Vulnerabilities Including Six Zero-Days - The Hacker News](https://thehackernews.com/2026/02/microsoft-patches-59-vulnerabilities.html)
- [Microsoft February 2026 Patch Tuesday - BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [Patch Tuesday February 2026 - Krebs on Security](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [Ni8mare - CVE-2026-21858 n8n RCE - Cyera Research Labs](https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858)
- [CVE-2026-21858 n8n RCE - Aikido Security](https://www.aikido.dev/blog/n8n-rce-vulnerability-cve-2026-21858)
- [Ni8mare Test - Horizon3.ai](https://horizon3.ai/attack-research/attack-blogs/the-ni8mare-test-n8n-rce-under-the-microscope-cve-2026-21858/)
- [CVE-2026-21858 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21858)
- [n8n Critical Vulnerability - SecurityWeek](https://www.securityweek.com/critical-vulnerability-exposes-n8n-instances-to-takeover-attacks/)
- [D-Link Router Zero-Day - Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)
- [Conduent Data Breach 25M+ Victims - TechCrunch](https://techcrunch.com/2026/02/24/conduent-data-breach-grows-affecting-at-least-25m-people/)
- [Conduent Data Breach Class Action Update](https://allaboutlawyer.com/conduent-data-breach-class-action-2026-10-feb-update-25m-victims-10-lawsuits-filed-free-credit-monitoring-deadline-march-31/)
- [Two US Cybersecurity Pros Plead Guilty - SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [BlackCat Affiliates Plead Guilty - CSO Online](https://www.csoonline.com/article/4112400/two-cybersecurity-experts-plead-guilty-to-running-ransomware-operation.html)
- [Singapore Largest Cyber Operation vs APT - Computer Weekly](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [New China APT Phantom Taurus - Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)
- [Ransomware Tactics 2026 - Recorded Future](https://www.recordedfuture.com/blog/ransomware-tactics-2026)
- [State of Ransomware 2026 - BlackFog](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [Ransomware Without Encryption - Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Published CVEs Could Hit 50,000+ in 2026 - SC Media](https://www.scworld.com/news/published-cves-could-hit-record-breaking-50000-plus-in-2026)
- [March 1 2026 HIPAA Reporting Deadline - HIPAA Journal](https://www.hipaajournal.com/march-1-2026-small-healthcare-data-breach-hipaa-reporting-deadline/)
- [Cyber Threats to Watch 2026 - World Economic Forum](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
