# Cyber Threat Intelligence Report
**Date:** 2026-02-26
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0226

---

## Executive Summary

- **CRITICAL - PATCH NOW:** Cisco Catalyst SD-WAN CVE-2026-20127 (auth bypass) is being actively exploited; CISA issued an emergency directive requiring federal agencies to patch by Feb 27, 2026
- **Active Campaign:** BeyondTrust CVE-2026-1731 RCE actively exploited across 10,600+ exposed instances with VShell backdoor and SparkRAT being deployed by suspected Chinese APT
- **Supply Chain Compromise Disclosed:** Notepad++ update mechanism hijacked by suspected Chinese APT (Violet Typhoon/Lotus Blossom) for ~6 months (June-Dec 2025), targeting financial and telecom firms
- **February Patch Tuesday:** Microsoft patched 59 vulnerabilities including 6 actively exploited zero-days; immediate patching required
- **Nation-State Activity:** Singapore executed Operation CYBER GUARDIAN against UNC3886 (China-nexus) APT that compromised all 4 major telecom operators via zero-day firewall exploit
- **Ransomware:** Japanese chip testing giant Advantest hit by ransomware on Feb 15; IBM X-Force 2026 report confirms 49% surge in active ransomware groups YoY
- **Data Breaches:** Odido (Dutch telecom) breached exposing 6M+ accounts; IRS improperly shared 1.28M individuals' tax data with DHS/ICE

---

## Critical Vulnerabilities

### CISA KEV Additions - February 2026

| CVE | Product | Type | Due Date |
|-----|---------|------|----------|
| CVE-2026-20127 | Cisco Catalyst SD-WAN Controller/Manager | Auth Bypass (Critical) | Feb 27, 2026 |
| CVE-2022-20775 | Cisco Catalyst SD-WAN | Path Traversal / Privilege Escalation | Feb 27, 2026 |
| CVE-2026-25108 | Soliton FileZen | OS Command Injection | Feb 24, 2026 |
| CVE-2025-49113 | RoundCube Webmail | Deserialization of Untrusted Data | Feb 20, 2026 |
| CVE-2025-68461 | RoundCube Webmail | Cross-Site Scripting | Feb 20, 2026 |
| CVE-2026-21510 | Microsoft Windows Shell | Protection Mechanism Failure | Feb 10, 2026 |
| CVE-2026-21513 | Microsoft MSHTML | Security Feature Bypass | Feb 10, 2026 |
| CVE-2026-21514 | Microsoft Office Word | Security Feature Bypass | Feb 10, 2026 |
| CVE-2026-21519 | Microsoft Windows DWM | Type Confusion / EoP | Feb 10, 2026 |
| CVE-2026-21525 | Microsoft Windows RasMan | NULL Pointer Dereference / DoS | Feb 10, 2026 |
| CVE-2026-21533 | Microsoft Windows RDS | Elevation of Privilege | Feb 10, 2026 |
| CVE-2025-40551 | SolarWinds Web Help Desk | Deserialization of Untrusted Data | Feb 3, 2026 |
| CVE-2025-64328 | Sangoma FreePBX | OS Command Injection | Feb 3, 2026 |
| CVE-2021-39935 | GitLab CE/EE | Server-Side Request Forgery | Feb 3, 2026 |
| CVE-2019-19006 | Sangoma FreePBX | Improper Authentication | Feb 3, 2026 |

### High-Priority CVEs (Not Yet in KEV)

**CVE-2026-1731 - BeyondTrust Remote Support (Critical RCE)**
- Pre-authentication RCE in the `thin-scc-wrapper` WebSocket handler
- Attackers embed command substitution (e.g., `a[$(cmd)]0`) in `remoteVersion` parameter
- 10,600+ internet-exposed instances remain unpatched per Cortex Xpanse telemetry
- Active exploitation deploying VShell + SparkRAT (see Threat Actors section)
- Affected sectors: financial services, legal, high-tech, healthcare, education
- Countries impacted: US, France, Germany, Australia, Canada

**CVE-2026-25049 - n8n Workflow Automation (CVSS 9.4)**
- Bypasses sanitization from a previously patched vulnerability
- Enables system command execution via malicious workflow definitions
- Patch available; update immediately if running n8n

**CVE-2026-26119 - Microsoft Windows Admin Center**
- Disclosed Feb 19; critical severity
- Organizations using Windows Admin Center for remote management should prioritize

---

## Exploits & Zero-Days

### Microsoft February 2026 Patch Tuesday Zero-Days (6 Actively Exploited)

All six were added to CISA KEV on Feb 10; three were publicly disclosed prior to patching:

| CVE | Component | Type | CVSS | Notes |
|-----|-----------|------|------|-------|
| CVE-2026-21510 | Windows Shell / SmartScreen | Security Feature Bypass | 8.8 | Publicly disclosed; user opens malicious link/shortcut |
| CVE-2026-21513 | MSHTML Framework | Security Feature Bypass | - | Publicly disclosed; browser-based attack surface |
| CVE-2026-21514 | Microsoft Word | Security Feature Bypass | 5.5 | Publicly disclosed; malicious .docx required |
| CVE-2026-21519 | Windows Desktop Window Manager | EoP - Type Confusion | - | Local; attains SYSTEM privileges |
| CVE-2026-21525 | Windows RasMan | DoS - NULL Ptr Dereference | - | Unauthenticated local attacker, low complexity |
| CVE-2026-21533 | Windows Remote Desktop Services | EoP - Privilege Escalation | - | Low-privilege authenticated user -> SYSTEM |

### Chrome Zero-Day

**CVE-2026-2441** - First Chrome zero-day of 2026
- Allows code execution via malicious webpages
- Google issued an out-of-band emergency update (did not wait for next major release)
- **Update Chrome immediately**

### Notepad++ Supply Chain (Disclosed February 2026)

- Update mechanism for Notepad++ was hijacked at the **hosting provider level** from June-December 2025
- Malicious payloads delivered to select high-value targets (not all users)
- Custom backdoor "Chrysalis" deployed (Lotus Blossom attribution by Rapid7)
- Violet Typhoon / APT31 / Zirconium attribution also reported (Dark Reading / Kevin Beaumont)
- Notepad++ has since migrated hosting and hardened update integrity checks

---

## Malware & Ransomware

### Active Incidents

**Advantest Corporation (Chip Testing - Critical Infrastructure)**
- Japanese semiconductor test equipment giant detected ransomware intrusion on Feb 15, 2026
- Unauthorized third-party gained network access and deployed ransomware
- Incident response activated; forensic investigation ongoing
- Supplier to major semiconductor firms globally

### Threat Landscape Trends

**IBM 2026 X-Force Threat Intelligence Index (Released Feb 25, 2026)**
- Active ransomware and extortion groups surged **49% YoY**
- Publicly disclosed victim counts rose ~12%
- Vulnerability exploitation is now the **#1 initial access vector** (40% of incidents)
- Attacks on public-facing applications increased **44%**, accelerated by AI-enabled vuln discovery
- Over **300,000 ChatGPT credentials** exposed via infostealer malware in 2025
- Supply chain/third-party compromises nearly **quadrupled** since 2020

**Pro-Russian Hacktivist Activity**
- Noticeable increase in DDoS and defacement attacks since the 2026 Winter Olympics opened in Milan/Cortina d'Ampezzo (Feb 6)
- CYFIRMA weekly intelligence (Feb 20) flagged ongoing escalation

---

## Threat Actors

### UNC3886 (China-Nexus) - Operation CYBER GUARDIAN

- **Target:** Singapore telecommunications sector - all 4 major operators (M1, SIMBA, Singtel, StarHub)
- **Method:** Zero-day exploit to bypass perimeter firewalls; rootkits for persistent undetected access
- **Response:** Singapore CSA and IMDA launched largest-ever multi-agency cyber operation (disclosed Feb 9, 2026)
- **Impact:** No confirmed exfiltration of customer data or service disruption
- **Context:** UNC3886 previously linked to Juniper router compromise campaigns; focus on critical national infrastructure

### Violet Typhoon / Lotus Blossom (China-Nexus) - Notepad++ Supply Chain

- **Campaign:** 6-month compromise of Notepad++ update infrastructure (June-Dec 2025)
- **Targets:** Financial services and telecommunications providers of strategic interest to China
- **Malware:** "Chrysalis" custom backdoor (Rapid7 attribution to Lotus Blossom); SparkRAT also observed
- **Attribution conflict:** Rapid7 says Lotus Blossom; Kevin Beaumont/Dark Reading say Violet Typhoon (APT31/Zirconium)
- Notepad++ has ~17 million downloads - attack surface for supply chain is significant

### Unnamed Chinese APT - BeyondTrust Exploitation

- **Tool:** VShell (Linux backdoor, fileless memory execution, blends as system service) + SparkRAT (Go-based RAT, first seen 2023 with DragonSpark group)
- **TTPs:** Network recon -> account creation -> web shell -> C2 -> backdoor -> lateral movement -> data theft
- **Scale:** Victims span 6 sectors across 5 countries; 10,600+ exposed instances still vulnerable

---

## Data Breaches

| Organization | Type | Records Affected | Date Discovered | Details |
|---|---|---|---|---|
| Odido (Netherlands) | Telecom - Cyberattack | 6M+ accounts | Feb 7, 2026 | Names, phone numbers, emails, bank account numbers, passport numbers stolen |
| IRS / DHS | Government - Policy Breach | 1.28M individuals | Disclosed Feb 12, 2026 | IRS improperly disclosed tax records to DHS/ICE; legal challenges filed |
| Conduent | Govtech - Ongoing | Millions (ballooning) | Disclosed Feb 5, 2026 | Originally reported as smaller; scope expanded significantly |
| Cottage Hospital | Healthcare | 1,600+ | Feb 6, 2026 (notifications) | SSNs, driver's license numbers, bank account info; breach occurred Oct 2025 |
| EyeCare Partners | Healthcare | Unknown | Feb 2026 (state AG notifications) | Unauthorized email account access; incident first identified Jan 28, 2025 |

---

## Vendor Advisories

### Microsoft - February 2026 Patch Tuesday (Feb 10, 2026)
- **59 CVEs patched**, 6 actively exploited zero-days, 5 Critical
- Notable: Multiple Outlook vulnerabilities exploit via Preview Pane (CVE-2026-21260)
- CVE-2026-21231: Windows Win32k EoP allowing security boundary crossing
- **Action:** Apply February cumulative updates immediately

### Cisco - Emergency Advisory
- **CVE-2026-20127:** Critical authentication bypass in Catalyst SD-WAN Controller/Manager
- CISA Emergency Directive: Federal agencies must patch by **5:00 PM ET February 27, 2026**
- Unauthenticated remote attacker can gain full administrative access
- **Action:** Apply Cisco patch immediately; no workaround available

### Google Chrome
- CVE-2026-2441 zero-day patched via emergency out-of-band update
- **Action:** Verify Chrome is updated to latest stable channel version

### RoundCube Webmail
- CVE-2025-49113 and CVE-2025-68461 both in CISA KEV; confirmed active exploitation
- **Action:** Patch RoundCube immediately; self-hosted instances are at highest risk

### n8n Workflow Automation
- CVE-2026-25049 (CVSS 9.4) enables system command execution
- **Action:** Update n8n to latest version; audit workflow permissions

---

## Recommended Actions

### Immediate (24-48 hours)

1. **Cisco Catalyst SD-WAN** - Apply patch for CVE-2026-20127 before Feb 27, 2026 EOD (CISA emergency directive)
2. **BeyondTrust Remote Support** - Patch CVE-2026-1731 immediately; audit for indicators of VShell/SparkRAT compromise
3. **Microsoft Windows** - Deploy February 2026 Patch Tuesday updates; prioritize the 6 zero-days
4. **Google Chrome** - Ensure all enterprise endpoints are on latest stable channel (CVE-2026-2441)
5. **RoundCube Webmail** - Patch CVE-2025-49113 and CVE-2025-68461 immediately

### Short-Term (This Week)

6. **Notepad++ Audit** - Scan enterprise endpoints for "Chrysalis" backdoor IoCs; check software update logs from June-December 2025 for anomalies
7. **n8n Instances** - Patch CVE-2026-25049; restrict workflow execution permissions
8. **SolarWinds Web Help Desk** - Patch CVE-2025-40551 (CISA KEV)
9. **GitLab** - Remediate CVE-2021-39935 if still present on self-hosted instances
10. **Telecom / CNI Sector** - Review UNC3886 TTPs (zero-day firewall exploits, rootkit persistence); conduct threat hunt for signs of long-dwell intrusion

### Strategic (This Month)

11. Review and harden software supply chain processes; validate update mechanisms use code signing and integrity verification
12. Implement identity-first security controls - vulnerability exploitation is now the #1 initial access vector per IBM X-Force 2026
13. Audit internet-exposed BeyondTrust, RDP, and remote access infrastructure for exposure
14. Evaluate infostealer exposure - assume AI platform credentials (ChatGPT, Copilot) are at risk and enforce SSO/MFA

---

## Sources

- [CISA KEV - Feb 20 Addition (RoundCube)](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 10 Addition (Microsoft)](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA KEV - Feb 24 Addition (FileZen)](https://www.cisa.gov/news-events/alerts/2026/02/24/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV - Feb 3 Addition (FreePBX, SolarWinds, GitLab)](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Cisco CVE-2026-20127 - Rapid7 ETR](https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-vulnerability-exploited-in-the-wild-cve-2026-20127/)
- [Cisco SD-WAN CVE-2026-20127 - TheHackerWire](https://www.thehackerwire.com/cisco-sd-wan-critical-peering-authentication-bypass-cve-2026-20127/)
- [CISA KEV Update: Cisco SD-WAN - Windows Forum](https://windowsforum.com/threads/cisa-kev-update-patch-urgency-for-cisco-catalyst-sd-wan-flaws.403256/)
- [BeyondTrust CVE-2026-1731 - Unit 42 / Palo Alto](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [BeyondTrust CVE-2026-1731 - CyberSecureFox](https://cybersecurefox.com/en/beyondtrust-cve-2026-1731-notepad-plus-plus-supply-chain-cisa-kev/)
- [BeyondTrust Active Exploitation - GBHackers](https://gbhackers.com/beyondtrust-vulnerability/)
- [BeyondTrust CVE-2026-1731 - SecurityAffairs](https://securityaffairs.com/188370/hacking/cve-2026-1731-fuels-ongoing-attacks-on-beyondtrust-remote-access-products.html)
- [n8n CVE-2026-25049 - The Hacker News](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [Windows Admin Center CVE-2026-26119 - Help Net Security](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)
- [Microsoft February 2026 Patch Tuesday - BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [February 2026 Patch Tuesday - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)
- [February 2026 Patch Tuesday - SecurityWeek](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)
- [February 2026 Patch Tuesday - Krebs on Security](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [February 2026 Patch Tuesday - Zero Day Initiative](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
- [February 2026 Patch Tuesday - CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-february-2026/)
- [Chrome Zero-Day CVE-2026-2441 - Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)
- [Notepad++ Supply Chain - Dark Reading](https://www.darkreading.com/application-security/chinese-hackers-hijack-notepad-updates-6-months)
- [Notepad++ Supply Chain - The Hacker News](https://thehackernews.com/2026/02/notepad-official-update-mechanism.html)
- [Notepad++ Supply Chain - SecurityWeek](https://www.securityweek.com/notepad-supply-chain-hack-conducted-by-china-via-hosting-provider/)
- [Notepad++ Supply Chain - The Record](https://therecord.media/popular-text-editor-hijacked-by-suspected-state-sponsored-hackers)
- [Notepad++ Infrastructure - SOCRadar](https://socradar.io/blog/notepad-infrastructure-hijacked/)
- [UNC3886 / Singapore CYBER GUARDIAN - Computer Weekly](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [Singapore CSA Press Release - Operation CYBER GUARDIAN](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [Advantest Ransomware - SecurityWeek](https://www.securityweek.com/chip-testing-giant-advantest-hit-by-ransomware/)
- [Advantest Ransomware - CyberPress](https://cyberpress.org/ransomware-attack-disrupts/)
- [IBM 2026 X-Force Threat Intelligence Index](https://newsroom.ibm.com/2026-02-25-ibm-2026-x-force-threat-index-ai-driven-attacks-are-escalating-as-basic-security-gaps-leave-enterprises-exposed)
- [IBM X-Force 2026 Full Report](https://www.ibm.com/reports/threat-intelligence)
- [CYFIRMA Weekly Intel - Feb 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [Odido Data Breach - BreachSense](https://www.breachsense.com/breaches/)
- [Conduent Breach - TechCrunch](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [IRS Data Breach - evrimagaci/GPT](https://evrimagaci.org/gpt/irs-data-breach-sparks-outcry-over-immigration-deal-528626)
- [Cottage Hospital Breach - Valley News](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [Healthcare Breaches - HIPAA Journal](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [WEF Cyber Threats 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [Ransomware State 2026 - BlackFog](https://www.blackfog.com/the-state-of-ransomware-2026/)
