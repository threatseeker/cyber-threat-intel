# Cyber Threat Intelligence Report
**Date:** 2026-03-16
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0316

---

## Executive Summary

- **HIGH:** APT28 (Fancy Bear / GRU Unit 26165) formally attributed to CVE-2026-21513 MSHTML zero-day exploitation via malicious LNK files -- bypasses MotW and IE ESC, delivers multistage payloads; patched February 2026 but campaign IOCs still active
- **HIGH:** CVE-2026-23669 -- Windows Print Spooler use-after-free RCE (CVSS 8.8, PrintNightmare-style) patched March 10; no active exploitation yet but PoC-style mechanics are well-understood and exploitation window is narrowing
- **HIGH:** CVE-2026-26118 -- Azure MCP Server Tools EoP via SSRF (CVSS 8.8); first significant vulnerability in the emerging MCP (Model Context Protocol) ecosystem; authorized attacker can escalate privileges over network
- **HIGH:** Intuitive Surgical (ISRG) discloses targeted phishing breach exposing customer/employee data, da Vinci and Ion procedure metadata, HCP engagement records, and commercial contract data -- surgical robotics platforms unaffected
- **HIGH:** Social Security Administration whistleblower alleges DOGE-linked exfiltration of sensitive PII for 500M+ Americans -- Senator Wyden characterizes it as potentially the largest known U.S. data breach in history
- **MEDIUM:** [UPDATE] Stryker still recovering from March 11 Iran-linked (Handala) cyberattack -- global operations partially disrupted; Handala confirmed using Starlink satellite connectivity to maintain C2 following Iran's internet shutdown
- **MEDIUM:** Two U.S. cybersecurity professionals plead guilty to operating BlackCat ransomware against five U.S. companies (2023); sentencing March 12, 2026 -- rare insider-threat / industry prosecution
- **MEDIUM:** CVE-2026-26125 Payment Orchestrator Service EoP (CVSS 8.6) -- unauthenticated remote privilege escalation via missing authentication; no exploitation yet but high-value target for financial infrastructure

---

## Critical Vulnerabilities

### CISA KEV -- Status as of March 16, 2026
> No new KEV additions since March 13 (CVE-2026-3909 and CVE-2026-3910, previously reported in CTI-2026-0314 and CTI-2026-0315). FCEB deadline for Chrome Skia/V8 fixes: **March 27, 2026**.

### New / Previously Unreported CVEs from March 2026 Patch Cycle

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-21513 | Windows MSHTML Framework | Security Feature Bypass / Code Exec | 8.8 | Exploited pre-patch by APT28; patched Feb 2026; IOCs still active |
| CVE-2026-23669 | Windows Print Spooler | Use-After-Free RCE | 8.8 | Patched March 10; no active exploitation; high PoC risk |
| CVE-2026-26118 | Azure MCP Server Tools | EoP via SSRF | 8.8 | Patched March 10; no active exploitation |
| CVE-2026-26125 | Windows Payment Orchestrator Service | EoP (missing auth, remote) | 8.6 | Patched March 10; no active exploitation |
| CVE-2026-26127 | Microsoft .NET 9.0/10.0 | DoS (publicly disclosed zero-day) | 7.5 | Patched March 10; publicly known before patch |
| CVE-2026-23651 | Microsoft ACI Confidential Containers | EoP | 6.7 | Patched March 10 |
| CVE-2026-26124 | Microsoft ACI Confidential Containers | EoP | 6.7 | Patched March 10 |

---

## Exploits & Zero-Days

### CVE-2026-21513 -- APT28 MSHTML Zero-Day (Formal Attribution)

Akamai Security Research published a detailed analysis formally attributing pre-patch exploitation of CVE-2026-21513 to APT28 (Fancy Bear, GRU Unit 26165). The malicious artifact was uploaded to VirusTotal on January 30, 2026 -- over a week before Microsoft's February 2026 Patch Tuesday fix.

**Technical mechanics:** The exploit uses a specially crafted Windows Shortcut (LNK) file with an embedded HTML file in the trailing data region. The LNK initiates HTTP communication with wellnesscaremed[.]com (APT28 infrastructure). The exploit leverages nested iframes and multiple DOM contexts to manipulate trust boundaries within ieframe.dll, bypassing Mark-of-the-Web (MotW) and Internet Explorer Enhanced Security Configuration (IE ESC). The final execution path reaches ShellExecuteExW, allowing code execution outside the browser sandbox. Microsoft's fix tightens hyperlink protocol validation to block file://, http://, and https:// links from reaching that code path.

**Recommended action:** Block wellnesscaremed[.]com and related APT28 C2 infrastructure. Hunt for LNK files dropped via phishing, especially targeting government, defense, and NGO sectors. Ensure February 2026 Patch Tuesday was applied.

### CVE-2026-23669 -- Windows Print Spooler RCE (PrintNightmare-Class)

Microsoft patched this use-after-free RCE in the Windows Print Spooler service on March 10. Security researchers note it operates similarly to 2021's PrintNightmare: a privileged attacker sends crafted network messages to inject and execute code. CVSS 8.8, affects Windows 10/11 and Server 2019/2022. No active exploitation confirmed but the PrintNightmare exploitation playbook is widely understood; expect rapid weaponization. Organizations with exposed print servers (especially internet-facing or accessible from OT networks) should treat this as urgent.

### CVE-2026-26127 -- .NET Publicly Disclosed DoS Zero-Day

This .NET 9.0/10.0 flaw was publicly known before Microsoft patched it on March 10, making it a disclosure-class zero-day. Affects apps on Windows, macOS, and Linux. Any .NET application running the affected runtime versions can be remotely crashed. Particularly relevant for microservices and API gateway infrastructure running on modern .NET.

---

## Malware & Ransomware

### BlackCat Ransomware -- Two U.S. Cybersecurity Professionals Plead Guilty
Ryan Goldberg and Kevin Martin, both employed in the cybersecurity industry, pleaded guilty to conspiring to extort U.S. companies using BlackCat ransomware between April and December 2023. Victims included a Florida medical device company, a Maryland pharmaceutical firm, a California doctor's office, a California engineering firm, and a Virginia drone manufacturer. Sentencing was scheduled for March 12, 2026. This case is a rare example of criminal prosecution of cybersecurity insiders leveraging RaaS tooling, underscoring that insider threat extends to practitioners with direct knowledge of defensive gaps.

### [UPDATE] Stryker -- Ongoing Recovery from Handala Cyberattack
Stryker confirmed it is still recovering globally from the March 11 Iran-linked cyberattack claimed by Handala Hack. New detail: Handala has been operating via Starlink satellite connectivity since mid-January 2026, when Iran's government announced a nationwide internet shutdown. This is a significant OPSEC adaptation -- Iranian-aligned threat actors are circumventing state-imposed connectivity restrictions using commercial satellite internet, maintaining C2 capability despite the post-airstrike infrastructure disruption.

### Brightspeed / Crimson Collective -- 1M Records, Encryption-Free Extortion
Crimson Collective's January 2026 breach of U.S. fiber broadband provider Brightspeed continues to be investigated. The group claims over 1 million residential customer records exfiltrated, including physical addresses, email, phone numbers, payment histories, and limited card data. Crimson Collective employs encryption-free pure data exfiltration and extortion -- consistent with the broader trend reported in CTI-2026-0315. Brightspeed's investigation remains ongoing.

---

## Threat Actors

### APT28 (Fancy Bear / GRU Unit 26165) -- Active MSHTML Campaign
Akamai's formal attribution of CVE-2026-21513 to APT28 confirms the group ran an active pre-patch campaign against Windows MSHTML targets. APT28 infrastructure domain wellnesscaremed[.]com was used for multistage payload delivery. This is consistent with APT28's historical TTPs: spear-phish with LNK/Office lures, browser-based initial access, credential harvesting and lateral movement. Primary targets historically include NATO governments, defense contractors, political organizations, and Eastern European infrastructure.

**IOC:** wellnesscaremed[.]com -- block at DNS/proxy level.

### [UPDATE] Handala Hack (IRGC/Void Manticore) -- Starlink OPSEC Adaptation
Handala is confirmed using Starlink satellite internet to maintain operational connectivity after Iran's national internet was disrupted to 1-4% following the February 28 U.S.-Israeli airstrike. This represents a meaningful adaptation in Iranian-aligned threat actor OPSEC tradecraft. Organizations should not assume Iranian-linked threat actors are operationally degraded simply because Iran's national internet is restricted.

### APT42 (IRGC Intelligence Organization) -- Social Engineering + Custom Backdoors
Threat intelligence reports published this week detail APT42's expanded technical arsenal. While the group's primary tradecraft remains social engineering and credential harvesting, recent campaigns incorporate custom lightweight backdoors when persistent access is required. APT42 is assessed to be operating on behalf of the IRGC Intelligence Organization. Targets include journalists, academics, diplomats, and organizations linked to U.S. and Israeli interests.

---

## Data Breaches

### Intuitive Surgical (ISRG) -- Phishing-Enabled Breach of Clinical and Commercial Data
Intuitive Surgical disclosed a targeted phishing incident that compromised an employee's access to internal business IT systems. Exposed data includes customer contact information, employee records, da Vinci and Ion procedure type and duration, field service engineer complaint logs, HCP engagement records, commercial contract data extracts, and service work orders as of January 18, 2026. Robotic surgery platforms are on a separate network and were not affected. Healthcare provider partners should audit Intuitive-connected credentials and prepare for follow-on phishing using harvested HCP contact data.

### Social Security Administration -- Alleged 500M+ American PII Breach (Whistleblower)
A whistleblower complaint filed with the SSA Office of the Inspector General alleges that a DOGE-affiliated software engineer removed sensitive personal data belonging to more than 500 million living and deceased Americans from Social Security systems. Senator Ron Wyden (D-OR) has characterized this as potentially the largest known data breach in American history. The Senate Finance Committee is investigating. The whistleblower complaint is formally filed and under OIG review.

### University of Hawaii Cancer Center -- 1.2M Affected (August 2025, Disclosed 2026)
The University of Hawaii confirmed that a ransomware group stole data belonging to approximately 1.2 million individuals after breaching its Cancer Center Epidemiology Division in August 2025. Notification to affected individuals was completed in Q1 2026.

### Conduent Business Services -- 25M+ Victims, Class Action Deadline March 31
A data breach at Conduent spanning October 2024 through January 2025 exposed personal and protected health information of over 25 million individuals, ranking as the eighth-largest healthcare data breach in U.S. history. Victims must enroll in free credit monitoring by **March 31, 2026**. Organizations using Conduent for HR or benefits administration should confirm whether employee data was in scope.

---

## Vendor Advisories

| Vendor | Advisory | Key Items |
|--------|----------|-----------|
| Microsoft | March 10 Patch Tuesday (previously reported) | NEW: CVE-2026-23669 (Print Spooler RCE 8.8), CVE-2026-26118 (Azure MCP SSRF EoP 8.8), CVE-2026-26125 (Payment Orchestrator EoP 8.6), CVE-2026-26127 (.NET DoS zero-day 7.5) |
| Google | Chrome Skia/V8 zero-day update (previously reported) | FCEB patch deadline March 27; CVE-2026-3909 and CVE-2026-3910 |
| Intuitive Surgical | Security incident notification, March 2026 | Phishing breach; da Vinci/Ion platforms unaffected; HCP and customer data exposed |
| CISA | KEV enforcement reminder | March 27 deadline for Chrome Skia/V8; March 24 deadline for VMware Aria Operations CVE-2026-22719 |

---

## Recommended Actions

1. **IMMEDIATE (24h):** Hunt for APT28 IOC wellnesscaremed[.]com in DNS logs, proxy logs, and EDR telemetry. Block at network edge. Check for LNK file drops via phishing targeting government, defense, and NGO sectors.
2. **IMMEDIATE (24h):** If you use Intuitive Surgical products -- audit HCP account credentials and reset any accounts with unusual login activity since January 18, 2026. Notify affected clinical staff.
3. **URGENT (48h):** Complete March 10 Patch Tuesday rollout; prioritize CVE-2026-23669 (Print Spooler RCE) and CVE-2026-26118 (Azure MCP SSRF EoP) in addition to previously reported critical patches.
4. **URGENT (48h):** Verify Chrome is updated past CVE-2026-3909/3910 zero-day patch. FCEB deadline is March 27 but exploitation is confirmed in the wild.
5. **URGENT (48h):** Patch VMware Aria Operations for CVE-2026-22719 (CVSS 8.1, CISA KEV). FCEB deadline is March 24.
6. **HIGH (7 days):** Update all .NET 9.0 and 10.0 runtimes for CVE-2026-26127. Affects Windows, macOS, and Linux.
7. **HIGH (7 days):** If SSA data is used in identity verification workflows, assess risk from the alleged DOGE/SSA breach. Monitor for SSN-based fraud spikes.
8. **HIGH (7 days):** Reassess Iranian APT operational status -- Handala's Starlink adaptation means full operational capability should be assumed. Continue hunting for Seedworm, APT42, and Handala/Void Manticore IOCs.
9. **MEDIUM (30 days):** Audit print server exposure. CVE-2026-23669 PrintNightmare-style mechanics will attract PoC development; print servers accessible across network segments are highest risk.
10. **MEDIUM (30 days):** If Conduent is an HR/benefits vendor, confirm employee data scope and enroll affected individuals before the March 31 credit monitoring deadline.

---

## Sources

- [APT28 Tied to CVE-2026-21513 MSHTML 0-Day | The Hacker News](https://thehackernews.com/2026/03/apt28-tied-to-cve-2026-21513-mshtml-0.html)
- [Inside the Fix: Analysis of CVE-2026-21513 In-the-Wild Exploit | Akamai](https://www.akamai.com/blog/security-research/inside-the-fix-cve-2026-21513-mshtml-exploit-analysis)
- [APT28 Exploited MSHTML Zero-Day Before February Patch Tuesday | Security Affairs](https://securityaffairs.com/188782/security/russia-linked-apt28-exploited-mshtml-zero-day-cve-2026-21513-before-patch.html)
- [CVE-2026-23669 Windows Print Spooler RCE | WindowsForum](https://windowsforum.com/threads/cve-2026-23669-use-after-free-rce-patch-windows-print-spooler-now.404533/)
- [CVE-2026-23669 | Rapid7 Vulnerability DB](https://www.rapid7.com/db/vulnerabilities/microsoft-windows-cve-2026-23669/)
- [March 2026 Patch Tuesday Analysis | CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-march-2026/)
- [March 2026 Patch Tuesday Zero-Days Fixed | Malwarebytes](https://www.malwarebytes.com/blog/news/2026/03/march-2026-patch-tuesday-fixes-two-zero-day-vulnerabilities)
- [ZDI March 2026 Security Update Review](https://www.thezdi.com/blog/2026/3/10/the-march-2026-security-update-review)
- [CISA KEV Adds VMware Aria Operations CVE-2026-22719 | The Hacker News](https://thehackernews.com/2026/03/cisa-adds-actively-exploited-vmware.html)
- [CISA KEV Adds Skia and Chromium V8 Flaws | WindowsForum](https://windowsforum.com/threads/cisa-kev-adds-critical-skia-and-chromium-v8-flaws-cve-2026-3909-cve-2026-3910-patch-now.405045/)
- [Google Fixes Two Chrome Zero-Days Exploited in the Wild | The Hacker News](https://thehackernews.com/2026/03/google-fixes-two-chrome-zero-days.html)
- [Intuitive Surgical Cybersecurity Incident Statement | Intuitive.com](https://www.intuitive.com/en-us/about-us/newsroom/Intuitive-statement-on-cybersecurity-incident)
- [Intuitive Surgical Reveals Cyber Breach | Benzinga](https://www.benzinga.com/markets/equities/26/03/51247928/intuitive-surgical-reveals-cyber-breach)
- [Wyden Statement on SSA Whistleblower Data Breach | Senate Finance Committee](https://www.finance.senate.gov/ranking-members-news/wyden-statement-on-whistleblower-report-of-massive-data-breach-at-social-security)
- [Stryker Still Recovering from Iran-Linked Cyberattack | Medical Device Network](https://www.medicaldevice-network.com/news/stryker-still-recovering-from-iran-linked-cyberattack/)
- [Two U.S. Cybersecurity Pros Plead Guilty Over Ransomware | SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [Brightspeed Investigating Cyberattack | SecurityWeek](https://www.securityweek.com/brightspeed-investigating-cyberattack/)
- [Crimson Collective Claims Brightspeed Breach -- 1M Records | CyberPress](https://cyberpress.org/crimson-collective-brightspeed-breach/)
- [Conduent Data Breach -- 25M+ Victims, Class Action | All About Lawyer](https://allaboutlawyer.com/conduent-data-breach-class-action-2026-10-feb-update-25m-victims-10-lawsuits-filed-free-credit-monitoring-deadline-march-31/)
- [Top Data Breaches March 2026 | SharkStriker](https://sharkstriker.com/blog/march-data-breaches-today-2026/)
- [Threat Brief: March 2026 Iran Escalation | Palo Alto Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [The Iranian Cyber Capability 2026 | Trellix](https://www.trellix.com/blogs/research/the-iranian-cyber-capability-2026/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
