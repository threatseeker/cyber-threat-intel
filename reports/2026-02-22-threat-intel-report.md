# Cyber Threat Intelligence Report
**Date:** 2026-02-22
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0222

---

## Executive Summary

- **NEW - CRITICAL**: Apple CVE-2026-20700 (dyld memory corruption) actively exploited in "extremely sophisticated" targeted attacks - iOS/macOS/watchOS/tvOS/visionOS all affected; Google TAG reported alongside two WebKit flaws indicating a full exploit chain
- **NEW - CRITICAL**: SmarterMail CVE-2026-24423 (CVSS 9.3 unauthenticated RCE) actively exploited in ransomware campaigns - 1,000+ attempts from 60 unique IPs; CISA KEV deadline February 26 (4 days)
- **NEW - CRITICAL**: D-Link CVE-2026-0625 (CVSS 9.3 RCE) in EOL legacy DSL routers - NO PATCH will be issued; replace affected devices immediately
- **NEW**: n8n workflow platform CVE-2026-25049 (CVSS 9.4) RCE via sandbox bypass - affects AI/automation pipelines; patch to v1.123.17 or 2.5.2
- **NEW**: Singapore Operation CYBER GUARDIAN - UNC3886 (China-linked) targeted all 4 major Singapore telecom operators via zero-day firewall bypass
- **NEW**: Japan Airlines breach (Feb 9) - customer PII exposed for users since July 2024; Substack breach (Feb 3) also disclosed
- **[UPDATE] URGENT**: CISA KEV deadlines for FreePBX (CVE-2019-19006, CVE-2025-64328) and GitLab (CVE-2021-39935) are **TOMORROW February 24** - final 24-hour warning
- **[UPDATE]**: Winter Olympics closing ceremony is **TODAY** (Feb 22) - pro-Russian hacktivist activity at peak; elevated DDoS/defacement risk through Feb 23

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2026-20700 | Apple dyld (iOS/macOS/watchOS/tvOS/visionOS) | 7.8 | Memory Corruption/RCE | **Actively exploited - sophisticated targeted attacks** |
| CVE-2026-24423 | SmarterTools SmarterMail | **9.3** | Unauthenticated RCE | **CISA KEV - deadline Feb 26 (4 DAYS)** |
| CVE-2026-0625 | D-Link DSL legacy routers | **9.3** | Command Injection RCE | **NO PATCH - EOL devices; actively exploited** |
| CVE-2026-25049 | n8n workflow automation | **9.4** | RCE via sandbox bypass | Patch immediately (all < v1.123.17 / 2.5.2) |
| CVE-2026-23760 | SmarterTools SmarterMail | High | Auth Bypass (admin reset) | CISA KEV - deadline Feb 16 (PAST DUE) |
| CVE-2019-19006 | Sangoma FreePBX | High | Improper Authentication | **CISA KEV - deadline Feb 24 (TOMORROW)** |
| CVE-2025-64328 | Sangoma FreePBX | High | OS Command Injection | **CISA KEV - deadline Feb 24 (TOMORROW)** |
| CVE-2021-39935 | GitLab CE/EE | High | SSRF | **CISA KEV - deadline Feb 24 (TOMORROW)** |

---

### NEW: CVE-2026-20700 - Apple dyld Memory Corruption (Actively Exploited)

**Product:** Apple iOS, iPadOS, macOS Tahoe, watchOS, tvOS, visionOS
**CVSS:** 7.8
**Type:** Memory corruption in dyld (Dynamic Link Editor)
**Disclosed/Patched:** February 11, 2026

Apple patched its first actively exploited zero-day of 2026 on February 11. A memory corruption flaw in `dyld` - Apple's dynamic linker - allows attackers with memory write capability to achieve arbitrary code execution. Apple acknowledged "extremely sophisticated attacks against specific targeted individuals" on pre-patch iOS versions.

Google Threat Analysis Group (TAG) reported CVE-2026-20700 alongside two WebKit flaws (CVE-2025-14174, CVE-2025-43529), indicating a deliberate exploit chain characteristic of commercial spyware or nation-state surveillance operations. Targeted individuals strongly suggests a surveillance/espionage campaign.

**Affected Versions:** iOS/iPadOS < 26.3, macOS Tahoe < 26.3, watchOS < 26.3, tvOS < 26.3, visionOS < 26.3 (backports available for iOS 18.7.5, macOS Sequoia 15.7.4, macOS Sonoma 14.8.4)

**Action:** Apply Apple security updates immediately across all Apple platforms. Prioritize executive devices and high-value targets. Consider EDR coverage for Mac fleets.

**Sources:**
- [SOC Prime - CVE-2026-20700 Analysis](https://socprime.com/blog/cve-2026-20700-vulnerability/)
- [CyberScoop - Apple First Zero-Day of 2026](https://cyberscoop.com/apple-zero-day-vulnerability-cve-2026-20700/)
- [Help Net Security - Apple Zero-Day Fixed](https://www.helpnetsecurity.com/2026/02/12/apple-zero-day-fixed-cve-2026-20700/)
- [The Hacker News - Apple Fixes Exploited Zero-Day](https://thehackernews.com/2026/02/apple-fixes-exploited-zero-day.html)

---

### NEW: CVE-2026-24423 - SmarterMail Unauthenticated RCE (Ransomware Active)

**Product:** SmarterTools SmarterMail
**CVSS:** 9.3
**Type:** Missing authentication for critical function (ConnectToHub API)
**CISA KEV Deadline:** February 26, 2026 (4 days)

An unauthenticated RCE vulnerability in SmarterMail's ConnectToHub API is being actively weaponized in ransomware attacks. Over 1,000 exploitation attempts from 60 unique attacker IPs have been observed since January 28. CISA added CVE-2026-24423 to the KEV catalog on February 5; federal agencies must patch by February 26.

Companion vulnerability CVE-2026-23760 (admin password reset auth bypass) had a KEV deadline of February 16 - organizations that missed this deadline are at elevated risk of complete server compromise.

**Action:** Patch SmarterMail immediately. Audit for indicators of compromise (unauthorized admin account creation, lateral movement from mail server). If patching is delayed, isolate SmarterMail from untrusted networks.

**Sources:**
- [Help Net Security - SmarterMail Ransomware CVE-2026-24423](https://www.helpnetsecurity.com/2026/02/06/ransomware-smartermail-cve-2026-24423/)
- [SecurityWeek - SmarterMail Exploited in Ransomware](https://www.securityweek.com/critical-smartermail-vulnerability-exploited-in-ransomware-attacks/)
- [Bleeping Computer - CISA Warns SmarterMail RCE](https://www.bleepingcomputer.com/news/security/cisa-warns-of-smartermail-rce-flaw-used-in-ransomware-attacks/)

---

### NEW: CVE-2026-0625 - D-Link Legacy DSL Routers (No Patch - Replace Now)

**Product:** D-Link DSL-2740R, DSL-2640B, DSL-2780B, DSL-526B (End of Life)
**CVSS:** 9.3
**Type:** Command injection in `dnscfg.cgi` (DNS configuration endpoint)
**Actively Exploited Since:** November 2025

A critical command injection vulnerability in D-Link's discontinued DSL gateway products is being actively exploited. The flaw exists in `dnscfg.cgi`, which fails to sanitize user input before processing DNS configuration commands. D-Link has confirmed **no patch will be released** for these EOL devices.

Exploitation has been ongoing since late November 2025. The Shadowserver Foundation is tracking active attack activity. Legacy DSL gateways in SOHO environments are the primary exposure.

**Action:** Retire and replace all affected D-Link devices. There is no mitigation short of device replacement. If replacement is not immediate, isolate from internet access and place behind a NAT/firewall with restricted management access.

**Sources:**
- [Dark Reading - Attackers Exploit Zero-Day in EOL D-Link Routers](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)
- [SecurityWeek - Hackers Exploit Zero-Day in Discontinued D-Link Devices](https://www.securityweek.com/hackers-exploit-zero-day-in-discontinued-d-link-devices/)
- [Bleeping Computer - D-Link Flaw in Legacy DSL Routers Actively Exploited](https://www.bleepingcomputer.com/news/security/new-d-link-flaw-in-legacy-dsl-routers-actively-exploited-in-attacks/)
- [SecurityOnline - CVE-2026-0625 Critical RCE](https://securityonline.info/cve-2026-0625-critical-actively-exploited-rce-hits-unpatchable-d-link-routers/)

---

### NEW: CVE-2026-25049 - n8n Workflow RCE (AI/Automation Pipeline Risk)

**Product:** n8n workflow automation platform (npm)
**CVSS:** 9.4
**Type:** Expression escape vulnerability leading to RCE (JavaScript sandbox bypass)
**Affected Versions:** All n8n < 1.123.17 (v1 branch) and < 2.5.2 (v2 branch)

A critical sandbox bypass in n8n's workflow expression evaluator enables arbitrary system command execution. The flaw arises from a mismatch between TypeScript compile-time enforcement and JavaScript runtime behavior, allowing authenticated users with workflow creation/modification permissions to escape the expression sandbox and run OS-level commands.

This is a bypass of the December 2025 patch for CVE-2025-68613 (CVSS 9.9). Organizations running n8n for AI workflow automation are at particular risk, as compromise enables credential theft, data exfiltration, and persistent backdoor installation.

**Action:** Upgrade n8n to v1.123.17 or v2.5.2 immediately. Audit n8n workflow nodes for suspicious expression payloads. Restrict workflow creation permissions to trusted users.

**Sources:**
- [The Hacker News - Critical n8n Flaw CVE-2026-25049](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [Endor Labs - CVE-2026-25049 Deep Dive](https://www.endorlabs.com/learn/cve-2026-25049-n8n-rce)
- [The Register - n8n Latest Critical Flaws Bypass December Fix](https://www.theregister.com/2026/02/05/n8n_security_woes_roll_on/)

---

## Exploits & Zero-Days

### Apple Exploit Chain - CVE-2026-20700 + WebKit Flaws (Google TAG)

See **Critical Vulnerabilities** section above. The combination of CVE-2026-20700 (dyld) with CVE-2025-14174 and CVE-2025-43529 (WebKit) forms a full exploitation chain. Google TAG's involvement and the targeted nature of attacks strongly suggests a commercial surveillance vendor or nation-state capability.

**Sources:**
- [SecurityWeek - Apple Patches iOS Zero-Day Exploited in Extremely Sophisticated Attack](https://www.securityweek.com/apple-patches-ios-zero-day-exploited-in-extremely-sophisticated-attack/)
- [Malwarebytes - Apple Patches Zero-Day Flaw](https://www.malwarebytes.com/blog/news/2026/02/apple-patches-zero-day-flaw-that-could-let-attackers-take-control-of-devices)

### D-Link CVE-2026-0625 - Unauthenticated DNS Hijacking + RCE

Active exploitation enables attackers to hijack DNS settings on compromised routers, potentially redirecting all traffic through attacker-controlled infrastructure. Combined with the RCE capability, full router compromise allows for network-level MITM attacks against all connected devices.

**Source:** [Field Effect - Legacy D-Link Routers Exploited via Unauthenticated DNS Hijacking](https://fieldeffect.com/blog/legacy-d-link-routers-exploited-via-unauthenticated-dns-hijacking)

---

## Malware & Ransomware

### [UPDATE] SmarterMail Ransomware Campaign - Active as of Feb 22

Ransomware actors are actively weaponizing CVE-2026-24423 (SmarterMail unauthenticated RCE). See Critical Vulnerabilities section for technical details. 1,000+ exploitation attempts observed. The CISA KEV deadline (Feb 26) means federal exposure is also at risk.

**Source:** [SecurityWeek - Critical SmarterMail Vulnerability Exploited in Ransomware Attacks](https://www.securityweek.com/critical-smartermail-vulnerability-exploited-in-ransomware-attacks/)

### NEW: Two US Cybersecurity Professionals Plead Guilty - Ransomware Attacks

Two US-based cybersecurity professionals pleaded guilty to conducting ransomware attacks. Details of victims and specific ransomware families were not yet fully public at time of report. This follows an increasing trend of insider threat and rogue security practitioner activity in the ransomware ecosystem.

**Source:** [SecurityWeek - Two US Cybersecurity Pros Plead Guilty](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)

### NEW: "Digital Parasite" - Ransomware-as-Residency Trend (The Hacker News Analysis)

A new analysis published by The Hacker News describes a shift in ransomware tactics from smash-and-grab encryption to long-term "residency" in victim networks - exfiltrating data continuously before ever deploying ransomware. This aligns with observed trends from Qilin, Cl0p, and Akira groups.

**Source:** [The Hacker News - From Ransomware to Residency: Inside the Rise of the Digital Parasite](https://thehackernews.com/2026/02/from-ransomware-to-residency-inside.html)

### [UPDATE] Advantest Ransomware - No Group Claim (Feb 22)

The February 15 ransomware attack on semiconductor test equipment giant Advantest (serving Intel, Samsung, TSMC) remains unclaimed by any known group. Systems disruption is ongoing; supply chain impact to semiconductor testing operations being assessed.

**Source:** [CyberPress - Ransomware Attack Disrupts Advantest](https://cyberpress.org/ransomware-attack-disrupts/)

---

## Threat Actors

### NEW: Singapore Operation CYBER GUARDIAN - UNC3886 (China-Linked) Targets All 4 Major Telcos

**Threat Actor:** UNC3886 (China-linked cyberespionage)
**Operation:** CYBER GUARDIAN (Singapore Cyber Security Agency + IMDA)
**Disclosed:** February 9, 2026
**Targets:** M1, SIMBA Telecom, Singtel, StarHub (all four major Singapore telecom operators)

The Cyber Security Agency of Singapore (CSA) revealed a coordinated multi-agency response to UNC3886's targeted campaign against Singapore's telecommunications sector. The threat actor exploited a zero-day vulnerability to bypass perimeter firewalls and gain access to all four major telco networks simultaneously.

While Singapore's CSA confirmed no customer data was accessed or exfiltrated and telecommunications services were not disrupted, the breadth of targeting (all four major carriers in a single campaign) demonstrates sophisticated pre-positioning and intelligence gathering. This is consistent with UNC3886's known focus on telecommunications infrastructure for signals intelligence collection.

**Significance:** UNC3886 previously targeted Dell RecoverPoint (CVE-2026-22769) and VMware infrastructure. The Singapore telco campaign confirms ongoing global telecommunications infrastructure targeting by this group.

**Action:** Telco and ISP organizations globally should review UNC3886 IOCs and TTPs. Review perimeter firewall zero-day exposure and monitor for lateral movement consistent with UNC3886 TTPs (living-off-the-land, custom implants).

**Sources:**
- [Computer Weekly - Singapore Mounts Largest Ever Cyber Operation vs APT](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [Cyber Security Agency of Singapore - Operation CYBER GUARDIAN](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)

### NEW: APT42 (Iran) + Gemini AI - Reconnaissance and Phishing Preparation

**Threat Actor:** APT42 (Iranian state-sponsored)
**Tool:** Google Gemini AI
**Published:** February 12, 2026 (Google GTIG / Google DeepMind)

Google Threat Intelligence Group and DeepMind published joint findings on nation-state AI misuse. Iranian APT42 was specifically identified using Google Gemini to:
- Search for official email addresses of specific targets
- Conduct reconnaissance on potential business partners
- Craft credible pretexts for phishing emails

This represents a maturation of AI-assisted spear-phishing operations. The combination of AI-generated pretexts with APT42's known focus on government, NGO, and media targets elevates phishing risk for these sectors.

**Sources:**
- [Infosecurity Magazine - Nation-State Hackers Embrace Gemini AI](https://www.infosecurity-magazine.com/news/nation-state-hackers-gemini-ai/)
- [The Record - Nation-State Hackers Ramping Up Use of Gemini](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns)
- [CYFIRMA Weekly Intelligence - February 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)

### NEW: "Prince of Persia" Iranian APT - Resurfaces After 3-Year Hiatus

**Threat Actor:** "Prince of Persia" (Iranian state-sponsored)
**Status:** Active - resurfaced in 2025 after 3-year absence

SafeBreach Labs uncovered fresh activity from the Iranian "Prince of Persia" APT, which had been dormant since approximately 2022. The group has been running sophisticated malware campaigns since resurfacing. Specific targets and TTPs were not fully disclosed at time of report, but the reemergence of a previously dormant nation-state actor warrants threat model updates for organizations tracking Iranian threat activity.

**Source:** [CYFIRMA Weekly Intelligence - February 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)

### [UPDATE] Winter Olympics - Closing Ceremony TODAY (Feb 22) - Hacktivist Peak

**Status:** PEAK RISK - Closing ceremony is TODAY
**Threat:** Pro-Russian hacktivist groups (NoName057(16), KillNet aligned)

The 2026 Winter Olympics closing ceremony in Milan/Cortina d'Ampezzo occurs today. Pro-Russian hacktivist activity has been elevated throughout the Games (since Feb 6) due to Russia's exclusion. Closing ceremonies historically represent the final peak of protest-driven cyber activity, typically including DDoS surges and defacement attempts through Feb 23.

**High-Risk Targets Today:** Italian government infrastructure, Olympic broadcast systems, Western media organizations, Olympic corporate sponsors.

**Action:** Maintain elevated monitoring posture through Feb 23. DDoS mitigation should be on standby for Italian-facing services and sponsor organizations.

**Source:** [CYFIRMA Weekly Intelligence - February 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)

---

## Data Breaches

| Organization | Records Affected | Data Exposed | Threat Actor | Notes |
|-------------|-----------------|--------------|--------------|-------|
| Japan Airlines | Unknown (customers Jul 2024+) | Names, phones, emails, travel details | Unknown | Unauthorized access Feb 9 |
| Substack | Unknown | Phone numbers, email addresses, user data | Unknown | Unauthorized access Feb 3 |
| Cottage Hospital | 1,600 | SSNs, driver's licenses, bank accounts | Unknown | October 2023 breach disclosed Feb 2026 |

### NEW: Japan Airlines - Customer Data Breach (Feb 9)

**Organization:** Japan Airlines (JAL)
**Disclosed:** February 9, 2026
**Data Exposed:** Customer names, phone numbers, email addresses, travel-related details
**Scope:** Customers who used JAL services since July 2024

Japan Airlines discovered unauthorized access to systems and data on February 9. All customers who have used JAL since July 2024 may be affected. The breach exposed core PII and travel history, enabling targeted phishing and social engineering against frequent fliers.

**Action:** JAL customers should be alert to phishing using travel details as lure. Organizations with JAL corporate accounts should review employee exposure.

**Source:** [SharkStriker - Top Data Breaches February 2026](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)

### NEW: Substack - User Data Breach (Feb 3)

**Organization:** Substack (newsletter/publishing platform)
**Discovered:** February 3, 2026
**Data Exposed:** Phone numbers, email addresses, and other user data

Substack disclosed unauthorized access to user data on February 3. The platform hosts numerous journalists, researchers, and public figures, making this breach of particular value for phishing and impersonation campaigns targeting prominent individuals.

**Action:** Substack users should enable 2FA and be vigilant for phishing attempts using Substack-specific social engineering.

**Source:** [SharkStriker - Top Data Breaches February 2026](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)

### NEW: Cottage Hospital - 1,600 Affected (Delayed Disclosure)

**Organization:** Cottage Hospital (Twin States region)
**Breach Date:** October 2023
**Disclosed:** February 2026 (delayed ~16 months)
**Data Exposed:** Names, Social Security numbers, driver's license numbers, bank account information

**Note:** The 16-month disclosure delay is concerning. While the breach was in October 2023, notifications are only being issued now, limiting victim response time. Healthcare breach delayed disclosures remain a systemic problem.

**Source:** [Valley News - Cottage Hospital Data Breach](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)

---

## Vendor Advisories

### Apple - Emergency Security Updates (Feb 11)
**Products:** iOS/iPadOS 26.3, macOS Tahoe 26.3, watchOS 26.3, tvOS 26.3, visionOS 26.3
**Priority:** CRITICAL - actively exploited zero-day chain
Apply updates immediately. Older OS users: iOS 18.7.5 and macOS 15.7.4/14.8.4 backports available.

**Source:** [Help Net Security - Apple Zero-Day Fixed](https://www.helpnetsecurity.com/2026/02/12/apple-zero-day-fixed-cve-2026-20700/)

### SmarterTools - SmarterMail
**CVEs:** CVE-2026-24423 (RCE, ransomware active), CVE-2026-23760 (auth bypass)
**Priority:** CRITICAL - CISA KEV; active ransomware exploitation
Patch immediately. Deadline for federal agencies: Feb 26.

**Source:** [CISA - Adds Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### n8n - Workflow Automation Platform
**CVE:** CVE-2026-25049 (CVSS 9.4)
**Fix:** Upgrade to v1.123.17 (v1) or v2.5.2 (v2)

**Source:** [The Hacker News - Critical n8n Flaw](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)

### D-Link - EOL DSL Routers
**CVE:** CVE-2026-0625 (CVSS 9.3) - NO PATCH AVAILABLE
**Models:** DSL-2740R, DSL-2640B, DSL-2780B, DSL-526B
**Action:** Replace devices. No patch will be issued.

**Source:** [SecurityOnline - CVE-2026-0625](https://securityonline.info/cve-2026-0625-critical-actively-exploited-rce-hits-unpatchable-d-link-routers/)

### Google-Wiz Acquisition ($32B) - EU Approved
The European Commission granted unconditional approval for Google's $32 billion acquisition of cybersecurity firm Wiz. No competition concerns were raised. Implications for Wiz's CNAPP/cloud security product direction should be monitored as integration planning begins.

**Source:** [WEF - 2026 Cyberthreats to Watch](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)

---

## CISA KEV Deadline Tracker (Updated Feb 22)

| CVE | Product | CISA Deadline | Status |
|-----|---------|---------------|--------|
| CVE-2026-23760 | SmarterMail Auth Bypass | Feb 16 | **PAST DUE** |
| CVE-2019-19006 | FreePBX Improper Auth | **Feb 24** | **TOMORROW** |
| CVE-2025-64328 | Sangoma FreePBX Cmd Injection | **Feb 24** | **TOMORROW** |
| CVE-2021-39935 | GitLab CE/EE SSRF | **Feb 24** | **TOMORROW** |
| CVE-2026-24423 | SmarterMail Unauthenticated RCE | **Feb 26** | 4 days |
| CVE-2026-21510/21513/21514/21519/21525/21533 | Microsoft (6 zero-days) | Mar 3 | 9 days |
| CVE-2026-1731 | BeyondTrust RS/PRA | ~Mar 6 | 12 days |
| CVE-2025-49113 | RoundCube Webmail | TBD | ACTIVELY EXPLOITED |
| CVE-2025-68461 | RoundCube Webmail | TBD | ACTIVELY EXPLOITED |
| CVE-2026-22769 | Dell RecoverPoint | TBD | ACTIVELY EXPLOITED (UNC6201) |
| CVE-2025-30411 | Linux Cyber Protect | TBD | CVSS 10.0 |
| CVE-2025-30412 | Linux Cyber Protect | TBD | CVSS 10.0 |
| CVE-2026-0625 | D-Link DSL Routers | TBD / NO PATCH | REPLACE DEVICES |

---

## Recommended Actions

### Priority 1 - Patch/Act Today (Feb 22)
1. **Apple Devices**: Apply iOS 26.3 / macOS Tahoe 26.3 / watchOS 26.3 / tvOS 26.3 updates - actively exploited sophisticated attack chain (CVE-2026-20700 + WebKit)
2. **D-Link Legacy Routers**: Retire and replace DSL-2740R, DSL-2640B, DSL-2780B, DSL-526B immediately - no patch exists, active exploitation ongoing
3. **Winter Olympics Alert**: Maintain elevated monitoring for Italian and Olympic-affiliated infrastructure through Feb 23; DDoS mitigation on standby

### Priority 2 - Patch by Feb 24 (CISA KEV TOMORROW)
4. **Sangoma FreePBX**: Patch CVE-2019-19006 and CVE-2025-64328 - CISA KEV deadline is TOMORROW (federal agencies must comply)
5. **GitLab CE/EE**: Patch CVE-2021-39935 (SSRF) - CISA KEV deadline is TOMORROW

### Priority 3 - Patch by Feb 26 (CISA KEV 4 Days)
6. **SmarterMail**: Patch CVE-2026-24423 (CVSS 9.3 unauthenticated RCE) and CVE-2026-23760 (auth bypass, already past due). Audit for ransomware IOCs immediately even pre-patch.

### Priority 4 - This Week
7. **n8n Workflow Platform**: Upgrade to v1.123.17 or v2.5.2 (CVE-2026-25049, CVSS 9.4) - particularly critical for AI/automation pipeline operators
8. **SmarterMail IOC Hunt**: Audit for unauthorized admin accounts, lateral movement artifacts from mail server, even if patched
9. **UNC3886 IOC Review**: Telecom and ISP operators globally should review UNC3886 TTPs post-Singapore disclosure; audit perimeter firewalls for zero-day exposure

### Priority 5 - Process & Awareness
10. **JAL/Substack Phishing Alert**: Employees who use Japan Airlines (since Jul 2024) or Substack should be notified of potential phishing risk from leaked PII
11. **AI-Assisted Spear Phishing Defense**: Brief security awareness teams on APT42's Gemini-assisted phishing capability; focus on email verification for Iran-attributed targets (government, NGO, media)
12. **"Prince of Persia" Watch**: Update threat models for Iranian APT activity; monitor SafeBreach Labs and threat intel feeds for emerging IOCs
13. **Ransomware Residency Defense**: Review dwell time detection capabilities; implement behavioral analytics to catch long-term persistence before ransomware deployment phase
14. **Cottage Hospital Notification Delay**: Healthcare sector should review disclosure timeline compliance; 16-month delays expose organizations to regulatory action

---

## Sources

- [SOC Prime - CVE-2026-20700 Analysis](https://socprime.com/blog/cve-2026-20700-vulnerability/)
- [CyberScoop - Apple First Zero-Day of 2026](https://cyberscoop.com/apple-zero-day-vulnerability-cve-2026-20700/)
- [Help Net Security - Apple Zero-Day Fixed CVE-2026-20700](https://www.helpnetsecurity.com/2026/02/12/apple-zero-day-fixed-cve-2026-20700/)
- [The Hacker News - Apple Fixes Exploited Zero-Day](https://thehackernews.com/2026/02/apple-fixes-exploited-zero-day.html)
- [SecurityWeek - Apple Patches iOS Zero-Day in Extremely Sophisticated Attack](https://www.securityweek.com/apple-patches-ios-zero-day-exploited-in-extremely-sophisticated-attack/)
- [Malwarebytes - Apple Patches Zero-Day Flaw](https://www.malwarebytes.com/blog/news/2026/02/apple-patches-zero-day-flaw-that-could-let-attackers-take-control-of-devices)
- [Help Net Security - SmarterMail Ransomware CVE-2026-24423](https://www.helpnetsecurity.com/2026/02/06/ransomware-smartermail-cve-2026-24423/)
- [SecurityWeek - SmarterMail Exploited in Ransomware](https://www.securityweek.com/critical-smartermail-vulnerability-exploited-in-ransomware-attacks/)
- [Bleeping Computer - CISA Warns SmarterMail RCE](https://www.bleepingcomputer.com/news/security/cisa-warns-of-smartermail-rce-flaw-used-in-ransomware-attacks/)
- [Dark Reading - Attackers Exploit Zero-Day in EOL D-Link Routers](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)
- [SecurityWeek - Hackers Exploit Zero-Day in Discontinued D-Link Devices](https://www.securityweek.com/hackers-exploit-zero-day-in-discontinued-d-link-devices/)
- [Bleeping Computer - D-Link Flaw Actively Exploited](https://www.bleepingcomputer.com/news/security/new-d-link-flaw-in-legacy-dsl-routers-actively-exploited-in-attacks/)
- [SecurityOnline - CVE-2026-0625 D-Link No Patch](https://securityonline.info/cve-2026-0625-critical-actively-exploited-rce-hits-unpatchable-d-link-routers/)
- [Field Effect - D-Link DNS Hijacking](https://fieldeffect.com/blog/legacy-d-link-routers-exploited-via-unauthenticated-dns-hijacking)
- [The Hacker News - Critical n8n Flaw CVE-2026-25049](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [Endor Labs - CVE-2026-25049 Deep Dive](https://www.endorlabs.com/learn/cve-2026-25049-n8n-rce)
- [The Register - n8n Security Woes](https://www.theregister.com/2026/02/05/n8n_security_woes_roll_on/)
- [Computer Weekly - Singapore Operation CYBER GUARDIAN](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [CSA Singapore - UNC3886 Telco Campaign](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [Infosecurity Magazine - Nation-State Hackers Embrace Gemini AI](https://www.infosecurity-magazine.com/news/nation-state-hackers-gemini-ai/)
- [The Record - Nation-State Hackers Using Gemini](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns)
- [SecurityWeek - Two US Cybersecurity Pros Plead Guilty](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [The Hacker News - From Ransomware to Residency](https://thehackernews.com/2026/02/from-ransomware-to-residency-inside.html)
- [CyberPress - Advantest Ransomware Disrupts](https://cyberpress.org/ransomware-attack-disrupts/)
- [CYFIRMA Weekly Intelligence - February 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [SharkStriker - Top Data Breaches February 2026](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)
- [Valley News - Cottage Hospital Data Breach](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds Two KEV Feb 20](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [WEF - 2026 Cyberthreats to Watch](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [FTC - Second Report to Congress on Ransomware](https://www.ftc.gov/news-events/news/press-releases/2026/02/ftc-issues-second-report-congress-its-work-fight-ransomware-other-cyberattacks)

---

*Report generated: 2026-02-22*
*Next report: 2026-02-23*
*Classification: TLP:CLEAR*
*Deduplication: Items from Feb 18, Feb 20, and Feb 21 reports not repeated unless marked [UPDATE]. Excluded (see prior reports): Linux Cyber Protect CVSS 10.0 (CVE-2025-30411/30412), Microsoft Semantic Kernel CVE-2026-26030, Odido telecom breach, Figure/Shiny Hunterz breach (previously reported; 967K records now confirmed), Microsoft Feb Patch Tuesday 6 zero-days, Cisco/Fortinet patches, BeyondTrust CVE-2026-1731, RoundCube KEV additions, Dell RecoverPoint/UNC6201, Harvard/ShinyHunters breach, IRS data breach, Qilin/Conpet, Advantest (no new claims).*
