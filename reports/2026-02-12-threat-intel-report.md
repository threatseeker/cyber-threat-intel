# Cyber Threat Intelligence Report
**Date:** February 12, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0212

---

## Executive Summary

- **UPDATE**: Microsoft Patch Tuesday revised - 6 actively exploited zero-days (up from 2 initially reported), 59 total CVEs, 5 critical; CISA added all 6 to KEV with March 3 deadline
- **NEW**: CVE-2026-21511 - Outlook spoofing via deserialization triggers in email preview pane; no user action required beyond viewing
- **NEW**: CVE-2026-24300 - Azure Front Door EoP (CVSS 9.8) - unauthenticated privilege escalation; Microsoft patched server-side
- **NEW**: CVE-2026-0488 - SAP CRM/S4HANA code injection (CVSS 9.9) - authenticated low-privilege users can execute arbitrary code
- **NEW**: CVE-2026-21643 - FortiClientEMS SQLi (CVSS 9.1) - unauthenticated RCE via crafted HTTP requests; only v7.4.4 affected
- **NEW**: SSHStalker botnet - 7,000 Linux systems compromised via IRC C2 and legacy kernel exploits dating back to 2009; Romanian-linked
- **NEW**: UNC1069 (North Korea) deploys deepfake Zoom calls and ClickFix technique with 7+ macOS malware families targeting crypto/DeFi sector
- **NEW**: APT36/SideCopy (Pakistan) launches three parallel RAT campaigns against Indian defense, government, and strategic sectors
- **NEW**: Picus Red Report 2026 - 38% drop in encryption-based ransomware; attackers shift to "silent residency" and long-term stealth exfiltration

---

## Critical Vulnerabilities

### UPDATE: Microsoft Patch Tuesday - 6 Actively Exploited Zero-Days (Revised)

**Released:** February 10, 2026
**Total CVEs:** 59 vulnerabilities (5 critical, 52 important, 2 moderate)
**Zero-Days:** 6 actively exploited (3 also publicly disclosed) - significantly more than the 2 initially reported
**CISA KEV:** All 6 added February 10; remediation deadline **March 3, 2026**

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-21510 | Windows Shell | Security Feature Bypass (SmartScreen) | 8.8 | Exploited + Disclosed |
| CVE-2026-21513 | MSHTML Framework | Security Feature Bypass | 8.8 | Exploited + Disclosed |
| CVE-2026-21514 | Microsoft Word/Office | OLE Mitigation Bypass | 7.8 | Exploited + Disclosed |
| CVE-2026-21519 | Desktop Window Manager | Elevation of Privilege (SYSTEM) | 7.8 | Exploited |
| CVE-2026-21533 | Remote Desktop Services | Elevation of Privilege (SYSTEM) | High | Exploited |
| CVE-2026-21525 | Remote Access Connection Manager | Denial of Service | High | Exploited |

**CVE-2026-21510** bypasses Windows SmartScreen and Shell warnings when users open malicious links or .lnk shortcut files. **CVE-2026-21513** bypasses MSHTML protection prompts via crafted HTML/.lnk files. **CVE-2026-21514** bypasses OLE mitigations in Office. **CVE-2026-21519** enables local attackers to escalate to SYSTEM via DWM. **CVE-2026-21525** disrupts VPN connections by crashing the Remote Access Connection Manager service.

The February 10 report covered the initial 2 zero-day count. The actual release contained 6 zero-days - matching last year's high-water mark.

**Action:** Deploy patches immediately. All 6 zero-days are in CISA KEV with March 3 deadline for federal agencies.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/), [Tenable](https://www.tenable.com/blog/microsofts-february-2026-patch-tuesday-addresses-54-cves-cve-2026-21510-cve-2026-21513), [SecurityWeek](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/), [Krebs on Security](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/), [CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-february-2026/), [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2026/02/10/microsoft-patch-tuesday-february-2026-security-update-review), [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days), [CyberScoop](https://cyberscoop.com/microsoft-patch-tuesday-february-2026/)

---

### NEW: CVE-2026-21511 - Microsoft Outlook Spoofing (Preview Pane Attack Vector)

**CVE:** CVE-2026-21511
**CVSS:** 7.5
**Type:** Spoofing via deserialization of untrusted data
**Exploitability:** "Exploitation More Likely" (Microsoft)
**Attack Vector:** Email preview pane - no user action required beyond viewing

**Why Notable:** This is a zero-click-adjacent vulnerability. Simply previewing a crafted email in Outlook triggers deserialization of untrusted data, enabling spoofing attacks. The preview pane processes the malicious content automatically.

**Action:** Included in February Patch Tuesday. Deploy alongside zero-day patches.

**Sources:** [Tenable](https://www.tenable.com/blog/microsofts-february-2026-patch-tuesday-addresses-54-cves-cve-2026-21510-cve-2026-21513), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21511)

---

### NEW: CVE-2026-24300 - Azure Front Door Elevation of Privilege (CVSS 9.8)

**CVE:** CVE-2026-24300
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N)
**Type:** Improper Access Control (CWE-284)
**Product:** Microsoft Azure Front Door
**Status:** Patched server-side by Microsoft; no admin action required

**Impact:** An unauthenticated remote attacker could escalate privileges within Azure Front Door, potentially redirecting traffic, bypassing security controls, or causing denial of service. Azure Front Door is widely used by enterprises to secure and accelerate web applications.

**Significance:** Although Microsoft resolved this server-side (no customer patches needed), the CVSS 9.8 with no authentication required makes this one of the most critical cloud vulnerabilities this month. Organizations should verify their Azure Front Door configurations are intact.

**Sources:** [Heise Online](https://www.heise.de/en/news/Microsoft-addresses-critical-security-vulnerability-in-Azure-environment-11169172.html), [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-24300/), [NVD](https://nvd.nist.gov/vuln/detail/cve-2026-24300)

---

### NEW: CVE-2026-0488 - SAP CRM/S4HANA Code Injection (CVSS 9.9)

**CVE:** CVE-2026-0488
**CVSS:** 9.9 (Critical)
**Type:** Code Injection in Scripting Editor
**Products:** SAP CRM, SAP S/4HANA
**SAP Note:** 3697099
**Released:** February 11, 2026 (SAP Security Patch Day)

**Impact:** Authenticated low-privilege users can inject and execute arbitrary SQL statements and code, converting "business user" access into application-layer execution. Successful exploitation leads to full database compromise with high impact on confidentiality, integrity, and availability.

**Affected:** S4FND 102-109, SAP_ABA 700, WEBCUIF 700/701/730/731/746/747/748/800/801

**Why Critical:** SAP landscapes are tightly coupled - compromising one module enables lateral movement across integrations. A CVSS 9.9 with low-privilege authentication makes this accessible to any authenticated business user.

**Sources:** [SecurityWeek](https://www.securityweek.com/sap-patches-critical-crm-s-4hana-netweaver-vulnerabilities/), [Cybersecurity News](https://cybersecuritynews.com/sap-security-patch-day-feburary/), [GBHackers](https://gbhackers.com/sap-security-patch-day-fixes-critical-code-injection-flaw/), [RedRays](https://redrays.io/blog/sap-security-patch-day-february-2026/)

---

### NEW: CVE-2026-21643 - FortiClientEMS SQL Injection (CVSS 9.1)

**CVE:** CVE-2026-21643
**CVSS:** 9.1 (Critical)
**Type:** SQL Injection (unauthenticated)
**Product:** Fortinet FortiClientEMS
**Affected:** FortiClientEMS 7.4.4 only (7.2 and 8.0 not affected)
**Fixed:** FortiClientEMS 7.4.5
**Discovered:** Internally by Fortinet

**Impact:** An unauthenticated attacker can execute unauthorized code or commands via specially crafted HTTP requests to the FortiClientEMS administrative interface. Successful exploitation provides an initial foothold for lateral movement and malware deployment.

**Context:** This follows Fortinet's pattern of critical vulnerabilities in endpoint management products. While not yet exploited in the wild, given Fortinet's history of rapid post-disclosure exploitation (FortiCloud SSO CVE-2026-24858 was weaponized within days), organizations should patch urgently.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/fortinet-patches-critical-sqli-flaw.html), [SOC Prime](https://socprime.com/blog/cve-2026-21643-vulnerability/), [Arctic Wolf](https://arcticwolf.com/resources/blog/cve-2026-21643/), [CSA Singapore](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-013/), [Security Affairs](https://securityaffairs.com/187787/security/critical-fortinet-forticlientems-flaw-allows-remote-code-execution.html)

---

### CISA KEV Updates

**February 10 additions (6 CVEs):** CVE-2026-21510, CVE-2026-21513, CVE-2026-21514, CVE-2026-21519, CVE-2026-21525, CVE-2026-21533 - all Microsoft zero-days, deadline **March 3, 2026**

**Deadlines passed/imminent:**

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20045 | Cisco Unified CM/Webex | **Passed (Feb 11)** |
| CVE-2025-31125 | Vite Vitejs | **TODAY (Feb 12)** |
| CVE-2025-34026 | Versa Concerto | **TODAY (Feb 12)** |
| CVE-2025-68645 | Zimbra ZCS | **TODAY (Feb 12)** |
| CVE-2026-21509 | Microsoft Office | Feb 16 |
| CVE-2019-19006/CVE-2025-64328 | FreePBX/Sangoma | Feb 24 |
| CVE-2021-39935 | GitLab CE/EE | Feb 24 |
| CVE-2026-24423 | SmarterTools SmarterMail | Feb 26 |
| CVE-2025-11953 | React Native CLI | Feb 26 |

**Sources:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CISA Alert - Feb 10](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog), [CyberNews](https://cybernews.com/security/microsoft-six-exploited-zero-days-cisa-kev-february-2026/)

---

## Threat Actors

### NEW: UNC1069 (North Korea) - Deepfake Zoom + ClickFix Crypto Campaign

**Threat Actor:** UNC1069 / "CryptoCore" (North Korea-linked, high confidence - Mandiant)
**Target Sector:** Cryptocurrency and DeFi organizations
**Disclosed:** February 11, 2026

**Attack Chain:**
1. Hijacked Telegram account used for initial contact
2. Victim invited to fake Zoom meeting
3. During the call, an **AI-generated deepfake video** of a CEO from another crypto company is displayed
4. **ClickFix-style social engineering** tricks victim into executing a command
5. Multi-stage macOS malware deployment begins

**Malware Arsenal (7+ families):**
- WAVESHAPER, HYPERCALL, HIDDENCALL (existing families)
- SILENCELIFT, DEEPBREATH, CHROMEPUSH (new families)
- Additional unnamed macOS backdoors

**Significance:** This is one of the first documented cases of deepfake video being used operationally in a targeted intrusion. The combination of hijacked trusted accounts, deepfake identity verification, and ClickFix delivery represents a significant evolution in social engineering tradecraft.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/north-korea-linked-unc1069-uses-ai.html), [Dark Reading](https://www.darkreading.com/threat-intelligence/north-koreas-unc1069-hammers-crypto-firms), [BleepingComputer](https://www.bleepingcomputer.com/news/security/north-korean-hackers-use-new-macos-malware-in-crypto-theft-attacks/), [CSO Online](https://www.csoonline.com/article/4130724/north-korean-actors-blend-clickfix-with-new-macos-backdoors-in-crypto-campaign.html), [The Record](https://therecord.media/north-korean-hackers-targeted-crypto-exec-clickfix), [Decrypt](https://decrypt.co/357601/google-warns-of-ai-powered-north-korean-malware-campaign-targeting-crypto-defi)

---

### NEW: APT36/SideCopy (Pakistan) - Three-Pronged Assault on Indian Defense

**Threat Actor:** Transparent Tribe (APT36) and SideCopy subgroup (Pakistan-attributed)
**Targets:** Indian defense, government, and strategic sector organizations
**Disclosed:** February 10-11, 2026
**Platforms:** Windows and Linux

**Three Parallel Campaigns:**

| Campaign | RAT | Technique |
|----------|-----|-----------|
| Campaign 1 | GETA RAT (.NET) | mshta.exe abuse, XAML deserialization, in-memory execution |
| Campaign 2 | ARES RAT | Defense-themed phishing lures, impersonated official documents |
| Campaign 3 | Desk RAT | PowerPoint Add-In files, ELF binaries for Linux |

**Delivery Methods:** Phishing emails with malicious attachments or embedded download links, including Windows shortcuts (.lnk), ELF binaries, and PowerPoint Add-In files that launch multi-stage payload chains.

**Persistence:** GETA RAT uses layered startup mechanisms via legitimate Windows components to evade signature-based detection.

**Significance:** Three simultaneous campaigns across both Windows and Linux demonstrate a well-resourced, persistent threat actor with dedicated focus on Indian strategic infrastructure.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/apt36-and-sidecopy-launch-cross.html), [SecurityWeek](https://www.securityweek.com/rats-in-the-machine-inside-a-pakistan-linked-three-pronged-cyber-assault-on-india/)

---

## Malware & Botnets

### NEW: SSHStalker Botnet - 7,000 Linux Systems via IRC C2

**Discovered by:** Multiple researchers (February 11, 2026)
**Scale:** ~7,000 compromised systems
**C2 Protocol:** IRC (Internet Relay Chat)
**Suspected Origin:** Romanian (overlaps with Outlaw hacking group)

**Technical Details:**
- Initial access via automated SSH scanning and brute forcing
- Go binary masquerades as nmap for network discovery
- Downloads GCC to compile payloads on-device for portability/evasion
- Exploits a catalog of **16 distinct Linux kernel vulnerabilities** (some from 2009)
- Multi-server/channel IRC redundancy for resilient C2

**Targets:** Geographically dispersed across US, Europe, and Asia-Pacific; heavily concentrated on cloud providers including Oracle Cloud infrastructure.

**Why Notable:** While IRC-based botnets are considered "old school," SSHStalker's approach prioritizes resilience, scale, and low cost over stealth - and its exploitation of legacy kernel vulnerabilities highlights the persistent risk of unpatched Linux systems.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-linux-botnet-sshstalker-uses-old-school-irc-for-c2-comms/), [The Hacker News](https://thehackernews.com/2026/02/sshstalker-botnet-uses-irc-c2-to.html), [SecurityWeek](https://www.securityweek.com/new-sshstalker-linux-botnet-uses-old-techniques/), [SC Media](https://www.scworld.com/news/sshstalker-botnet-hijacks-7000-linux-systems-using-irc-and-ssh), [SecPod](https://www.secpod.com/blog/7000-servers-and-counting-the-rise-of-the-sshstalker-linux-botnet/)

---

### NEW: Kimwolf Botnet Disrupts I2P Anonymity Network

**Botnet:** Kimwolf (surfaced late 2025, 2M+ infected devices)
**Incident:** Sybil attack on I2P network
**Impact:** I2P service disruptions for users

**What Happened:**
- Kimwolf operators attempted to join **700,000 infected bots** as nodes on I2P
- This constitutes a Sybil attack - overwhelming a peer-to-peer network with fake nodes
- The operators admitted on Discord they "accidentally" disrupted I2P
- Actual goal: establish backup C2 infrastructure on I2P and Tor that can't be easily taken down

**Context:** Kimwolf is a massive IoT botnet (TV streaming boxes, digital picture frames, routers) used for DDoS attacks. The move to establish C2 on anonymity networks represents an evolution in botnet resilience tactics.

**Sources:** [Krebs on Security](https://krebsonsecurity.com/2026/02/kimwolf-botnet-swamps-anonymity-network-i2p/), [The Hacker News (Jan)](https://thehackernews.com/2026/01/kimwolf-android-botnet-infects-over-2.html)

---

## Threat Intelligence Reports

### NEW: Picus Red Report 2026 - The Rise of the "Digital Parasite"

**Published:** February 10, 2026
**Dataset:** 1.1 million malicious files, 15.5 million actions (2025)
**Publisher:** Picus Security

**Key Findings:**

| Metric | Change |
|--------|--------|
| Data Encrypted for Impact | **-38%** (ransomware's signature technique declining) |
| Stealth/evasion techniques | **8 of top 10** MITRE ATT&CK techniques now stealth-focused |
| Attacker goal shift | From disruption to "silent residency" and long-term access |

**Notable Tradecraft Evolution:**
- Malware like LummaC2 now uses **trigonometry** (Euclidean distance of mouse movement angles) to detect sandbox environments
- If mouse movements are too "perfect," the malware refuses to detonate
- Attackers maintain invisible access for weeks/months, then extort using stolen data
- As organizations mastered backups, the encryption-based ransomware business model collapsed

**Strategic Implication:** Detection strategies focused on encryption activity will increasingly miss threats. Organizations need to invest in data exfiltration detection, anomalous access patterns, and behavioral analytics.

**Sources:** [GlobeNewsWire](https://www.globenewswire.com/news-release/2026/02/10/3235422/0/en/Picus-Red-Report-2026-Finds-38-Drop-in-Ransomware-Attacks-as-Hackers-Choose-Silent-Residency-Over-Destruction.html), [The Hacker News](https://thehackernews.com/2026/02/from-ransomware-to-residency-inside.html), [eSecurity Planet](https://www.esecurityplanet.com/threats/picus-red-report-2026-shows-attackers-favor-stealth-over-disruption/), [Picus Security](https://www.picussecurity.com/red-report)

---

## Data Breaches

### UPDATE: Conduent Breach - Volvo Group NA 17K Employees Added

**Previous Coverage:** Feb 6, 9, 10 reports (25.9M total)
**What's New:** Conduent breach now confirmed to include data from nearly **17,000 Volvo Group North America employees**, expanding the list of impacted organizations.

**Running Totals:**
- 25M+ individuals affected across multiple states
- 10+ federal class action lawsuits filed
- Credit monitoring deadline: **March 31, 2026**
- 15.4M in Texas alone

**Source:** [TechCrunch](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/), [Fox Business](https://www.foxbusiness.com/technology/data-breach-exposes-personal-data-25m-americans)

---

## Vendor Advisories

### Microsoft
- **Patch Tuesday (Feb 10):** 59 CVEs, 6 actively exploited zero-days (revised from initial 2)
- Deploy patches immediately; all 6 zero-days in CISA KEV (deadline March 3)
- CVE-2026-24300 Azure Front Door (CVSS 9.8) patched server-side; no admin action needed
- CVE-2026-21511 Outlook spoofing via preview pane - "Exploitation More Likely"

### SAP
- **Security Patch Day (Feb 11):** CVE-2026-0488 (CVSS 9.9) code injection in CRM/S4HANA
- Apply SAP Note 3697099 immediately for S4HANA and CRM systems

### Fortinet
- **CVE-2026-21643** FortiClientEMS SQLi (CVSS 9.1) - upgrade 7.4.4 to 7.4.5
- Only version 7.4.4 affected; 7.2 and 8.0 are safe

### CISA
- Three CISA KEV deadlines **today** (Feb 12): Vite, Versa Concerto, Zimbra
- Cisco UCM/Webex deadline passed yesterday (Feb 11)
- 6 new Microsoft CVEs added with March 3 deadline

---

## Recommended Actions

### Immediate Priority (Next 24 Hours)

1. **Microsoft Patch Tuesday (REVISED)** - 6 zero-days, not 2; deploy all February patches immediately; prioritize CVE-2026-21510 (SmartScreen bypass) and CVE-2026-21519 (SYSTEM EoP)
2. **CISA KEV deadlines TODAY** - Vite (CVE-2025-31125), Versa Concerto (CVE-2025-34026), Zimbra (CVE-2025-68645) must be patched by end of day
3. **FortiClientEMS** - If running v7.4.4, upgrade to 7.4.5 for CVE-2026-21643 before exploitation begins
4. **SAP CRM/S4HANA** - Apply SAP Note 3697099 for CVE-2026-0488 (CVSS 9.9); any authenticated business user can exploit this

### High Priority (This Week)

5. **Outlook preview pane** - CVE-2026-21511 triggers on email preview; ensure February patches deployed across all Outlook instances
6. **Azure Front Door** - Verify configurations intact; Microsoft patched server-side but review for any unauthorized changes
7. **Linux infrastructure** - Audit for SSHStalker indicators: anomalous SSH scanning, IRC traffic, Go binaries masquerading as nmap
8. **macOS crypto/DeFi environments** - Alert employees to UNC1069 deepfake Zoom/ClickFix campaign; block suspicious Telegram invites to video calls

### Threat Hunting

9. **Linux kernel patching** - SSHStalker exploits 16 kernel vulnerabilities (some from 2009); audit Linux fleet for missing kernel patches
10. **Data exfiltration detection** - Per Picus Red Report, 38% fewer encryption events but attackers are silently stealing data; review DLP and network egress monitoring
11. **Indian defense/government orgs** - Hunt for GETA RAT, ARES RAT, and DeskRAT indicators; check for mshta.exe abuse and XAML deserialization
12. **I2P/Tor traffic** - Monitor for Kimwolf botnet indicators; unusual I2P node activity may indicate compromised hosts

### Strategic

13. **Shift detection focus** - Encryption-based ransomware declining; invest in behavioral analytics and silent exfiltration detection per Picus findings
14. **Deepfake awareness** - UNC1069 used AI-generated video in live calls; update social engineering training to cover video call impersonation
15. **SAP governance** - CVE-2026-0488 turns any business user into an attacker; review SAP role assignments and Scripting Editor access controls

---

## Sources

- [BleepingComputer - Microsoft February Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [SecurityWeek - 6 Zero-Days](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)
- [Krebs on Security - February 2026 Patch Tuesday](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [Tenable - February 2026 Patch Tuesday](https://www.tenable.com/blog/microsofts-february-2026-patch-tuesday-addresses-54-cves-cve-2026-21510-cve-2026-21513)
- [CrowdStrike - February Patch Tuesday Analysis](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-february-2026/)
- [Qualys - February Patch Tuesday Review](https://blog.qualys.com/vulnerabilities-threat-research/2026/02/10/microsoft-patch-tuesday-february-2026-security-update-review)
- [Malwarebytes - Six Zero-Days](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)
- [CyberScoop - Patch Tuesday](https://cyberscoop.com/microsoft-patch-tuesday-february-2026/)
- [CISA - Six KEV Additions Feb 10](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CyberNews - Microsoft Six Zero-Days CISA KEV](https://cybernews.com/security/microsoft-six-exploited-zero-days-cisa-kev-february-2026/)
- [Heise Online - Azure Front Door CVE-2026-24300](https://www.heise.de/en/news/Microsoft-addresses-critical-security-vulnerability-in-Azure-environment-11169172.html)
- [SentinelOne - Azure Front Door EoP](https://www.sentinelone.com/vulnerability-database/cve-2026-24300/)
- [SecurityWeek - SAP Patches Critical Flaws](https://www.securityweek.com/sap-patches-critical-crm-s-4hana-netweaver-vulnerabilities/)
- [Cybersecurity News - SAP Patch Day](https://cybersecuritynews.com/sap-security-patch-day-feburary/)
- [GBHackers - SAP Code Injection](https://gbhackers.com/sap-security-patch-day-fixes-critical-code-injection-flaw/)
- [RedRays - SAP February 2026](https://redrays.io/blog/sap-security-patch-day-february-2026/)
- [The Hacker News - FortiClientEMS SQLi](https://thehackernews.com/2026/02/fortinet-patches-critical-sqli-flaw.html)
- [SOC Prime - CVE-2026-21643](https://socprime.com/blog/cve-2026-21643-vulnerability/)
- [Arctic Wolf - CVE-2026-21643](https://arcticwolf.com/resources/blog/cve-2026-21643/)
- [CSA Singapore - FortiClientEMS Advisory](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-013/)
- [The Hacker News - UNC1069 AI Crypto Campaign](https://thehackernews.com/2026/02/north-korea-linked-unc1069-uses-ai.html)
- [Dark Reading - UNC1069](https://www.darkreading.com/threat-intelligence/north-koreas-unc1069-hammers-crypto-firms)
- [BleepingComputer - NK macOS Malware](https://www.bleepingcomputer.com/news/security/north-korean-hackers-use-new-macos-malware-in-crypto-theft-attacks/)
- [CSO Online - ClickFix macOS Backdoors](https://www.csoonline.com/article/4130724/north-korean-actors-blend-clickfix-with-new-macos-backdoors-in-crypto-campaign.html)
- [The Record - NK ClickFix Crypto](https://therecord.media/north-korean-hackers-targeted-crypto-exec-clickfix)
- [Decrypt - Google AI NK Campaign Warning](https://decrypt.co/357601/google-warns-of-ai-powered-north-korean-malware-campaign-targeting-crypto-defi)
- [The Hacker News - APT36/SideCopy RAT Campaigns](https://thehackernews.com/2026/02/apt36-and-sidecopy-launch-cross.html)
- [SecurityWeek - Pakistan RAT Assault on India](https://www.securityweek.com/rats-in-the-machine-inside-a-pakistan-linked-three-pronged-cyber-assault-on-india/)
- [BleepingComputer - SSHStalker Botnet](https://www.bleepingcomputer.com/news/security/new-linux-botnet-sshstalker-uses-old-school-irc-for-c2-comms/)
- [The Hacker News - SSHStalker IRC C2](https://thehackernews.com/2026/02/sshstalker-botnet-uses-irc-c2-to.html)
- [SecurityWeek - SSHStalker](https://www.securityweek.com/new-sshstalker-linux-botnet-uses-old-techniques/)
- [SC Media - SSHStalker 7000 Systems](https://www.scworld.com/news/sshstalker-botnet-hijacks-7000-linux-systems-using-irc-and-ssh)
- [Krebs on Security - Kimwolf I2P](https://krebsonsecurity.com/2026/02/kimwolf-botnet-swamps-anonymity-network-i2p/)
- [GlobeNewsWire - Picus Red Report 2026](https://www.globenewswire.com/news-release/2026/02/10/3235422/0/en/Picus-Red-Report-2026-Finds-38-Drop-in-Ransomware-Attacks-as-Hackers-Choose-Silent-Residency-Over-Destruction.html)
- [The Hacker News - Digital Parasite](https://thehackernews.com/2026/02/from-ransomware-to-residency-inside.html)
- [eSecurity Planet - Picus Stealth Over Disruption](https://www.esecurityplanet.com/threats/picus-red-report-2026-shows-attackers-favor-stealth-over-disruption/)
- [TechCrunch - Conduent Update](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST - Record 50K+ CVEs Forecast 2026](https://www.infosecurity-magazine.com/news/first-forecasts-record-50000-cve)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 5-10, 2026 reports:

- Microsoft Patch Tuesday initial coverage (2 zero-days - now updated to 6 above)
- CVE-2026-20876 Windows VBS Enclave EoP / CVE-2026-20805 DWM info disclosure (initial zero-day count)
- CVE-2026-20854/20944/20952/20953/20955/20957 Microsoft critical RCEs
- CVE-2026-1731 BeyondTrust RS/PRA (CVSS 9.9, pre-auth RCE)
- CVE-2026-24858 Fortinet FortiCloud SSO (auth bypass)
- CVE-2026-24423 SmarterMail (ransomware exploitation)
- CVE-2026-22778 vLLM (RCE via video URL)
- CVE-2026-25049/21858/1470/0863 n8n (16 total vulns, 6 critical)
- CVE-2026-1281/1340 Ivanti EPMM zero-days (~100 victims)
- CVE-2025-40551 SolarWinds WHD
- CVE-2025-22224/22225/22226 VMware ESXi chain
- CVE-2026-21509 Microsoft Office zero-day / APT28 Operation Neusploit
- CVE-2026-20045 Cisco UCM/Webex zero-day
- CVE-2025-40602 SonicWall SMA1000 chained zero-day
- CVE-2025-55182 React2Shell NGINX hijacking
- Claude Desktop Extensions zero-click RCE (CVSS 10.0, Anthropic won't fix)
- DockerDash MCP context injection (patched Docker Desktop 4.50.0)
- UNC3886 Singapore telecoms / Salt Typhoon Norway / VoidLink malware
- TGR-STA-1030 Shadow Campaigns (37 countries)
- Signal account hijacking campaign (Germany/Europe)
- Google IPIDEA residential proxy disruption
- CISA BOD 26-02 edge device directive
- Warlock ransomware / SmarterTools breach
- Iron Mountain / Everest ransomware (limited impact)
- 0APT fake ransomware operation
- Evolve Mortgage 20TB / Conduent 25.9M / Panera 5.1M / Chat & Ask AI 300M
- Harvard/UPenn / Illinois DHS / Spain Ministry of Science breaches
- AT&T breach data resurface / Two BlackCat affiliate guilty pleas
- AI-powered law firm cloning campaign (150+ domains)

---

*Report generated: 2026-02-12*
*Next report: 2026-02-13*
*Classification: TLP:CLEAR*
