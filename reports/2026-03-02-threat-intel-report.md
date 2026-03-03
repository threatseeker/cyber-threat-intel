# Cyber Threat Intelligence Report
**Date:** March 2, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0302

---

## Executive Summary

- **[UPDATE] APT28 linked to MSHTML zero-day (CVE-2026-21513)**: Akamai published detailed analysis confirming Russia's APT28 exploited the MSHTML security bypass via malicious LNK files before Microsoft's February patch - targets government and defense sectors
- **Android March 2026 Security Update**: Google patches 129 vulnerabilities including actively exploited Qualcomm zero-day (CVE-2026-21385) and critical CVSS 9.8 RCE (CVE-2026-0006) - update all Android devices immediately
- **Odido Dutch telecom breach - full data leaked**: ShinyHunters published 6.5M customer records plus 600K business accounts on March 1 after Odido refused ransom - includes passports, IDs, and diplomat residence permits
- **Canadian Tire breach hits 38M accounts**: October 2025 breach disclosed via Have I Been Pwned Feb 25 - names, emails, phones, addresses, partial credit card data, PBKDF2 password hashes exposed
- **Operation Epic Fury triggers Iran cyber escalation**: Following US-Israel strikes on Feb 28, Iran launches "The Great Epic" cyber campaign targeting ICS/SCADA in Israel, Jordan fuel infrastructure, and Gulf states
- **Scattered Lapsus$ Hunters (SLH) resurface**: Unified Scattered Spider/ShinyHunters/Lapsus$ collective claims 60M+ breached records in March 2026, including SoundCloud, Betterment, Crunchbase, Lacoste, and Adidas
- **CVE-2026-3422 (U-Office Force)**: Critical CVSS 9.8 insecure deserialization enabling unauthenticated RCE - no patch available yet

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2026-0006 | Android (System component) | 9.8 | Heap Buffer Overflow RCE | Patched in March 2026 Android update |
| CVE-2026-21385 | Qualcomm Display (Android) | High | Zero-Day (Actively Exploited) | Patched in March 2026 Android update |
| CVE-2026-3422 | U-Office Force | 9.8 | Insecure Deserialization RCE | **No patch available** |
| CVE-2026-0047 | Android Framework | Critical | Privilege Escalation | Patched in March 2026 Android update |
| CVE-2025-48631 | Android System | Critical | Denial of Service | Patched in March 2026 Android update |

### Android March 2026 Security Update - 129 Vulnerabilities

Google released the March 2026 Android Security Bulletin patching **129 vulnerabilities** across Framework, System, Kernel, and vendor components.

**CVE-2026-0006 - Critical RCE (CVSS 9.8)**
Heap buffer overflow in Android System component. Out of bounds read and write allows remote code execution with no additional privileges or user interaction required. Network-exploitable without authentication.

**CVE-2026-21385 - Qualcomm Display Zero-Day (Actively Exploited)**
High-severity zero-day in Qualcomm's Display component confirmed by Google as actively exploited in targeted attacks. Additional critical bugs include CVE-2026-0047 (Framework privilege escalation), CVE-2025-48631 (System DoS), and seven Kernel privilege escalation flaws.

**Remediation:** Apply March 2026 Android security patches. Prioritize devices running Qualcomm chipsets due to active exploitation of CVE-2026-21385.

### CVE-2026-3422 - U-Office Force Insecure Deserialization (CVSS 9.8)

Critical deserialization of untrusted data vulnerability in e-Excellence U-Office Force. Unauthenticated remote attackers can craft malicious serialized objects to achieve arbitrary code execution. No user interaction required, network-exploitable, low attack complexity.

**Remediation:** No patch available. Monitor TWCERT/CC advisories. Restrict network access to U-Office Force instances; implement WAF rules to inspect serialized payloads.

---

## Exploits & Zero-Days

### [UPDATE] APT28 Confirmed Behind CVE-2026-21513 MSHTML Zero-Day

Akamai published a detailed analysis on March 2, 2026 confirming that Russia's APT28 (Fancy Bear/Forest Blizzard) exploited CVE-2026-21513 before Microsoft's February 2026 Patch Tuesday fix.

**Technical Details:**
- **CVSS:** 8.8 (High)
- **Root cause:** Insufficient URL validation in `ieframe.dll` hyperlink navigation allows attacker-controlled input to reach ShellExecuteExW code paths
- **Exploit chain:** Specially crafted LNK file embeds HTML immediately after the LNK structure, using nested iframes and multiple DOM contexts to manipulate trust boundaries
- **Bypasses:** Mark-of-the-Web (MotW) and Internet Explorer Enhanced Security Configuration (IE ESC)
- **C2 domain:** `wellnesscaremed[.]com` (attributed to APT28)
- **Discovery:** Malicious artifact uploaded to VirusTotal on January 30, 2026
- **Targets:** Government and defense organizations

**Remediation:** Ensure February 2026 Patch Tuesday updates are applied. Hunt for IoCs including the C2 domain `wellnesscaremed[.]com` and LNK files with embedded HTML content. Block LNK file delivery via email gateways.

### [UPDATE] VMware ESXi VM Escape Toolkit - Huntress Deep Dive

Huntress published an in-depth technical analysis of the Chinese-origin ESXi VM escape toolkit exploiting CVE-2025-22224 (CVSS 9.3), CVE-2025-22225, and CVE-2025-22226.

**Key findings:**
- **Orchestrator "MAESTRO"** manages the full VM escape chain: disables VMCI drivers, loads unsigned exploit driver via BYOD, leaks VMX memory to bypass ASLR, abuses HGFS and VMCI flaws, writes shellcode into VMX process, escapes to ESXi kernel
- **Chinese-language development paths** including folder "All version escape - delivery" confirm attribution to Chinese-speaking threat actors
- **Toolkit developed as early as February 2024** - over a year before Broadcom's March 2025 disclosure
- **Initial access** via compromised SonicWall VPN appliances
- **30,000+ internet-exposed ESXi instances** remain potentially vulnerable

**Remediation:** Patch ESXi to latest versions. Audit for MAESTRO indicators. Review SonicWall VPN access logs.

---

## Malware & Ransomware

### Scattered Lapsus$ Hunters (SLH) - Major Resurgence

The unified cybercrime collective formed by Scattered Spider, ShinyHunters, and Lapsus$ has dramatically escalated operations in early March 2026.

**March 2026 claimed victims (partial list):**

| Victim | Sector | Attack Date |
|--------|--------|-------------|
| SoundCloud | Technology | March 2026 |
| Betterment | Financial Services | March 2026 |
| Crunchbase | Technology | March 2026 |
| MatchGroup | Technology | March 2026 |
| Lacoste | Consumer/Retail | March 1, 2026 |
| Adidas | Consumer/Retail | March 1, 2026 |
| Eiffage | Construction | March 1, 2026 |

**TTPs:**
- **Brand new real-time AiTM phishing kit** targeting Okta, Microsoft Entra ID, and Google SSO accounts
- **Brokered access model** - selling initial access to other threat groups
- **60M+ breached records** claimed across March 2026 operations
- Aggressive recruitment on Telegram via "scattered lapsu$ hunters - The Com HQ" channel

**Remediation:** Deploy phishing-resistant MFA (FIDO2/WebAuthn). Monitor for SLH AiTM indicators. Review SSO authentication logs for anomalous token replay patterns.

### Qilin Ransomware Claims Malaysia Airlines

On February 26-27, 2026, the Qilin ransomware group listed Malaysia Airlines on its dark web leak site. Malaysia Airlines has not officially confirmed the breach. Qilin has claimed 1,000+ victims in 2025 and 200+ additional victims in early 2026.

**Status:** Unconfirmed. No data samples published. Monitor for developments.

---

## Threat Actors

### Iran - "The Great Epic" Cyber Campaign (Post-Operation Epic Fury)

Following the February 28, 2026 US-Israel joint military strikes (Operation Epic Fury/Roaring Lion), Iran has launched a coordinated multi-vector cyber retaliation campaign.

**Current situation:**
- Iran's internet connectivity dropped to 1-4%, hindering state-run APT operations in the near term
- However, **proxy and diaspora threat actors** are executing the "Great Epic" campaign outside Iran's borders
- **Handala Hacker Group** (pro-Iranian) claimed shutdown of gas stations across Jordan via ICS/SCADA targeting
- **Cardinal** (pro-Russian hacktivist, state-aligned) claimed targeting of Israel Defense Forces systems
- **Tarnished Scorpius** (INC Ransomware, RaaS) listed Israeli industrial machinery company on leak site
- **BadeSaba prayer app** (5M+ downloads) was hacked to broadcast anti-regime messages during opening strikes
- State news sites (IRNA) hijacked to display anti-government messages

**Assessment:** Iran's conventional military response is severely degraded, making cyber operations a primary retaliation vector. Expect escalation against:
- ICS/SCADA in Israel, Jordan, Gulf states
- US critical infrastructure (pre-positioned access)
- Financial systems and government networks

**Remediation:** Organizations in affected sectors should activate heightened monitoring, review ICS/OT network segmentation, and implement CISA Iran-related threat advisories.

### APT28 (Russia) - MSHTML Zero-Day Campaign

See Exploits & Zero-Days section above for full details on APT28's exploitation of CVE-2026-21513.

---

## Data Breaches

### Odido (Dutch Telecom) - 6.5M Customers - Full Data Leaked

**Timeline:**
- **February 7, 2026:** Breach occurs via multi-stage social engineering against customer service employees
- **February 13, 2026:** Odido publicly discloses breach; initially reports 6.2M affected
- **February 2026:** ShinyHunters demands 1M EUR ransom (later reduced to 500K EUR)
- **February 2026:** Odido refuses to pay, stating it "will not allow itself to be blackmailed"
- **March 1, 2026:** ShinyHunters publishes full dataset to dark web

**Scale:** 6.5M individuals + 600K businesses

**Data exposed:**
- Names, addresses, email addresses, phone numbers
- Bank account numbers
- 5M+ identification documents (passports, driver's licenses)
- Diplomat and high-profile administrator residence permits
- Account numbers and customer IDs

**Attack method:** ShinyHunters used phishing to steal customer service employee passwords, then called those same employees impersonating Odido IT to trick them into approving MFA prompts. This allowed 48 hours of undetected Salesforce database scraping.

**Impact:** Largest telecom breach in Dutch history. Identity theft risk is extreme given passport/ID document exposure.

### Canadian Tire - 38.3M Accounts

**Breach date:** October 2, 2025 | **Public disclosure:** February 25, 2026 (via Have I Been Pwned)

**Affected brands:** Canadian Tire, SportChek, Mark's/L'Equipeur, Party City

**Data exposed:**
- 38,306,562 unique email addresses
- Names, phone numbers, physical addresses
- PBKDF2 password hashes
- Subset: dates of birth, partial credit card data (card type, expiry, masked number)

**Not compromised:** Bank account information, loyalty program data

**Remediation:** Users should change passwords on affected accounts and any accounts using the same credentials.

### [UPDATE] Conduent - 25M+ Victims

No new developments since March 1 report. Credit monitoring enrollment deadline remains **March 31, 2026**. Class action litigation ongoing with 10+ lawsuits filed.

---

## Vendor Advisories

### Google - Android March 2026 Security Bulletin (March 2, 2026)
- **129 vulnerabilities patched** across Framework, System, Kernel, Qualcomm, MediaTek, and Arm components
- **1 actively exploited zero-day** (CVE-2026-21385, Qualcomm Display)
- **1 critical RCE** (CVE-2026-0006, System component, CVSS 9.8)
- Patch levels: 2026-03-01 and 2026-03-05
- **Action:** Apply immediately; prioritize Qualcomm devices

### TWCERT/CC - U-Office Force Advisory (March 2, 2026)
- CVE-2026-3422: Critical insecure deserialization (CVSS 9.8)
- **No patch available** - monitor for vendor updates

### Akamai - MSHTML Zero-Day Analysis (March 2, 2026)
- Published detailed technical analysis of CVE-2026-21513 exploitation by APT28
- Includes IoCs, exploit chain breakdown, and detection guidance
- **Action:** Review IoCs against network telemetry

### Huntress - ESXi VM Escape Report (March 2, 2026)
- Deep technical analysis of Chinese MAESTRO toolkit exploiting ESXi zero-days
- Includes full exploit chain documentation and indicators
- **Action:** Verify ESXi patching, hunt for MAESTRO artifacts

---

## Recommended Actions

### Immediate (24-48 hours)

1. **Apply Android March 2026 security updates** - actively exploited Qualcomm zero-day (CVE-2026-21385) and critical CVSS 9.8 RCE (CVE-2026-0006) demand immediate patching
2. **Hunt for APT28 MSHTML IoCs** - search for C2 domain `wellnesscaremed[.]com`, suspicious LNK files with embedded HTML, anomalous ShellExecuteExW invocations
3. **Restrict access to U-Office Force instances** (CVE-2026-3422, CVSS 9.8) - no patch available; apply WAF rules and network segmentation
4. **Activate Iran threat monitoring** - organizations in energy, utilities, defense, and government sectors should implement CISA Iran advisories and review ICS/OT segmentation

### Short-Term (This week)

5. **Deploy phishing-resistant MFA** (FIDO2/WebAuthn) to counter Scattered Lapsus$ Hunters' AiTM phishing kit targeting Okta, Entra, and Google SSO
6. **Verify ESXi patching** against CVE-2025-22224/22225/22226; hunt for MAESTRO orchestrator artifacts if running VMware infrastructure
7. **Notify affected Canadian Tire customers** and enforce password resets for any shared credentials
8. **Review ShinyHunters TTPs** for telecom and retail organizations - MFA fatigue attacks and social engineering of helpdesk staff remain primary vectors

### Strategic

9. **Re-evaluate Iran threat posture** - with conventional military options degraded, Iran's cyber program becomes the primary retaliation vector; expect increased ICS/SCADA targeting in allied nations
10. **Track SLH collective evolution** - the merger of Scattered Spider, ShinyHunters, and Lapsus$ with a brokered-access model represents a new organizational threat paradigm for identity-based attacks
11. **Prepare for March Patch Tuesday** (March 10, 2026) - given the volume of actively exploited vulnerabilities, ensure rapid deployment capability

---

## Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds Two KEV (Feb 25, 2026)](https://www.cisa.gov/news-events/alerts/2026/02/25/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [APT28 Tied to CVE-2026-21513 MSHTML 0-Day - The Hacker News](https://thehackernews.com/2026/03/apt28-tied-to-cve-2026-21513-mshtml-0.html)
- [APT28 MSHTML Zero-Day - Security Affairs](https://securityaffairs.com/188782/security/russia-linked-apt28-exploited-mshtml-zero-day-cve-2026-21513-before-patch.html)
- [Inside the Fix: CVE-2026-21513 Analysis - Akamai](https://www.akamai.com/blog/security-research/inside-the-fix-cve-2026-21513-mshtml-exploit-analysis)
- [MSHTML Zero-Day Exploited by APT28 - GBHackers](https://gbhackers.com/mshtml-zero-day-in-windows-exploited-by-apt28/)
- [Google Confirms CVE-2026-21385 Qualcomm Zero-Day - The Hacker News](https://thehackernews.com/2026/03/google-confirms-cve-2026-21385-in.html)
- [Android Security Update March 2026 - VPNCentral](https://vpncentral.com/android-security-update-march-2026-patches-129-vulnerabilities-including-actively-exploited-zero-day-cve-2026-21385/)
- [CVE-2026-0006 Critical RCE - TheHackerWire](https://www.thehackerwire.com/cve-2026-0006-critical-rce-via-heap-buffer-overflow/)
- [U-Office Force CVE-2026-3422 - TheHackerWire](https://www.thehackerwire.com/u-office-force-critical-rce-via-insecure-deserialization-cve-2026-3422/)
- [CVE-2026-3422 - TWCERT/CC](https://www.twcert.org.tw/en/cp-139-10743-9a952-2.html)
- [CVE-2026-2441 Chrome Zero-Day - Orca Security](https://orca.security/resources/blog/cve-2026-2441-chrome-chromium-zero-day-vulnerability/)
- [ESXi VM Escape Exploitation - Huntress](https://www.huntress.com/blog/esxi-vm-escape-exploit)
- [Chinese ESXi Zero-Day Exploitation - The Register](https://www.theregister.com/2026/01/09/china_esxi_zerodays/)
- [Odido Data Breach Full Leak - NL Times](https://nltimes.nl/2026/03/01/hackers-publish-full-cache-stolen-odido-customer-data-ransom-refusal)
- [Odido Breach Impacts Millions - Infosecurity Magazine](https://www.infosecurity-magazine.com/news/odido-breach-millions-dutch-telco/)
- [Odido Breach - TechCrunch](https://techcrunch.com/2026/02/13/dutch-phone-giant-odido-says-millions-of-customers-affected-by-data-breach/)
- [Odido 6.5M Customers Leaked - Techzine](https://www.techzine.eu/news/security/139178/all-data-from-dutch-telco-odido-65m-customers-leaked-online/)
- [Odido & Ben Data Breach Overview - UpGuard](https://www.upguard.com/news/odido-nl-data-breach-2026-03-02)
- [Odido Hackers Leak Data - Cybernews](https://cybernews.com/cybercrime/odido-hackers-leak-remaining-customer-data-of-6-5m-people-and-600000-companies/)
- [Canadian Tire Breach 38M Accounts - SecurityWeek](https://www.securityweek.com/canadian-tire-data-breach-impacts-38-million-accounts/)
- [Canadian Tire - Have I Been Pwned](https://haveibeenpwned.com/Breach/CanadianTire)
- [Canadian Tire Breach - CyberInsider](https://cyberinsider.com/canadian-tire-data-breach-impacted-over-38-million-people/)
- [Iran Cyberattacks 2026 Threat Brief - Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [US-Israel Iran Cyberattack Exchange - SecurityWeek](https://www.securityweek.com/us-israel-and-iran-trade-cyberattacks-pro-west-hacks-cause-disruption-as-tehran-retaliates/)
- [Iran Conflict Blackout and Cyberattacks - Cybernews](https://cybernews.com/editorial/iran-us-conflict-blackout-cyberattacks-misinformation/)
- [Iran Cyber Escalation - SC Media](https://www.scworld.com/news/iran-cyberattacks-likely-in-expanding-conflict-experts-say)
- [Israel-Iran Cyber Escalation - Euronews](https://www.euronews.com/next/2026/03/02/the-digital-battleground-how-cyber-attacks-will-shape-the-israel-iran-conflict)
- [Scattered Lapsus$ Hunters Alliance - Infosecurity Magazine](https://www.infosecurity-magazine.com/news/scattered-spider-shinyhunters/)
- [SLH Resurgence - CYFIRMA](https://www.cyfirma.com/research/resurgence-of-scattered-lapsus-hunters/)
- [SLH Brokered Access Model - Industrial Cyber](https://industrialcyber.co/ransomware/scattered-lapsus-resurfaces-with-brokered-access-model-raising-risks-for-industrial-and-critical-infrastructure/)
- [SLH Anatomy - LevelBlue](https://www.levelblue.com/blogs/spiderlabs-blog/scattered-lapsuss-hunters-anatomy-of-a-federated-cybercriminal-brand)
- [Lapsus$ Ransomware Victim Lacoste - RedPacket Security](https://www.redpacketsecurity.com/lapsus-ransomware-victim-lacoste/)
- [Malaysia Airlines Qilin Claim - Cybernews](https://cybernews.com/news/malaysian-airlines-qilin-ransomware-attack-claim/)
- [Ransomware Trends 2026 - BlackFog](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [Ransomware Without Encryption - Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [BlackCat Affiliates Guilty Plea - SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [Top Ransomware Attacks 2026 - SharkStriker](https://sharkstriker.com/blog/top-10-ransomware-attack-of-2026/)
- [Top Data Breaches February 2026 - Security Boulevard](https://securityboulevard.com/2026/03/top-data-breaches-of-february-2026/)
- [Data Breaches Digest March 2026](https://www.dbdigest.com/2026/03/)
- [Cyber Threats 2026 - World Economic Forum](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
