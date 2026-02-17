# Cyber Threat Intelligence Report
**Date:** February 16, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0216

---

## Executive Summary

- **NEW**: CISA added 4 more KEVs on February 12 including Apple zero-day CVE-2026-20700 and Microsoft SCCM CVE-2024-43468 (CVSS 9.8) - now actively exploited
- **NEW**: Apple patches first zero-day of 2026 (CVE-2026-20700) - dyld memory corruption exploited in "extremely sophisticated" targeted attacks; Google TAG discovery
- **NEW**: Lazarus Group "Graphalgo" supply chain campaign plants 192 malicious packages across npm/PyPI targeting cryptocurrency developers via fake recruiter lures
- **NEW**: 300+ malicious Chrome extensions discovered stealing data from 37.4 million users; 30 AI-themed extensions (AiFrame campaign) target 260,000 users
- **NEW**: Sedgwick/Managed Care Advisors breach via TridentLocker ransomware - government contractor serving DHS, ICE, and CISA; notifications started February 11
- **NEW**: Physical phishing letters impersonating Trezor and Ledger target hardware wallet users via snail mail with QR codes to steal recovery phrases
- **NEW**: IRS improperly disclosed 47,000 immigrant taxpayer records to DHS despite federal court order blocking the practice
- **NEW**: Google Chrome zero-day CVE-2026-2441 (use-after-free in CSS, CVSS 8.8) - actively exploited in the wild; patch to Chrome 145.0.7632.75/76 immediately
- **NEW**: Figure Technology Solutions (fintech/HELOC lender) discloses data breach after employee phishing attack
- **NEW**: Odido (telecoms) discloses breach exposing millions of customer records including sensitive identifiers
- **NEW**: South Korea fines Louis Vuitton, Christian Dior, Tiffany ~$25M combined for cloud SaaS failures exposing 5.5 million customers
- **DEADLINE TODAY**: Microsoft Office CVE-2026-21509 CISA KEV deadline is **February 16** - patch immediately
- **UPDATE**: 83% of Ivanti EPMM exploitation traced to single IP on PROSPERO bulletproof hosting; "sleeper" webshells persist after patching

---

## CISA KEV Updates

### February 12 Additions (4 CVEs) - NOT IN PREVIOUS REPORTS

CISA added four new vulnerabilities to the KEV catalog on February 12, 2026:

| CVE | Product | CVSS | Type | Deadline |
|-----|---------|------|------|----------|
| CVE-2024-43468 | Microsoft Configuration Manager (SCCM) | 9.8 | SQL Injection - RCE | ~March 5 |
| CVE-2026-20700 | Apple iOS/macOS/watchOS/tvOS/visionOS (dyld) | 7.8 | Buffer Overflow - Code Execution | ~March 5 |
| CVE-2025-15556 | Notepad++ | TBD | Download Without Integrity Check | ~March 5 |
| CVE-2025-40536 | SolarWinds Web Help Desk | TBD | Security Control Bypass | ~March 5 |

**Sources:** [CISA Adds Four KEV - Feb 12](https://www.cisa.gov/news-events/alerts/2026/02/12/cisa-adds-four-known-exploited-vulnerabilities-catalog)

### Deadline Tracker

| CVE | Product | Deadline | Status |
|-----|---------|----------|--------|
| CVE-2026-21509 | Microsoft Office | **Feb 16 (TODAY)** | **DEADLINE TODAY** |
| CVE-2019-19006 | FreePBX | Feb 24 | 8 days |
| CVE-2025-64328 | Sangoma | Feb 24 | 8 days |
| CVE-2021-39935 | GitLab CE/EE | Feb 24 | 8 days |
| CVE-2026-24423 | SmarterMail | Feb 26 | 10 days |
| CVE-2025-11953 | React Native CLI | Feb 26 | 10 days |
| CVE-2026-21510/21513/21514/21519/21525/21533 | Microsoft (6 zero-days) | March 3 | 15 days |
| CVE-2024-43468 | Microsoft SCCM | ~March 5 | ~17 days |
| CVE-2026-20700 | Apple (dyld) | ~March 5 | ~17 days |
| CVE-2026-1731 | BeyondTrust RS/PRA | ~March 6 | ~18 days |

---

## Critical Vulnerabilities

### NEW: CVE-2026-2441 - Google Chrome Zero-Day (Use-After-Free in CSS)

**CVE:** CVE-2026-2441
**CVSS:** 8.8 (High)
**Type:** Use-after-free in CSS processing
**Product:** Google Chrome
**Patched:** February 16, 2026
**Reported by:** Shaheen Fazim (February 11, 2026)
**Status:** Actively exploited in the wild

**Impact:** Remote attacker can execute arbitrary code inside a sandbox via a crafted HTML page. Visiting a malicious website is sufficient to trigger exploitation.

**Affected Versions:** Chrome prior to 145.0.7632.75/76 (Windows/Mac) or 144.0.7559.75 (Linux)

**Action Required:** Update Chrome immediately. In Chrome settings: Help > About Google Chrome > auto-update or force restart.

**Significance:** Google's first zero-day of 2026. Active exploitation confirmed. Chrome's large install base (~3.5B users) makes this a high-priority patch.

**Sources:** [Help Net Security - CVE-2026-2441](https://www.helpnetsecurity.com/2026/02/16/google-patches-chrome-vulnerability-with-in-the-wild-exploit-cve-2026-2441/), [Qualys ThreatPROTECT](https://threatprotect.qualys.com/2026/02/16/google-patches-its-first-zero-day-vulnerability-of-the-year-cve-2026-2441/)

---

### NEW: CVE-2026-20700 - Apple Zero-Day Exploited in "Extremely Sophisticated" Attacks

**CVE:** CVE-2026-20700
**CVSS:** 7.8
**Type:** Memory corruption in dyld (Dynamic Link Editor)
**Disclosed:** February 11, 2026
**Discovered by:** Google Threat Analysis Group (TAG)
**Status:** Actively exploited, now in CISA KEV

**Impact:** Attackers with memory write capability can execute arbitrary code on affected devices. Apple described the attacks as "extremely sophisticated" targeting "specific targeted individuals" on iOS versions before iOS 26.

**Affected Products & Patches:**
- iOS 26.3 / iPadOS 26.3
- macOS Tahoe 26.3
- watchOS 26.3
- tvOS 26.3
- visionOS 26.3
- **Older branches (iOS 18.7.5, macOS Sequoia 15.7.4, macOS Sonoma 14.8.4) - waiting for backports**

**Exploit Chaining:** Apple confirmed CVE-2026-20700 was exploited alongside two previously patched flaws (CVE-2025-14174 and CVE-2025-43529), suggesting a multi-stage exploit chain.

**Significance:** First actively exploited Apple zero-day of 2026. Google TAG discovery and "extremely sophisticated" language suggests nation-state involvement. The exploit chain combining three vulnerabilities indicates a well-resourced threat actor.

**Sources:** [Help Net Security](https://www.helpnetsecurity.com/2026/02/12/apple-zero-day-fixed-cve-2026-20700/), [CyberScoop](https://cyberscoop.com/apple-zero-day-vulnerability-cve-2026-20700/), [The Hacker News](https://thehackernews.com/2026/02/apple-fixes-exploited-zero-day.html), [SecurityWeek](https://www.securityweek.com/apple-patches-ios-zero-day-exploited-in-extremely-sophisticated-attack/), [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/apple-patches-zero-day-flaw-that-could-let-attackers-take-control-of-devices), [SOC Prime](https://socprime.com/blog/cve-2026-20700-vulnerability/), [Qualys](https://threatprotect.qualys.com/2026/02/12/apple-ios-zero-day-vulnerability-exploited-in-attacks-cve-2026-20700/)

---

### NEW: CVE-2024-43468 - Microsoft SCCM/ConfigMgr SQLi Now Actively Exploited (CVSS 9.8)

**CVE:** CVE-2024-43468
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N)
**Type:** SQL Injection - Remote Code Execution
**Product:** Microsoft Configuration Manager (SCCM/ConfigMgr)
**Patched:** October 2024 (original release)
**Added to KEV:** February 12, 2026
**Deadline:** March 5, 2026

**Impact:** Remote attackers with no privileges can execute arbitrary commands with the highest level of privileges on the server and underlying database. SCCM is widely used for endpoint management across enterprise environments.

**Exploitation Timeline:**
- October 2024: Microsoft patches the vulnerability
- November 2024: Synacktiv publishes proof-of-concept exploitation code
- February 2026: CISA confirms active exploitation in the wild

**Why This Matters:** SCCM manages software deployments and configurations across thousands of endpoints. Compromising SCCM gives attackers a pivot point to push malicious payloads to every managed device in an organization.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-microsoft-configmgr-rce-flaw-as-exploited-in-attacks/), [Cybersecurity News](https://cybersecuritynews.com/microsoft-configuration-manager-sql-injection-vulnerability/)

---

## Exploits & Zero-Days

### UPDATE: Ivanti EPMM - 83% of Exploits From Single Bulletproof Hosting IP

**Previous Coverage:** February 10 report (initial disclosure, ~100 victims)

**What's New:**
- GreyNoise recorded **417 exploitation sessions** from 8 unique IPs between February 1-9
- **83% (346 sessions)** traced to a single IP: `193.24.123.42`
- IP belongs to **PROSPERO OOO (AS200593)** - a known bulletproof hosting provider
- Published IOC lists from other vendors point to different IPs, missing the primary attacker
- Researchers discovered **"sleeper" webshells** that persist even after patching CVE-2026-1281/1340

**Action Required:** Organizations that patched Ivanti EPMM should hunt for webshells that may have been planted before patching. Simply applying the patch is insufficient.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/one-threat-actor-responsible-for-83-percent-of-recent-ivanti-rce-attacks/), [The Hacker News](https://thehackernews.com/2026/02/83-of-ivanti-epmm-exploits-linked-to.html), [GreyNoise](https://www.greynoise.io/blog/active-ivanti-exploitation), [Help Net Security](https://www.helpnetsecurity.com/2026/02/11/ivanti-epmm-sleeper-webshell/)

---

## Threat Actors

### NEW: Lazarus Group "Graphalgo" - 192 Malicious npm/PyPI Packages

**Threat Actor:** Lazarus Group (North Korea)
**Campaign Name:** Graphalgo
**Active Since:** May 2025
**Disclosed:** February 11-13, 2026
**Target:** Cryptocurrency developers

**Attack Chain:**
1. Attackers approach targets via LinkedIn, Facebook, or Reddit job ads posing as recruiters
2. Victims directed to GitHub repositories with "coding challenges"
3. Challenges contain dependencies on malicious npm/PyPI packages
4. Packages deploy a modular RAT (JavaScript, Python, or VBScript variants)

**Malware Capabilities:**
- Arbitrary command execution
- File upload/download
- Process listing
- **MetaMask browser extension detection** (cryptocurrency theft)
- Token-protected C2 communication (blocks researcher analysis)

**Scale:** 192 malicious packages identified. Notable example: `bigmathutils` npm package accumulated 10,000+ legitimate downloads before malicious version 1.1.0 was pushed.

**Attribution:** Token-based C2 authentication mechanism matches patterns from other known North Korean campaigns.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/lazarus-campaign-plants-malicious.html), [BleepingComputer](https://www.bleepingcomputer.com/news/security/fake-job-recruiters-hide-malware-in-developer-coding-challenges/), [Cybersecurity News](https://cybersecuritynews.com/lazarus-groups-graphalgo-fake-recruiter-campaign/), [Security Affairs](https://securityaffairs.com/188009/apt/malicious-npm-and-pypi-packages-llinked-to-lazarus-apt-fake-recruiter-campaign.html), [SC Media](https://www.scworld.com/brief/lazarus-group-exploits-npm-and-pypi-with-fake-recruitment-campaign)

---

## Malware & Supply Chain

### NEW: 300+ Malicious Chrome Extensions - 37.4 Million Users Affected

**Disclosed:** February 2026 (multiple researchers)
**Scale:** 300+ extensions, 37.4 million users total

**Three Overlapping Campaigns:**

| Campaign | Extensions | Users | Target |
|----------|-----------|-------|--------|
| AiFrame (LayerX) | 30 AI-themed extensions | 260,000+ | Credentials, browsing data |
| Mass data leakage | 287 extensions | 27.2M (confirmed history leak) | Browser history, search results |
| Meta Business Suite stealer | 1 extension (CL Suite) | Unknown | Meta/Facebook business data, TOTP codes |

**AiFrame Campaign Details:**
- 30 extensions posing as AI assistants (summarization, writing, Gmail)
- No actual AI functionality - render full-screen iframe loading remote content
- Operators can change behavior without Chrome Web Store review
- Steal credentials from 260,000+ users

**ChatGPT/DeepSeek Conversation Theft:**
- Two malicious extensions across 900,000+ installs
- Exfiltrate ChatGPT and DeepSeek conversation content
- Transmit all Chrome tab URLs to remote server every 30 minutes

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html), [SecurityWeek](https://www.securityweek.com/over-300-malicious-chrome-extensions-caught-leaking-or-stealing-user-data/), [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/how-to-find-and-remove-credential-stealing-chrome-extensions), [TechWorm](https://www.techworm.net/2026/02/ai-chrome-extensions-expose-data-of-300000-users.html)

---

### NEW: Trezor/Ledger Physical Phishing Letters (Snail Mail)

**Disclosed:** February 14-15, 2026
**Target:** Cryptocurrency hardware wallet users
**Vector:** Physical postal mail with printed letterhead

**How It Works:**
1. Victims receive official-looking letters claiming to be from Trezor or Ledger security teams
2. Letters warn of mandatory "Authentication Check" or "Transaction Check"
3. Urgency created with deadlines (e.g., "complete by February 15, 2026")
4. QR codes direct to phishing sites mimicking official setup pages
5. Victims enter wallet recovery phrases
6. Attackers import wallets and drain all funds

**Connection to Previous Breaches:** Both Trezor and Ledger have suffered data breaches in recent years exposing customer mailing addresses, which likely supplies the targeting data for this campaign.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/snail-mail-letters-target-trezor-and-ledger-users-in-crypto-theft-attacks/), [CryptoTimes](https://www.cryptotimes.io/2026/02/16/ledger-and-trezor-users-are-being-tricked-into-giving-away-millions/), [CoinSpectator](https://coinspectator.com/cryptonews/2026/02/15/crypto-hackers-target-trezor-and-ledger-users-in-theft-campaign/)

---

## Data Breaches

### NEW: Sedgwick/Managed Care Advisors - Government Contractor Breach

**Victim:** Sedgwick Government Solutions / Managed Care Advisors (subsidiary of Sedgwick)
**Attacker:** TridentLocker ransomware (RaaS, emerged November 2025)
**Incident Date:** December 31, 2025
**Notification Date:** February 11, 2026
**Data Stolen:** 3.4 GB

**Government Clients Served:**
- Department of Homeland Security (DHS)
- Immigration and Customs Enforcement (ICE)
- Customs and Border Protection (CBP)
- Citizenship and Immigration Services (USCIS)
- Department of Labor
- **Cybersecurity and Infrastructure Security Agency (CISA)**

**Containment:** Sedgwick states the Government Solutions subsidiary is segmented from the rest of the business, with no wider Sedgwick systems affected. The attack targeted an isolated file transfer system.

**About TridentLocker:** New RaaS operation since November 2025 using standard double-extortion tactics. Previously attacked Belgian postal service bpost.

**Sources:** [The Record](https://therecord.media/sedgwick-cyber-incident-ransomware), [SecurityWeek](https://www.securityweek.com/sedgwick-confirms-cyberattack-on-government-subsidiary/), [Security Affairs](https://securityaffairs.com/186525/data-breach/sedgwick-discloses-data-breach-after-tridentlocker-ransomware-attack.html), [ClassAction.org](https://www.classaction.org/data-breach-lawsuits/managed-care-advisors-sedgwick-government-solutions-february-2026)

---

### NEW: Figure Technology Solutions - Fintech Data Breach via Phishing

**Victim:** Figure Technology Solutions (blockchain-based HELOC/lending platform)
**Incident:** Employee phishing attack leading to unauthorized data access
**Disclosed:** February 16, 2026
**Data Exposed:** Customer data (specific fields not yet confirmed)

**Significance:** Blockchain fintech platforms hold sensitive financial data including mortgage/lending records. Phishing remains the leading initial access vector even at technology-forward companies.

**Sources:** [Digital Forensics Magazine - Feb 16 Roundup](https://digitalforensicsmagazine.com/news-roundup-16th-february-2026/)

---

### NEW: Odido - Millions of Customer Records Exposed

**Victim:** Odido (European/Netherlands-based telecommunications provider)
**Type:** Unauthorized access to customer-contact system
**Disclosed:** February 16, 2026
**Data Exposed:** Personal data for millions of customers including sensitive identifiers

**Significance:** Major telecom breach; customer contact system access often includes names, addresses, phone numbers, account details - high value for social engineering campaigns.

**Sources:** [Digital Forensics Magazine - Feb 16 Roundup](https://digitalforensicsmagazine.com/news-roundup-16th-february-2026/)

---

### NEW: South Korea Fines Luxury Brands ~$25M Over Cloud SaaS Security Failures

**Regulator:** South Korea Personal Information Protection Commission (PIPC)
**Fined Entities:** Louis Vuitton Korea, Christian Dior Couture Korea, Tiffany Korea
**Fine Amount:** KRW 36.033 billion (~US$25 million combined)
**Disclosed:** February 16, 2026

**What Happened:** Cloud-based customer management SaaS platform lacked basic security controls, enabling breaches that exposed data for more than 5.5 million customers across all three brands.

**Significance:** Demonstrates regulatory enforcement against third-party SaaS security failures. Organizations cannot outsource accountability for customer data protection to SaaS vendors.

**Sources:** [Digital Forensics Magazine - Feb 16 Roundup](https://digitalforensicsmagazine.com/news-roundup-16th-february-2026/)

---

### NEW: IRS Improperly Shares 47,000 Taxpayer Records with DHS

**Disclosed:** February 11, 2026 (Washington Post)
**Type:** Improper government data sharing (not a hack)
**Impact:** ~47,000 taxpayers - address data improperly disclosed

**What Happened:**
- April 2025: Treasury Secretary Bessent and DHS Secretary Noem sign data-sharing agreement
- ICE requested information on **1.28 million individuals**
- IRS verified ~47,000 names against tax records
- IRS improperly disclosed additional **confidential address information** for <5% of those 47,000
- A federal court had **already blocked** IRS from sharing data with DHS in November 2025

**Policy Impact:** The deal broke a longstanding IRS policy encouraging undocumented immigrants to file taxes with assurance their data would be protected. This breach of trust may reduce future tax compliance.

**Sources:** [Washington Post](https://www.washingtonpost.com/business/2026/02/11/immigrants-irs-dhs-tax-data/), [US News](https://www.usnews.com/news/top-news/articles/2026-02-11/irs-improperly-disclosed-confidential-immigrant-tax-data-to-dhs-washington-post-reports), [Accounting Today](https://www.accountingtoday.com/news/irs-improperly-shared-taxpayer-data-with-dhs)

---

## Regulatory & Government

### NEW: FTC Second Ransomware Report to Congress

**Published:** February 2026
**Mandate:** RANSOMWARE Act

**Key Findings:**
- **128,000 reports** of ransomware and malware-based attacks received between July 2023 - July 2025
- Ransomware accounts for <3% of all fraud complaints
- FTC has had "limited interactions" with Russian and Chinese counterparts
- **No interactions at all** with Iran or North Korea on ransomware enforcement
- International cooperation on ransomware remains essentially non-existent

**Sources:** [FTC Press Release](https://www.ftc.gov/news-events/news/press-releases/2026/02/ftc-issues-second-report-congress-its-work-fight-ransomware-other-cyberattacks), [GCN](https://gcn.com/u-s-ftc-briefs-congress-cross-border-ransomware/18847), [Cybersecurity Dive](https://www.cybersecuritydive.com/news/ftc-ransomware-scams-fraud-report/811705/)

---

## Vendor Advisories

### Google Chrome
- **CVE-2026-2441** - First Chrome zero-day of 2026; use-after-free in CSS; update to 145.0.7632.75/76 (Win/Mac) or 144.0.7559.75 (Linux) immediately

### Apple
- **CVE-2026-20700** - First zero-day of 2026; patch to iOS 26.3 / macOS Tahoe 26.3 immediately
- Exploit chain with CVE-2025-14174 and CVE-2025-43529
- Older OS branches (iOS 18.x, macOS Sequoia/Sonoma) await backported patches

### Microsoft
- **CVE-2026-21509** Office zero-day - CISA deadline **TODAY (February 16)**
- **CVE-2024-43468** SCCM/ConfigMgr SQLi (CVSS 9.8) - now actively exploited, in KEV since Feb 12
- Six February Patch Tuesday zero-days - CISA deadline March 3

### CISA
- 4 new KEV additions February 12 (SCCM, Apple, Notepad++, SolarWinds WHD)
- Total February KEV additions: 11 (Feb 3: 4, Feb 10: 6, Feb 12: 4, Feb 13: 1)

### Ivanti
- EPMM CVE-2026-1281/1340 - hunt for sleeper webshells even after patching
- 83% of exploitation from single bulletproof hosting IP

---

## Recommended Actions

### Immediate Priority (Today)

1. **Google Chrome CVE-2026-2441** - Actively exploited zero-day; update Chrome to 145.0.7632.75/76 (Win/Mac) or 144.0.7559.75 (Linux) NOW
2. **Microsoft Office CVE-2026-21509** - CISA deadline is **TODAY**; verify February out-of-band patch deployed across all Office/M365 instances
3. **Apple CVE-2026-20700** - Update all Apple devices to iOS 26.3 / macOS Tahoe 26.3; this is an actively exploited zero-day in CISA KEV
4. **Microsoft SCCM CVE-2024-43468** - If running Configuration Manager, verify the October 2024 patch is applied; active exploitation confirmed

### High Priority (This Week)

4. **Chrome extension audit** - Review installed extensions across your organization; remove any AI-themed extensions not from verified publishers; check for the 300+ identified malicious extensions
5. **npm/PyPI supply chain** - If your development teams use npm or PyPI, scan for the 192 Graphalgo-associated packages; audit dependencies of recently added packages
6. **Ivanti EPMM webshell hunt** - If you patched CVE-2026-1281/1340, hunt for sleeper webshells that may persist; patching alone is insufficient
7. **Sedgwick/MCA notification** - If your organization uses Sedgwick Government Solutions, verify breach notification received and monitor for data misuse

### Threat Hunting

8. **Lazarus fake recruiter indicators** - Alert development teams about LinkedIn/Reddit job scam patterns; monitor for bigmathutils and related npm packages
9. **Bulletproof hosting IOCs** - Block traffic to PROSPERO OOO (AS200593), particularly IP `193.24.123.42` (Ivanti EPMM exploitation)
10. **MetaMask targeting** - Cryptocurrency organizations should audit for unauthorized MetaMask extension access and review endpoint security

### Awareness

11. **Hardware wallet phishing** - Alert cryptocurrency holders about physical phishing letters impersonating Trezor/Ledger; no legitimate company asks for recovery phrases
12. **AI extension risk** - Educate users that AI-themed browser extensions are a primary attack vector; many render remote iframes with no local AI functionality

---

## Sources

- [CISA Adds Four KEV - February 12, 2026](https://www.cisa.gov/news-events/alerts/2026/02/12/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [Help Net Security - Apple Zero-Day CVE-2026-20700](https://www.helpnetsecurity.com/2026/02/12/apple-zero-day-fixed-cve-2026-20700/)
- [CyberScoop - Apple Zero-Day](https://cyberscoop.com/apple-zero-day-vulnerability-cve-2026-20700/)
- [The Hacker News - Apple Zero-Day Fix](https://thehackernews.com/2026/02/apple-fixes-exploited-zero-day.html)
- [SecurityWeek - Apple Extremely Sophisticated Attack](https://www.securityweek.com/apple-patches-ios-zero-day-exploited-in-extremely-sophisticated-attack/)
- [Malwarebytes - Apple Zero-Day](https://www.malwarebytes.com/blog/news/2026/02/apple-patches-zero-day-flaw-that-could-let-attackers-take-control-of-devices)
- [SOC Prime - CVE-2026-20700](https://socprime.com/blog/cve-2026-20700-vulnerability/)
- [Qualys - Apple iOS Zero-Day](https://threatprotect.qualys.com/2026/02/12/apple-ios-zero-day-vulnerability-exploited-in-attacks-cve-2026-20700/)
- [BleepingComputer - Microsoft SCCM KEV](https://www.bleepingcomputer.com/news/security/cisa-flags-microsoft-configmgr-rce-flaw-as-exploited-in-attacks/)
- [Cybersecurity News - SCCM SQLi](https://cybersecuritynews.com/microsoft-configuration-manager-sql-injection-vulnerability/)
- [The Hacker News - Lazarus Graphalgo](https://thehackernews.com/2026/02/lazarus-campaign-plants-malicious.html)
- [BleepingComputer - Fake Recruiters Malware](https://www.bleepingcomputer.com/news/security/fake-job-recruiters-hide-malware-in-developer-coding-challenges/)
- [Cybersecurity News - Lazarus Graphalgo Campaign](https://cybersecuritynews.com/lazarus-groups-graphalgo-fake-recruiter-campaign/)
- [Security Affairs - Lazarus npm PyPI](https://securityaffairs.com/188009/apt/malicious-npm-and-pypi-packages-llinked-to-lazarus-apt-fake-recruiter-campaign.html)
- [SC Media - Lazarus npm PyPI](https://www.scworld.com/brief/lazarus-group-exploits-npm-and-pypi-with-fake-recruitment-campaign)
- [The Hacker News - Malicious Chrome Extensions](https://thehackernews.com/2026/02/malicious-chrome-extensions-caught.html)
- [SecurityWeek - 300+ Chrome Extensions](https://www.securityweek.com/over-300-malicious-chrome-extensions-caught-leaking-or-stealing-user-data/)
- [Malwarebytes - Chrome Extension Removal](https://www.malwarebytes.com/blog/news/2026/02/how-to-find-and-remove-credential-stealing-chrome-extensions)
- [TechWorm - AI Chrome Extensions](https://www.techworm.net/2026/02/ai-chrome-extensions-expose-data-of-300000-users.html)
- [BleepingComputer - Trezor Ledger Phishing Letters](https://www.bleepingcomputer.com/news/security/snail-mail-letters-target-trezor-and-ledger-users-in-crypto-theft-attacks/)
- [CryptoTimes - Ledger Trezor Scam](https://www.cryptotimes.io/2026/02/16/ledger-and-trezor-users-are-being-tricked-into-giving-away-millions/)
- [The Record - Sedgwick Ransomware](https://therecord.media/sedgwick-cyber-incident-ransomware)
- [SecurityWeek - Sedgwick Cyberattack](https://www.securityweek.com/sedgwick-confirms-cyberattack-on-government-subsidiary/)
- [Security Affairs - Sedgwick TridentLocker](https://securityaffairs.com/186525/data-breach/sedgwick-discloses-data-breach-after-tridentlocker-ransomware-attack.html)
- [ClassAction.org - Sedgwick Breach](https://www.classaction.org/data-breach-lawsuits/managed-care-advisors-sedgwick-government-solutions-february-2026)
- [Washington Post - IRS DHS Data Sharing](https://www.washingtonpost.com/business/2026/02/11/immigrants-irs-dhs-tax-data/)
- [US News - IRS Taxpayer Data](https://www.usnews.com/news/top-news/articles/2026-02-11/irs-improperly-disclosed-confidential-immigrant-tax-data-to-dhs-washington-post-reports)
- [Accounting Today - IRS Data Sharing](https://www.accountingtoday.com/news/irs-improperly-shared-taxpayer-data-with-dhs)
- [FTC - Second Ransomware Report](https://www.ftc.gov/news-events/news/press-releases/2026/02/ftc-issues-second-report-congress-its-work-fight-ransomware-other-cyberattacks)
- [GCN - FTC Congress Report](https://gcn.com/u-s-ftc-briefs-congress-cross-border-ransomware/18847)
- [BleepingComputer - Ivanti Single Threat Actor](https://www.bleepingcomputer.com/news/security/one-threat-actor-responsible-for-83-percent-of-recent-ivanti-rce-attacks/)
- [The Hacker News - Ivanti EPMM Bulletproof Hosting](https://thehackernews.com/2026/02/83-of-ivanti-epmm-exploits-linked-to.html)
- [GreyNoise - Active Ivanti Exploitation](https://www.greynoise.io/blog/active-ivanti-exploitation)
- [Help Net Security - Ivanti Sleeper Webshells](https://www.helpnetsecurity.com/2026/02/11/ivanti-epmm-sleeper-webshell/)
- [Malwarebytes - Week in Security Feb 9-15](https://www.malwarebytes.com/blog/news/2026/02/a-week-in-security-february-9-february-15)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Help Net Security - Chrome Zero-Day CVE-2026-2441](https://www.helpnetsecurity.com/2026/02/16/google-patches-chrome-vulnerability-with-in-the-wild-exploit-cve-2026-2441/)
- [Qualys ThreatPROTECT - Chrome CVE-2026-2441](https://threatprotect.qualys.com/2026/02/16/google-patches-its-first-zero-day-vulnerability-of-the-year-cve-2026-2441/)
- [Digital Forensics Magazine - Feb 16 News Roundup](https://digitalforensicsmagazine.com/news-roundup-16th-february-2026/)
- [Kordon - Cybersecurity News Week Summary Feb 16](https://kordon.app/latest-interesting-cybersecurity-news-of-the-week-summarised-16-02-2026/)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 10-14, 2026 reports and remain relevant context:

### Vulnerabilities
- Microsoft February 2026 Patch Tuesday (59 CVEs, 6 zero-days, 5 critical)
- CVE-2026-21510/21513/21514/21519/21525/21533 Microsoft zero-days
- CVE-2026-21511 Outlook preview pane spoofing
- CVE-2026-24300 Azure Front Door EoP (CVSS 9.8)
- CVE-2026-0488 SAP CRM/S4HANA code injection (CVSS 9.9)
- CVE-2026-21643 FortiClientEMS SQLi (CVSS 9.1)
- CVE-2026-1731 BeyondTrust RS/PRA (CVSS 9.9, pre-auth RCE, KEV Feb 13)
- Claude Desktop Extensions zero-click RCE (CVSS 10.0)
- DockerDash MCP injection

### Threat Actors
- Google Gemini AI abuse by APT31, APT42, UNC2970, Russian actors
- ChainedShark APT (Actor240820) targeting Chinese research institutions
- UNC3886 Singapore telecoms Operation Cyber Guardian
- UNC1069 North Korea deepfake Zoom + ClickFix crypto campaign
- APT36/SideCopy three-pronged RAT assault on Indian defense
- Salt Typhoon Norway operations

### Malware & Ransomware
- SSHStalker botnet (7,000 Linux systems, IRC C2)
- Kimwolf botnet I2P disruption
- VoidLink multi-cloud Linux malware
- BridgePay ransomware - Bryan Texas Utilities (70,000 customers)
- Picus Red Report 2026 (38% drop in encryption ransomware)
- BlackFog State of Ransomware 2026 (+49% YoY)
- Warlock ransomware vs SmarterTools
- Iron Mountain / Everest limited breach
- 0APT fake ransomware operation

### Breaches
- Conduent 25M+ (Texas AG investigation, Volvo Group 17K)
- Japan Airlines (customer data since July 2024)
- Substack (user phone numbers, emails)
- MedRevenu healthcare billing
- EyeCare Partners 55+ day email access
- Cottage Hospital (1,600 affected)
- Flickr third-party provider
- Evolve Mortgage Services 20TB
- Harvard/UPenn ShinyHunters

---

*Report generated: 2026-02-16*
*Next report: 2026-02-17*
*Classification: TLP:CLEAR*
