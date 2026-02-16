# Weekly Threat Intelligence Summary
**Week:** W07 (February 9 - February 15, 2026)
**Classification:** TLP:CLEAR
**Report ID:** CTI-WEEKLY-2026-W07

---

## Executive Summary

### Week at a Glance
| Metric | Count |
|--------|-------|
| Critical CVEs (CVSS 9+) | 15 |
| Zero-Days Patched/Disclosed | 10 |
| CISA KEV Additions | 11 |
| Active Exploits (ITW) | 11 |
| Ransomware Incidents | 5 |
| Data Breaches | 14 |
| Threat Actors Active | 8 |
| Vendor Advisories | 8 |

### Key Takeaways

1. **Microsoft Patch Tuesday dominates the week** - 59 CVEs including 6 actively exploited zero-days (revised from initial 2), all added to CISA KEV with March 3 deadline. The scale of active exploitation was significantly underreported on release day.

2. **China-nexus operations reach new scope** - UNC3886 targeted all 4 Singapore telecoms simultaneously (largest national cyber response in Singapore history), Salt Typhoon confirmed in Norway (first major European attribution), and Chinese hackers breached US Congressional committee email systems.

3. **Supply chain attacks proliferate across ecosystems** - Lazarus planted 192 malicious npm/PyPI packages via fake recruiter campaign, 300+ malicious Chrome extensions affected 37.4M users, and both Claude Desktop Extensions and Docker's AI assistant had critical MCP injection vulnerabilities.

4. **Apple's first zero-day of 2026** (CVE-2026-20700) exploited in "extremely sophisticated" targeted attacks, discovered by Google TAG, added to CISA KEV February 12. Exploit chain combines three separate vulnerabilities.

5. **Ransomware evolution accelerates** - 38% drop in encryption-based ransomware (Picus Red Report), 49% YoY increase overall (BlackFog). Attackers shifting to "silent residency" and pure data exfiltration. Physical phishing letters now target crypto wallet users.

---

## Top Vulnerabilities of the Week

### Tier 1: CISA KEV / Actively Exploited

| Rank | CVE ID | Product | CVSS | KEV Date | Days Reported |
|------|--------|---------|------|----------|---------------|
| 1 | CVE-2026-1731 | BeyondTrust RS/PRA | 9.9 | Feb 13 | Feb 14 |
| 2 | CVE-2024-43468 | Microsoft SCCM/ConfigMgr | 9.8 | Feb 12 | Feb 16 |
| 3 | CVE-2026-1281 | Ivanti EPMM | 9.8 | - | Feb 10, 16 |
| 4 | CVE-2026-1340 | Ivanti EPMM | 9.8 | - | Feb 10, 16 |
| 5 | CVE-2026-21510 | Windows Shell (SmartScreen) | 8.8 | Feb 10 | Feb 12 |
| 6 | CVE-2026-21513 | MSHTML Framework | 8.8 | Feb 10 | Feb 12 |
| 7 | CVE-2026-21533 | Remote Desktop Services | 8.8 | Feb 10 | Feb 12 |
| 8 | CVE-2026-21514 | Microsoft Word (OLE) | 7.8 | Feb 10 | Feb 12 |
| 9 | CVE-2026-21519 | Desktop Window Manager | 7.8 | Feb 10 | Feb 12 |
| 10 | CVE-2026-20700 | Apple iOS/macOS (dyld) | 7.8 | Feb 12 | Feb 16 |
| 11 | CVE-2026-21525 | Remote Access Connection Mgr | 6.5 | Feb 10 | Feb 12 |

### Tier 2: CVSS 9+ (Not Yet Exploited ITW)

| CVE ID | Product | CVSS | Patch Status |
|--------|---------|------|--------------|
| CVE-2026-21858 | n8n (Ni8mare) | 10.0 | Fixed in 1.123.17/2.5.2 - PoC public |
| Claude Desktop Extensions | Anthropic Claude DXT | 10.0 | Won't fix (by design) |
| CVE-2026-0488 | SAP CRM/S4HANA | 9.9 | SAP Note 3697099 |
| CVE-2026-1470 | n8n | 9.9 | Fixed in 1.123.17/2.5.2 |
| CVE-2026-24300 | Azure Front Door | 9.8 | Server-side fix (no action) |
| CVE-2026-25049 | n8n sandbox escape | 9.4 | Fixed in 1.123.17/2.5.2 |
| CVE-2026-21893 | n8n command injection | 9.4 | Fixed in 1.120.3 |
| CVE-2026-21643 | FortiClientEMS | 9.1 | Fixed in 7.4.5 |

### Tier 3: Notable (High Impact / Strategic)

| CVE ID | Product | CVSS | Significance |
|--------|---------|------|-------------|
| CVE-2026-21511 | Outlook (preview pane) | 7.5 | Zero-click adjacent |
| CVE-2025-15556 | Notepad++ | TBD | KEV Feb 12 |
| CVE-2025-40536 | SolarWinds WHD | TBD | KEV Feb 12 |
| DockerDash | Docker Ask Gordon AI | N/A | MCP injection (patched) |

### CISA KEV Activity This Week

**11 total additions across 3 dates:**

| Date | Count | CVEs |
|------|-------|------|
| Feb 10 | 6 | Microsoft Patch Tuesday zero-days (21510, 21513, 21514, 21519, 21525, 21533) |
| Feb 12 | 4 | SCCM (2024-43468), Apple (2026-20700), Notepad++ (2025-15556), SolarWinds (2025-40536) |
| Feb 13 | 1 | BeyondTrust RS/PRA (2026-1731) |

**Deadlines This Week:**
- CVE-2026-20045 Cisco UCM/Webex - **Passed Feb 11**
- CVE-2025-31125 Vite - **Passed Feb 12**
- CVE-2025-34026 Versa Concerto - **Passed Feb 12**
- CVE-2025-68645 Zimbra ZCS - **Passed Feb 12**
- CVE-2026-21509 Microsoft Office - **Due Feb 16 (end of week)**

---

## Exploits & Zero-Days Roundup

### Zero-Days Patched/Disclosed This Week

| CVE ID | Product | Disclosed | Vendor Patch | Exploited By |
|--------|---------|-----------|-------------|--------------|
| CVE-2026-21510 | Windows Shell | Feb 10 | Feb 10 PT | Unknown |
| CVE-2026-21513 | MSHTML | Feb 10 | Feb 10 PT | Unknown |
| CVE-2026-21514 | Microsoft Word | Feb 10 | Feb 10 PT | Unknown |
| CVE-2026-21519 | Desktop Window Manager | Feb 10 | Feb 10 PT | Unknown |
| CVE-2026-21525 | Remote Access CM | Feb 10 | Feb 10 PT | Unknown |
| CVE-2026-21533 | Remote Desktop Services | Feb 10 | Feb 10 PT | Unknown |
| CVE-2026-1281 | Ivanti EPMM | Jan 28 | Temp patches | Single actor (bulletproof hosting) |
| CVE-2026-1340 | Ivanti EPMM | Jan 28 | Temp patches | Single actor (bulletproof hosting) |
| CVE-2026-20700 | Apple dyld | Feb 11 | Feb 11 | Sophisticated targeted (nation-state suspected) |
| Claude DXT RCE | Anthropic Claude | Feb 10 | None (won't fix) | N/A |

### Exploitation Trends

**Ivanti EPMM Exploitation Deep Dive:**
- GreyNoise tracked 417 exploitation sessions from 8 IPs (Feb 1-9)
- **83%** of exploitation traced to a single IP: `193.24.123.42` on PROSPERO OOO bulletproof hosting (AS200593)
- Published IOC lists from other vendors miss the primary attacker
- "Sleeper" webshells discovered that **persist even after patching**
- Dominant payloads: reverse shells (port 443) and webshell deployment

**Microsoft SCCM (CVE-2024-43468) Delayed Exploitation:**
- Patched October 2024, PoC published November 2024
- Active exploitation detected February 2026 - 4 months after PoC availability
- Pattern: old CVEs with available PoCs see delayed mass exploitation

**Apple CVE-2026-20700 Exploit Chain:**
- Combined with CVE-2025-14174 and CVE-2025-43529 (previously patched)
- Apple describes attacks as "extremely sophisticated" targeting "specific individuals"
- Google TAG involvement suggests nation-state attribution

---

## Ransomware & Malware Activity

### Ransomware Incidents This Week

| Group | Victim | Impact | Date |
|-------|--------|--------|------|
| TridentLocker | Sedgwick Government Solutions | 3.4 GB stolen; serves DHS, ICE, CISA | Dec 31 (disclosed Feb 9-11) |
| Warlock | SmarterTools | ~12 Windows machines; vendor's own unpatched product | Disclosed Feb 10 |
| Unknown | BridgePay | 70,000 BTU customers offline payments disrupted | Feb 6 (ongoing through week) |
| Everest | Iron Mountain | Limited to marketing materials (inflated claims) | Disclosed Feb 10 |
| 0APT (fake) | 71 claimed orgs | Likely scam - empty leak files, no proof | Ongoing |

### Notable Malware Campaigns

**Lazarus Group "Graphalgo" Supply Chain Campaign:**
- **192 malicious npm/PyPI packages** via fake recruiter lures
- Targets cryptocurrency developers via LinkedIn, Facebook, Reddit
- Modular RAT with MetaMask detection for crypto theft
- Token-protected C2 blocks researcher analysis
- `bigmathutils` had 10,000+ downloads before trojanization
- *Reported: Feb 13-16*

**300+ Malicious Chrome Extensions:**
- 37.4 million users affected across three overlapping campaigns
- AiFrame: 30 AI-themed extensions (260K users) steal credentials via remote iframes
- Meta Business Suite stealer: TOTP codes, business manager data, contact lists
- ChatGPT/DeepSeek conversation theft: 900K+ installs, exfiltrate every 30 minutes
- *Reported: Feb 16*

**SSHStalker Botnet:**
- ~7,000 Linux systems compromised via SSH brute force
- IRC C2 with multi-server redundancy
- Exploits 16 distinct Linux kernel vulnerabilities (some from 2009)
- Go binary masquerades as nmap; downloads GCC to compile on-device
- *Reported: Feb 12*

**Kimwolf Botnet I2P Disruption:**
- 2M+ infected IoT devices attempted to join 700K bots as I2P nodes
- Sybil attack disrupted I2P anonymity network
- Goal: establish bulletproof C2 on anonymity networks
- *Reported: Feb 12*

**VoidLink Multi-Cloud Malware:**
- Linux-based framework persists across AWS, Azure, GCP, Alibaba, Tencent
- Container escape, kernel-level hiding, encrypted traffic mimicking normal web
- *Reported: Feb 10*

### Ransomware Trend Analysis

Two major reports published this week quantify the ransomware evolution:

**BlackFog State of Ransomware 2026:**
- **+49% year-over-year** increase in attacks
- **+30%** increase in active ransomware groups
- Most active groups: Qiling, Akira, Cl0p, Play, Safepay
- USA accounts for 58% of disclosed attacks

**Picus Red Report 2026 ("Digital Parasite"):**
- **-38% drop** in encryption-based ransomware
- 8 of top 10 MITRE ATT&CK techniques now stealth-focused
- Malware like LummaC2 uses trigonometry (mouse movement analysis) for sandbox evasion
- Attackers maintain "silent residency" for weeks/months before extortion

**Synthesis:** Ransomware is no longer synonymous with encryption. The business model has pivoted to silent data theft + extortion, rendering encryption-focused detection strategies increasingly obsolete.

### Physical Phishing - New Vector

Trezor/Ledger hardware wallet users receiving physical snail mail letters with:
- Official-looking letterhead impersonating security teams
- QR codes leading to phishing sites
- Recovery phrase entry to drain cryptocurrency wallets
- Deadline urgency tactics (e.g., "complete by February 15, 2026")
- Likely enabled by previous Trezor/Ledger data breaches exposing mailing addresses

---

## Threat Actor Intelligence

### APT/Nation-State Activity

| Actor | Attribution | Activity Summary | Target Sectors |
|-------|-------------|------------------|----------------|
| UNC3886 | China | Zero-day + rootkits across all 4 Singapore telecoms; 11-month containment | Telecommunications |
| Salt Typhoon | China | Confirmed in Norway (first European attribution); exploits edge devices | Telecoms, critical infrastructure |
| APT31/APT42/UNC2970 | China/Iran/DPRK | Systematic abuse of Google Gemini AI for recon, phishing, malware dev | Cross-sector |
| UNC1069 | North Korea | Deepfake Zoom + ClickFix; 7+ macOS malware families | Cryptocurrency/DeFi |
| Lazarus Group | North Korea | "Graphalgo" - 192 npm/PyPI packages via fake recruiter campaign | Cryptocurrency developers |
| APT36/SideCopy | Pakistan | Three parallel RAT campaigns (GETA, ARES, Desk) on Windows + Linux | Indian defense/government |
| ChainedShark (Actor240820) | Unattributed | Custom LinkedShell trojan targeting intl relations + marine research | Chinese academic/research |
| Chinese state actors | China | Breached US Congressional committee staff email systems | Government (US Congress) |

### Emerging TTPs

1. **AI-powered social engineering at scale** - Nation-state actors using Gemini for phishing, recon, and malware coding; 150+ AI-cloned law firm websites for recovery scams
2. **Deepfake video in targeted intrusions** - UNC1069 deployed AI-generated CEO deepfakes in live Zoom calls
3. **Physical phishing** - Snail mail letters with QR codes targeting crypto users (Trezor/Ledger)
4. **MCP/AI context injection** - Claude DXT and DockerDash show new attack surface where poisoned metadata triggers AI tool execution
5. **Sleeper webshells** - Ivanti EPMM attackers plant webshells that survive patching
6. **Bulletproof hosting concentration** - 83% of Ivanti exploitation from single PROSPERO OOO IP

---

## Data Breaches & Incidents

### Major Breaches (By Impact)

| Organization | Records/Impact | Data Type | Disclosure | Day |
|-------------|----------------|-----------|------------|-----|
| Conduent [UPDATE] | 25M+ (15.4M Texas alone) | SSN, medical, insurance | Ongoing | Feb 14 |
| Panera Bread | 5.1M records (760GB) | PII, email, phone, address | Feb 9 | Feb 9 |
| Illinois DHS | 700K individuals | Medicaid/Medicare data | Feb 9 | Feb 9 |
| Chat & Ask AI | 300M messages / 25M users | AI conversations | Feb 9 | Feb 9 |
| Evolve Mortgage | 20TB stolen | SSN, credit histories since 2016 | Feb 10 | Feb 10 |
| Japan Airlines | Unknown (July 2024 onward) | Names, phone, email, travel | Feb 14 | Feb 14 |
| IRS/DHS | 47,000 taxpayers | Address data improperly shared | Feb 16 | Feb 16 |
| Sedgwick/MCA | 3.4GB | Government contractor data | Feb 9, 16 | Feb 9, 16 |
| MedRevenu | Unknown | SSN, medical, financial | Feb 13 | Feb 13 |
| EyeCare Partners | Unknown (55 days access) | SSN, clinical data | Feb 13 | Feb 13 |
| Substack | Unknown | Phone, email, account data | Feb 14 | Feb 14 |
| Cottage Hospital | 1,600 | PII | Feb 13-14 | Feb 13-14 |
| Flickr | Unknown | Usernames, IPs, location | Feb 13 | Feb 13 |
| Spain Ministry of Science | Unknown | Personal records, emails | Feb 9 | Feb 9 |

### Breach Patterns This Week

**Healthcare sector continues to dominate:** MedRevenu, EyeCare Partners, Cottage Hospital, and Conduent (healthcare billing) all disclosed this week. Healthcare billing/claims processors are a particularly high-value supply chain target.

**Extended dwell times:** Japan Airlines (7 months), EyeCare Partners (55 days), Conduent (84 days). Average detection times remain dangerously long.

**Government data exposure:** IRS/DHS improper sharing (47K records), Sedgwick (government contractor), Illinois DHS (700K via misconfiguration), US Congressional email breach. Government data protection remains systemic.

**Vishing as primary vector:** ShinyHunters used vishing for both Panera (Microsoft Entra SSO) and Harvard/UPenn breaches, demonstrating voice phishing as a reliable method to bypass MFA.

---

## Vendor Advisory Highlights

### Microsoft
- **Patch Tuesday (Feb 10):** 59 CVEs, 6 actively exploited zero-days, 5 critical
- CVE-2026-21509 Office zero-day CISA deadline **Feb 16**
- 6 zero-day CISA deadline **March 3**
- CVE-2024-43468 SCCM (CVSS 9.8) now actively exploited; KEV deadline ~March 5
- CVE-2026-21511 Outlook preview pane spoofing - zero-click adjacent
- CVE-2026-24300 Azure Front Door (CVSS 9.8) - server-side fix

### Apple
- CVE-2026-20700 (CVSS 7.8) - first zero-day of 2026; patched in iOS 26.3, macOS Tahoe 26.3
- Older branches (iOS 18.x, macOS Sequoia/Sonoma) await backported patches
- Exploit chain with 2 previously patched CVEs

### SAP
- CVE-2026-0488 CRM/S4HANA code injection (CVSS 9.9) - any authenticated user can exploit
- Apply SAP Note 3697099

### Fortinet
- CVE-2026-21643 FortiClientEMS SQLi (CVSS 9.1) - only v7.4.4 affected; upgrade to 7.4.5
- CVE-2026-1731 BeyondTrust RS/PRA (CVSS 9.9) - now in CISA KEV

### Ivanti
- EPMM CVE-2026-1281/1340 - permanent fix expected Q1 2026 (v12.8.0.0)
- Hunt for sleeper webshells even after patching

### n8n
- 16 total vulnerabilities, 6 critical (including CVSS 10.0)
- Public exploits available for Ni8mare
- Canadian Cyber Centre advisory AL26-001
- Minimum safe: 1.123.17 or 2.5.2

### CISA
- 11 KEV additions this week (highest weekly total in Feb 2026)
- BOD 26-02 edge device directive continues enforcement
- FTC second ransomware report to Congress - 128K reports received

### Anthropic / Docker
- Claude Desktop Extensions zero-click RCE (CVSS 10.0) - Anthropic declines to fix
- DockerDash MCP injection - patched in Docker Desktop 4.50.0

---

## Weekly Trends & Analysis

### Attack Vector Trends

| Vector | Trend | Evidence |
|--------|-------|---------|
| Supply chain (npm/PyPI) | Rising | Lazarus Graphalgo (192 packages), Chrome extensions (300+) |
| AI/MCP injection | Emerging | Claude DXT, DockerDash, Gemini abuse |
| Vishing (voice phishing) | Rising | Panera/Harvard/UPenn (ShinyHunters), +442% in 2024 |
| Physical phishing | Novel | Trezor/Ledger snail mail letters |
| Edge device exploitation | Persistent | UNC3886, Salt Typhoon, Ivanti EPMM |
| Zero-day exploitation | Elevated | 10 zero-days this week across Microsoft, Apple, Ivanti |
| Credential-first attacks | Dominant | 79% of detections now malware-free (CrowdStrike) |

### Industry Targeting

| Sector | Incidents | Key Events |
|--------|-----------|------------|
| Government | 5+ | US Congress, IRS/DHS, Sedgwick/CISA, Illinois DHS, Singapore telecoms |
| Healthcare | 4 | MedRevenu, EyeCare Partners, Cottage Hospital, Conduent (billing) |
| Financial Services | 3+ | Evolve Mortgage (20TB), BridgePay ransomware, crypto targeting |
| Technology | 3+ | SmarterTools, n8n, Chrome extensions |
| Telecommunications | 2 | UNC3886 (Singapore 4 telecoms), Salt Typhoon (Norway) |
| Cryptocurrency | 3 | Lazarus Graphalgo, UNC1069 deepfake, Trezor/Ledger phishing |

### Geographic Patterns

- **China-nexus activity surging** - UNC3886 (Singapore), Salt Typhoon (Norway), Congressional emails (US), ChainedShark (China internal), Gemini abuse (global)
- **North Korea crypto focus intensifies** - UNC1069 deepfake campaign, Lazarus Graphalgo supply chain
- **Pakistan targeting India** - APT36/SideCopy three-pronged assault on defense sector
- **European expansion** - Salt Typhoon confirmed in Norway; Norway PST calls it "most serious since WWII"

### Emerging Concerns

1. **AI tool attack surface** - Claude DXT (CVSS 10.0, won't fix) and DockerDash demonstrate that AI assistants with tool execution capabilities create a fundamentally new class of vulnerabilities. MCP/tool-use security is immature.

2. **Post-patch persistence** - Ivanti EPMM "sleeper" webshells surviving patches shows that vulnerability patching alone is insufficient. Organizations must hunt for post-exploitation artifacts.

3. **Physical-digital convergence** - Trezor/Ledger phishing via postal mail represents threat actors bridging physical and digital attack vectors, leveraging previous digital breach data for physical targeting.

4. **Detection model obsolescence** - With 38% drop in encryption ransomware and 79% malware-free intrusions, organizations relying on signature-based or encryption-focused detection are increasingly blind.

5. **Supply chain attack industrialization** - Lazarus maintaining 192 packages and Chrome extensions at 37.4M user scale demonstrates supply chain attacks operating at industrial volume.

---

## Consolidated Recommendations

### Immediate Priority (This Weekend / Monday)

1. **Verify Microsoft Office CVE-2026-21509 patched** - CISA deadline was Feb 16 (Sunday); confirm deployment Monday morning
2. **Deploy Apple iOS 26.3 / macOS Tahoe 26.3** - CVE-2026-20700 actively exploited zero-day; now in CISA KEV
3. **Patch Microsoft SCCM CVE-2024-43468** - CVSS 9.8, actively exploited, in CISA KEV; verify October 2024 patch applied
4. **Ivanti EPMM webshell hunt** - If you patched CVE-2026-1281/1340, hunt for sleeper webshells that persist after patching; block IP `193.24.123.42` (PROSPERO OOO, AS200593)
5. **BeyondTrust RS/PRA** - CVE-2026-1731 (CVSS 9.9) now in CISA KEV; patch immediately if using Remote Support or Privileged Remote Access

### This Week

6. **Chrome extension audit** - Remove AI-themed extensions from unverified publishers; review all extensions against the 300+ identified malicious list
7. **npm/PyPI dependency audit** - Scan for Graphalgo-associated packages; check for `bigmathutils` and related trojanized packages
8. **SAP CRM/S4HANA** - Apply SAP Note 3697099 for CVE-2026-0488 (CVSS 9.9); any authenticated business user can exploit
9. **FortiClientEMS** - Upgrade v7.4.4 to v7.4.5 for CVE-2026-21643 (CVSS 9.1)
10. **n8n assessment** - 16 vulns, 6 critical, public exploits; upgrade to 1.123.17/2.5.2 or evaluate continued use
11. **Microsoft Patch Tuesday** - Deploy all February patches if not done; 6 zero-days with March 3 deadline
12. **Conduent monitoring** - Credit monitoring enrollment deadline March 31 if using Conduent services

### Strategic (30-Day)

13. **Shift detection strategy** - Invest in behavioral analytics, data exfiltration monitoring, and egress analysis; encryption-focused ransomware detection is increasingly ineffective
14. **AI tool governance** - Audit all AI assistants with MCP/tool access; restrict high-privilege extensions from ingesting untrusted external data (email, calendar)
15. **Supply chain security program** - Implement SCA for npm/PyPI dependencies; establish vetting for Chrome extensions; review third-party vendor security (Conduent, BridgePay, Sedgwick demonstrate cascading risk)
16. **Edge device hardening** - Align with CISA BOD 26-02; UNC3886 and Salt Typhoon both target routers, firewalls, VPN appliances as primary entry vectors
17. **Anti-vishing training** - ShinyHunters' vishing attacks bypass MFA; train help desks and IT staff on voice phishing impersonation tactics
18. **Healthcare sector preparedness** - 4 healthcare breaches this week; billing processors and claims administrators are high-value supply chain targets
19. **Post-patch hunting program** - Ivanti sleeper webshells demonstrate that patching alone is insufficient; establish post-patching verification procedures for critical vulnerabilities

---

## Report Sources

### Daily Reports Analyzed

| Date | Filename | Key Items |
|------|----------|-----------|
| Feb 9 | 2026-02-09-threat-intel-report.md | IPIDEA disruption, Congressional emails, Panera 5.1M, Chat & Ask AI 300M, n8n 16 vulns, Sedgwick/TridentLocker |
| Feb 10 | 2026-02-10-threat-intel-report.md | Microsoft Patch Tuesday (initial), UNC3886 Singapore, Salt Typhoon Norway, Claude DXT RCE, DockerDash, Evolve Mortgage 20TB, Ivanti EPMM ~100 victims |
| Feb 12 | 2026-02-12-threat-intel-report.md | Patch Tuesday revised (6 zero-days), CVE-2026-24300 Azure (9.8), CVE-2026-0488 SAP (9.9), CVE-2026-21643 Fortinet (9.1), UNC1069 deepfake, APT36/SideCopy, SSHStalker, Kimwolf, Picus Red Report |
| Feb 13 | 2026-02-13-threat-intel-report.md | Gemini AI nation-state abuse, ChainedShark APT, MedRevenu/EyeCare breaches, BridgePay ransomware, Flickr breach, BlackFog ransomware report |
| Feb 14 | 2026-02-14-threat-intel-report.md | BeyondTrust CVE-2026-1731 KEV, Japan Airlines breach, Substack breach, Conduent AG investigation |
| Feb 16 | 2026-02-16-threat-intel-report.md | CISA 4 KEV (Feb 12), Apple CVE-2026-20700 zero-day, SCCM exploitation, Lazarus Graphalgo, 300+ Chrome extensions, Trezor/Ledger phishing, IRS/DHS, Sedgwick update, Ivanti EPMM attribution |

### External Trend Sources

- [Bitdefender Threat Debrief February 2026](https://businessinsights.bitdefender.com/bitdefender-threat-debrief-february-2026)
- [WEF Global Cybersecurity Outlook 2026](https://www.weforum.org/publications/global-cybersecurity-outlook-2026/)
- [Boston Institute of Analytics - Weekly Cyber Security Feb 8-13](https://bostoninstituteofanalytics.org/blog/cyber-threat-intelligence-weekly-key-incidents-security-updates-8-13-feb-2026/)
- [The Cyber Express Weekly Roundup Feb 2026](https://thecyberexpress.com/weekly-roundup-cyber-express-feb-2026/)
- [Malwarebytes - Week in Security Feb 9-15](https://www.malwarebytes.com/blog/news/2026/02/a-week-in-security-february-9-february-15)
- [CISO Series - Feb 10 2026](https://cisoseries.com/cybersecurity-news-february-10-2026/)
- [Hipther Cybersecurity Roundup Feb 13](https://hipther.com/latest-news/2026/02/13/106906/)

---

## Appendix: Full CVE Reference

All CVEs mentioned this week, ranked by priority:

| CVE ID | Product | CVSS | KEV | Exploited | Day(s) |
|--------|---------|------|-----|-----------|--------|
| CVE-2026-21858 | n8n (Ni8mare) | 10.0 | No | PoC public | 9 |
| Claude DXT RCE | Anthropic Claude | 10.0 | No | N/A | 10 |
| CVE-2026-0488 | SAP CRM/S4HANA | 9.9 | No | No | 12 |
| CVE-2026-1731 | BeyondTrust RS/PRA | 9.9 | Feb 13 | Yes | 14 |
| CVE-2026-1470 | n8n | 9.9 | No | PoC public | 9 |
| CVE-2024-43468 | Microsoft SCCM | 9.8 | Feb 12 | Yes | 16 |
| CVE-2026-1281 | Ivanti EPMM | 9.8 | No | Yes | 10, 16 |
| CVE-2026-1340 | Ivanti EPMM | 9.8 | No | Yes | 10, 16 |
| CVE-2026-24300 | Azure Front Door | 9.8 | No | No | 12 |
| CVE-2026-25049 | n8n sandbox escape | 9.4 | No | PoC public | 9 |
| CVE-2026-21893 | n8n command injection | 9.4 | No | No | 9 |
| CVE-2026-21643 | FortiClientEMS | 9.1 | No | No | 12 |
| CVE-2026-21510 | Windows Shell | 8.8 | Feb 10 | Yes (0-day) | 12 |
| CVE-2026-21513 | MSHTML | 8.8 | Feb 10 | Yes (0-day) | 12 |
| CVE-2026-21533 | Remote Desktop Services | 8.8 | Feb 10 | Yes (0-day) | 12 |
| CVE-2026-25051 | n8n XSS | 8.5 | No | No | 9 |
| CVE-2026-21514 | Microsoft Word | 7.8 | Feb 10 | Yes (0-day) | 12 |
| CVE-2026-21519 | Desktop Window Manager | 7.8 | Feb 10 | Yes (0-day) | 12 |
| CVE-2026-20700 | Apple dyld | 7.8 | Feb 12 | Yes (0-day) | 16 |
| CVE-2026-21511 | Outlook (preview) | 7.5 | No | No | 12 |
| CVE-2026-21525 | Remote Access CM | 6.5 | Feb 10 | Yes (0-day) | 12 |
| CVE-2025-15556 | Notepad++ | TBD | Feb 12 | Yes | 16 |
| CVE-2025-40536 | SolarWinds WHD | TBD | Feb 12 | Yes | 16 |
| CVE-2026-20876 | Windows VBS Enclave | Critical | No | Yes (0-day) | 10 |
| CVE-2026-20805 | DWM Info Disclosure | High | No | Yes (0-day) | 10 |
| CVE-2026-21877 | n8n Auth RCE | Critical | No | No | 9 |
| CVE-2026-21509 | Microsoft Office | High | Yes | Yes (0-day) | 10, 14, 16 |
| DockerDash | Docker Ask Gordon | N/A | No | PoC | 10 |

---

*Weekly summary generated: 2026-02-16*
*Consolidating 6 daily reports from 2026-02-09 to 2026-02-16*
*Classification: TLP:CLEAR*
