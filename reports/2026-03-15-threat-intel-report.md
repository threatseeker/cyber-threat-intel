# Cyber Threat Intelligence Report
**Date:** 2026-03-15
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0315-v2

---

## Executive Summary

- **CRITICAL:** CVE-2026-0625 (CVSS 9.3) - Zero-day command injection actively exploited in end-of-life D-Link DSL gateway routers; no patch available, replace immediately
- **CRITICAL:** Two new n8n vulnerabilities CVE-2026-21858 and CVE-2026-21877 (CVSS 10.0) disclosed - affects ~100,000 self-hosted servers globally; distinct from previously reported CVE-2025-68613
- **CRITICAL:** Cisco Secure FMC CVE-2026-20079 and CVE-2026-20131 (CVSS 10.0) - patch released March 4
- **HIGH [NEW]:** Operation Lightning - international law enforcement dismantles SocksEscort proxy botnet (369,000 compromised routers across 163 countries); $3.5M in crypto seized
- **HIGH [NEW]:** GlassWorm supply chain escalation - 72 malicious Open VSX extensions and 151+ poisoned GitHub repositories discovered (March 3-9); invisible Unicode payloads steal credentials
- **HIGH [NEW]:** AMOS Stealer campaigns impersonating Claude Code and other AI tools to distribute macOS infostealer; fake documentation sites bypass anti-phishing filters
- **HIGH:** CVE-2026-21385 - Qualcomm display component memory corruption zero-day actively exploited in the wild; affects 234 chipsets; patched in Android March 2026 security bulletin
- **HIGH:** Microsoft Patch Tuesday March 2026 (79 flaws) - includes CVE-2026-26144 (Excel/Copilot zero-click data exfil), Office RCE via Preview Pane (CVE-2026-26110, CVE-2026-26113), Windows Kernel UAF EoP, Authenticator MitM
- **HIGH:** Seedworm (MuddyWater/MOIS) confirmed active on U.S. bank, airport, software company, and NGO networks since February 2026
- **HIGH [NEW]:** Salt Typhoon - FBI confirms threat "still very much ongoing"; at least 200 organizations targeted worldwide; Mandiant hired by AT&T and Verizon but security assessment reports withheld from Congress
- **MEDIUM [NEW]:** Starbucks data breach - 889 employees' SSNs, DOBs, and financial account info exposed via spoofed Partner Central login pages (Jan 19 - Feb 11); disclosed March 12
- **MEDIUM [NEW]:** OSI Systems data breach - 4,910 individuals affected; INC RANSOM claimed 250GB exfiltrated; disclosed March 11
- **MEDIUM:** Belgian hospital AZ Monica hit by ransomware - IT shut down, patient transfers initiated, paper-based emergency operations
- **MEDIUM:** TELUS (Canadian telecom) investigating active cybersecurity breach; McKinsey internal AI platform (Lilli) breached by autonomous AI agent in under 2 hours

---

## Critical Vulnerabilities

### CISA KEV - No New Additions Since March 13, 2026
> All KEV additions through March 13 were reported in CTI-2026-0314. No new KEV additions confirmed as of March 15.

### New Critical/High CVEs

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-0625 | D-Link DSL Gateways (EoL) | Command Injection (RCE, no auth) | 9.3 | Actively exploited, no patch |
| CVE-2026-21858 | n8n Workflow Automation | RCE | 10.0 | New disclosure, ~100k servers |
| CVE-2026-21877 | n8n Workflow Automation | RCE | 10.0 | New disclosure |
| CVE-2026-20079 | Cisco Secure FMC | Critical (unspecified) | 10.0 | Patch available March 4 |
| CVE-2026-20131 | Cisco Secure FMC | Critical (unspecified) | 10.0 | Patch available March 4 |
| CVE-2026-21385 | Qualcomm Display Component (Android) | Memory Corruption | High | Actively exploited, patch in Android March bulletin |
| CVE-2026-26144 | Microsoft Excel / Copilot | Zero-click Info Disclosure via Copilot | High | Patched Patch Tuesday March 10 |
| CVE-2026-26110 | Microsoft Office | RCE via Preview Pane | Critical | Patched March 10 |
| CVE-2026-26113 | Microsoft Office | RCE via Preview Pane | Critical | Patched March 10 |
| CVE-2026-26132 | Windows Kernel | Use-After-Free EoP (SYSTEM) | High | Patched March 10 |
| CVE-2026-24289 | Windows Kernel | Use-After-Free EoP (SYSTEM) | High | Patched March 10 |
| CVE-2026-26128 | Windows SMB Server | EoP (improper auth) | Important | Patched March 10 |
| CVE-2026-26123 | Microsoft Authenticator (Android/iOS) | MitM credential intercept | Important | Patched March 10 |
| CVE-2026-21262 | Microsoft SQL Server | EoP to SQLAdmin/sysadmin | CVSS 8.8 | Patched March 10 |
| CVE-2026-0628 | Google Gemini in Chrome | EoP | CVSS 8.8 | Patched in Android March bulletin |

---

## Exploits & Zero-Days

### CVE-2026-0625 - D-Link End-of-Life Router Zero-Day (Active Exploitation)
Attackers are actively exploiting a command injection flaw in multiple discontinued D-Link DSL gateway devices. The vulnerability resides in the `dnscfg.cgi` endpoint (DNS server settings handler) due to missing input validation, allowing unauthenticated remote code execution. D-Link will not release a patch - the affected devices are 5+ years past end-of-support. **Recommendation:** Replace immediately. No mitigation exists short of network isolation or device replacement.

### CVE-2026-21858 / CVE-2026-21877 - n8n Perfect-Score RCE (New, Distinct from CVE-2025-68613)
Two additional n8n vulnerabilities with CVSS 10.0 were disclosed this week, separate from CVE-2025-68613 (already in CISA KEV). Researchers estimate approximately 100,000 globally exposed self-hosted n8n instances. Any organization running self-hosted n8n must treat this as an immediate patching priority. All three n8n CVEs now require remediation.

### CVE-2026-21385 - Qualcomm Zero-Day in 234 Chipsets (Actively Exploited)
A memory corruption vulnerability in a Qualcomm open-source display driver component affects 234 Qualcomm chipsets. Google's March 2026 Android security bulletin includes a patch; Qualcomm notified OEM partners in February. Targeted exploitation has been confirmed - likely used in surveillance or targeted intrusion campaigns. Apply Android March security update immediately.

### CVE-2026-26144 - Microsoft Excel / Copilot Zero-Click Data Exfiltration
Microsoft flagged this as particularly novel: successful exploitation causes Copilot Agent mode to exfiltrate data via unintended network egress. Zero-click attack vector - no user interaction required. Represents an emerging class of AI-assisted data exfiltration vulnerabilities. Patch via March 2026 Patch Tuesday.

---

## Supply Chain & Developer Threats [NEW SECTION]

### GlassWorm Campaign Escalation - Open VSX, GitHub, npm Poisoning
The GlassWorm supply chain campaign has significantly escalated since January 2026. Researchers discovered:

- **72 additional malicious Open VSX extensions** (since Jan 31, 2026) mimicking popular developer tools including linters, formatters, and AI coding assistants like Claude Code
- **151+ GitHub repositories** poisoned between March 3-9, 2026, with invisible Unicode characters encoding malicious payloads
- Campaign has expanded across **npm, VS Code Marketplace, and Open VSX** simultaneously
- Attack uses **Remote Dynamic Dependencies (RDD)** in package.json to fetch payloads from attacker-controlled HTTP URLs, enabling on-the-fly modification and inspection bypass
- Decoded Unicode payloads deploy loaders that steal tokens, credentials, and secrets

**Recommendation:** Audit all recently installed VS Code/Open VSX extensions. Verify extension publisher authenticity. Implement extension allowlisting in managed developer environments.

### AMOS Stealer Impersonating AI Developer Tools
Active campaigns distributing the Atomic macOS Stealer (AMOS) through fake AI application downloads:

- Fake "Claude Code" download pages built on Squarespace bypass anti-phishing filters
- macOS victims receive curl-based installer that deploys AMOS spyware
- Windows variants deploy Amatera infostealer via mshta.exe
- Campaign also abuses malicious OpenClaw Skills to target AI agent users
- CYFIRMA identified a separate campaign using `Clearl_AI.dmg` disk image as delivery mechanism

**Recommendation:** Only download developer tools from official vendor sources. Verify download URLs against official documentation. Alert development teams to this specific campaign.

---

## Malware & Ransomware

### AZ Monica (Belgian Hospital Network) - Ransomware, March 2026
Belgian hospital network AZ Monica suffered a ransomware attack requiring full proactive IT shutdown. Electronic medical records went offline, scheduled procedures were cancelled, critical patients were transferred to other facilities, and emergency departments operated at reduced capacity with paper-based processes. Threat actor not yet attributed publicly.

### Advantest Corporation - Ransomware Disclosure (Detected Feb 15, 2026)
Advantest, a major Japanese semiconductor test equipment manufacturer, publicly disclosed a February 15 ransomware incident. Third-party cybersecurity experts confirmed unauthorized access and ransomware deployment across portions of the network. No attribution yet. Impact to semiconductor supply chain tooling warrants monitoring.

### Lacoste - Lapsus$ Ransomware
Fashion brand Lacoste became the latest Lapsus$ ransomware victim. Scope and data exposed are under investigation. Lapsus$ continues targeting consumer brand organizations and supply chains globally.

### HanseMerkur (German Insurer) - DragonForce Extortion
DragonForce listed German insurer HanseMerkur on its dark web leak site, claiming 97GB of exfiltrated data including financial documents. HanseMerkur has not publicly confirmed the incident.

### Ransomware Trend: Encryption-Free Extortion Growing
Industry research confirms a significant structural shift: many ransomware operations are now skipping encryption entirely, instead conducting quiet data exfiltration over weeks and then extorting victims with stolen data. This model is harder to detect and carries lower operational risk for attackers. Traditional detection based on encryption activity or ransom notes will miss these attacks.

### Qilin / Gentlemen Ransomware Evolution [NEW]
CYFIRMA's March 13 weekly intelligence report highlights continued evolution of Qilin ransomware (double extortion, cross-platform including VMware ESXi) and Gentlemen Ransomware (globally active, advanced evasion, cross-platform scalable deployment). Both represent growing threats to enterprises.

---

## Law Enforcement Operations [NEW SECTION]

### Operation Lightning - SocksEscort Proxy Botnet Dismantled (March 11-12)
International law enforcement (Europol, FBI, and authorities from Austria, Bulgaria, France, Germany, Hungary, Netherlands, and Romania) dismantled the SocksEscort criminal proxy service:

- **369,000 compromised routers and IoT devices** across 163 countries enslaved into botnet
- ~8,000 infected routers actively listed as proxies as of February 2026
- Service used to commit bank/crypto account fraud, ransomware attacks, DDoS, and CSAM distribution
- Botnet built by exploiting vulnerability in residential modems from an unnamed vendor
- **34 domains and 23 servers** seized across 7 countries
- **$3.5 million in cryptocurrency** frozen by U.S. authorities
- Powered by the AVrecon malware framework

---

## Threat Actors

### Seedworm / MuddyWater (Iranian MOIS) - Active on U.S. Networks
Seedworm (aka MuddyWater, Temp Zagros, Static Kitten), confirmed as subordinate to Iran's Ministry of Intelligence and Security, has been observed active on networks of a U.S. bank, a software company, an airport, and multiple NGOs in the U.S. and Canada since February 2026. TTPs focus on espionage and credential harvesting. Organizations in financial services, tech, transportation, and civil society should review for indicators of compromise.

### Salt Typhoon (PRC/MSS) - FBI Confirms Ongoing Threat [NEW]
The FBI has publicly stated that Salt Typhoon threats are "still very, very much ongoing." Key developments:

- At least **200 organizations** targeted worldwide, primarily telecom providers
- Compromises Cisco routers and edge networking gear, then pivots to lawful-intercept surveillance equipment
- Accesses call metadata, SMS content, and live audio capture
- Mandiant was hired by AT&T and Verizon for security assessments but reports have not been provided to Congress despite requests from Senator Cantwell
- CISA issued advisory AA25-239a on countering Chinese state-sponsored network compromise

### UNC2814 / GridTide (PRC) - Google Disrupts Global Espionage Campaign [NEW]
Google disrupted a decade-long Chinese cyberespionage campaign operated by UNC2814:

- **53 organizations breached** across **42 countries** (Americas, Asia, Africa)
- Primarily targeted telecommunications providers and government organizations
- Novel **GRIDTIDE backdoor** abuses Google Sheets API as C2 channel (cell A1 for commands, A2-An for data, V1 for victim metadata)
- Exfiltrated PII including names, DOBs, phone numbers, voter IDs, and national IDs (likely for tracking individuals of interest)
- Google terminated all attacker-controlled Cloud Projects and disabled known infrastructure

### Handala Hack (IRGC-Aligned) - Expanded Targeting
Following the Stryker wiper attack (reported CTI-2026-0314), Handala claimed additional breaches: Sharjah National Oil Corporation and Israel Opportunity Energy. Research from gTIC identifies overlap between Handala (Void Manticore) and Scarred Manticore, both IRGC-linked. The group is conducting an active multi-target destructive campaign in response to the Feb 28 Iran strikes.

### Cardinal (Pro-Russian Hacktivist) - Claims IDF Network Infiltration [UPDATE]
Cardinal claims to have accessed IDF systems and exfiltrated a document related to Operation Northern Shield (Magen Tsafoni). Assessed as state-aligned but operating independently. Claimed action is unverified; treat as an influence operation until independently confirmed.

### Broader Iranian Cyber Posture
Palo Alto Unit 42's March 2026 threat brief notes Iranian internet connectivity dropped to 1-4% immediately after the Feb 28 strikes, temporarily degrading command and coordination capacity. However, pre-positioned capabilities and diaspora-linked actors remain active. NCSC UK has issued an advisory warning of sustained Iranian cyber capability despite leadership disruption.

---

## Data Breaches

### Starbucks - Employee Data Breach (Disclosed March 12) [NEW]
Starbucks disclosed a data breach affecting 889 employees via spoofed Partner Central login pages:

- **Attack window:** January 19 - February 11, 2026
- **Exposed data:** Names, Social Security numbers, dates of birth, financial account and routing numbers
- **Method:** Attackers created cloned employee portal login pages to harvest credentials, then used legitimate access to exfiltrate sensitive HR data
- **Disclosure:** Filed with Maine AG March 12; notification letters sent March 10
- **Response:** 2 years of credit monitoring and identity protection offered

### OSI Systems - INC RANSOM Attack (Disclosed March 11) [NEW]
OSI Systems (security screening, healthcare, electronics) disclosed a breach affecting 4,910 individuals:

- **Attack window:** December 23-25, 2025; detected December 25
- **Exposed data:** Names, Social Security numbers, addresses
- **Attribution:** INC RANSOM claimed 250GB exfiltrated on December 30 dark web posting
- **Disclosure:** Completed review February 10; began notification March 11
- **Response:** 12 months credit monitoring through IDX

### TELUS - Active Breach Under Investigation
Canadian telecommunications provider TELUS confirmed it is investigating an active cybersecurity incident. No data confirmed exfiltrated yet; investigation ongoing.

### McKinsey "Lilli" AI Platform - Breached in 2 Hours
Security startup CodeWall disclosed that its autonomous AI agent breached McKinsey's internal AI platform "Lilli" in approximately two hours on Feb 28 via a basic, years-old database flaw, accessing tens of millions of messages and hundreds of thousands of files. Highlights systemic risk: enterprise AI platforms are being built on legacy infrastructure with unpatched vulnerabilities. McKinsey has not publicly commented.

### LexisNexis - January 2026 Breach Confirmed
LexisNexis Legal & Professional confirmed a January 2026 breach affecting "basic account information" for an undisclosed number of accounts. Exposed data may include credentials used for downstream legal research access.

### Fidelity - $2.5M Settlement [NEW]
Fidelity reached a $2.5 million settlement over a data breach affecting 155,000 individuals/joint accountholders. Settlement covers benefits, claims administration, and credit monitoring.

---

## Vendor Advisories

| Vendor | Release | Key Items |
|--------|---------|-----------|
| Microsoft | Patch Tuesday, March 10 | 79 flaws; 2 zero-days (CVE-2026-21262, CVE-2026-26127); 3 Critical; 6 "more likely" exploited; Office RCE, Excel/Copilot exfil, Windows Kernel UAF |
| Google | Android March 2026 Bulletin | 129 vulnerabilities; 10 critical; CVE-2026-21385 actively exploited (Qualcomm); CVE-2026-0628 (Gemini EoP) |
| Apple | iOS/iPadOS 26.3, tvOS, watchOS, visionOS, Safari | Security updates released; limited CVE disclosures in 26.3.1 follow-on |
| Cisco | March 4 bundled advisory | 48 vulnerabilities; CVE-2026-20079 and CVE-2026-20131 (CVSS 10, Secure FMC) |
| Adobe | March 2026 | 8 advisories, 80 vulnerabilities across Commerce, Illustrator, Acrobat Reader, Premiere Pro; 21 critical |

---

## Recommended Actions

1. **IMMEDIATE (24h):** Replace any D-Link DSL gateway devices subject to CVE-2026-0625 - no patch exists, actively exploited
2. **IMMEDIATE (24h):** Apply Android March 2026 security update across all managed Android devices (CVE-2026-21385 actively exploited, 234 chipsets affected)
3. **URGENT (48h):** Patch all n8n instances - three active CVEs (CVE-2025-68613, CVE-2026-21858, CVE-2026-21877); two are CVSS 10.0
4. **URGENT (48h):** Apply Cisco Secure FMC patches for CVE-2026-20079 and CVE-2026-20131 (CVSS 10.0) if not yet applied
5. **URGENT (48h):** Audit VS Code and Open VSX extensions across developer environments for GlassWorm indicators; implement extension allowlisting; check for invisible Unicode characters in recently cloned repositories
6. **HIGH (7 days):** Complete Microsoft March 2026 Patch Tuesday rollout - prioritize Office (Preview Pane RCE), Windows Kernel UAF (SYSTEM priv esc), and Excel/Copilot info disclosure
7. **HIGH (7 days):** Hunt for Seedworm/MuddyWater IOCs across financial, tech, transportation, and NGO environments; focus on PowerShell LOLBin activity
8. **HIGH (7 days):** Hunt for Salt Typhoon indicators on network edge infrastructure (Cisco routers, lawful-intercept systems); review CISA advisory AA25-239a
9. **HIGH (7 days):** Alert developers to AMOS Stealer campaigns impersonating AI tools (Claude Code, OpenClaw); verify all tool downloads against official vendor URLs
10. **HIGH (7 days):** Review enterprise AI platform security posture (McKinsey Lilli breach) - audit data access controls on internal LLM/AI infrastructure
11. **MEDIUM (30 days):** Audit encryption-free exfiltration detection capability - ensure DLP and data egress monitoring can detect exfil without ransomware artifacts
12. **MEDIUM (30 days):** Review TELUS and LexisNexis exposure if these are technology/legal research vendors in your supply chain
13. **MEDIUM (30 days):** Check for AVrecon/SocksEscort indicators on residential routers and IoT devices in your network perimeter

---

## Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds Two Known Exploited Vulnerabilities (March 13)](https://www.cisa.gov/news-events/alerts/2026/03/13/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Countering Chinese State-Sponsored Actors Advisory AA25-239a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [Microsoft March 2026 Patch Tuesday - 2 Zero-Days, 79 Flaws | BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/)
- [Microsoft Patch Tuesday March 2026 Review | Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/10/microsoft-patch-tuesday-march-2026-security-update-review)
- [March 2026 Patch Tuesday - Six More-Likely-Exploited | Help Net Security](https://www.helpnetsecurity.com/2026/03/11/march-2026-patch-tuesday/)
- [Google Android March 2026 Security Bulletin | CyberScoop](https://cyberscoop.com/android-security-update-march-2026/)
- [Attackers Exploit Zero-Day in End-of-Life D-Link Routers | Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)
- [n8n Critical Vulnerability | CyberScoop](https://cyberscoop.com/n8n-critical-vulnerability-massive-risk/)
- [Cisco Issues Patches for 48 Vulnerabilities | Infosecurity Magazine](https://www.infosecurity-magazine.com/news/cisco-issues-patches-48/)
- [GlassWorm Supply-Chain Attack Abuses 72 Open VSX Extensions | The Hacker News](https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html)
- [GlassWorm Returns: Invisible Unicode Malware in 150+ GitHub Repos | Aikido](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode)
- [AMOS Stealer Targets macOS Through AI Apps | BleepingComputer](https://www.bleepingcomputer.com/news/security/amos-infostealer-targets-macos-through-a-popular-ai-app/)
- [AMOS and Amatera Disguised as AI Agents | Kaspersky](https://me-en.kaspersky.com/blog/fake-ai-agents-infostealers/25346/)
- [Malicious OpenClaw Skills Distribute Atomic macOS Stealer | Trend Micro](https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html)
- [Authorities Disrupt SocksEscort Proxy Botnet | The Hacker News](https://thehackernews.com/2026/03/authorities-disrupt-socksescort-proxy.html)
- [SocksEscort Proxy Network Takedown | CyberScoop](https://cyberscoop.com/socksescort-proxy-network-botnet-takedown/)
- [Europol Disrupts SocksEscort Proxy Service | Europol](https://www.europol.europa.eu/media-press/newsroom/news/europol-and-international-partners-disrupt-socksescort-proxy-service)
- [Law Enforcement Shuts Down SocksEscort Botnet | TechCrunch](https://techcrunch.com/2026/03/12/law-enforcement-shuts-down-botnet-made-of-tens-of-thousands-of-hacked-routers/)
- [FBI: Salt Typhoon Threats Still Very Much Ongoing | CyberScoop](https://cyberscoop.com/fbi-salt-typhoon-ongoing-threat-cybertalks-2026/)
- [Salt Typhoon Hacking World's Telecom Giants | TechCrunch](https://techcrunch.com/2026/03/09/salt-typhoon-china-who-has-been-hacked-global-telecom-giants/)
- [Google Disrupts UNC2814 GRIDTIDE Campaign | The Hacker News](https://thehackernews.com/2026/02/google-disrupts-unc2814-gridtide.html)
- [Disrupting the GRIDTIDE Espionage Campaign | Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign)
- [Starbucks Discloses Data Breach | IT Security Guru](https://www.itsecurityguru.org/2026/03/13/starbucks-discloses-data-breach-affecting-hundreds-of-employees/)
- [Starbucks Data Breach | BleepingComputer](https://www.bleepingcomputer.com/news/security/starbucks-discloses-data-breach-affecting-hundreds-of-employees/)
- [Starbucks Data Breach Via Employee Portal Clone Sites | CyberInsider](https://cyberinsider.com/starbucks-suffers-data-breach-via-employee-portal-clone-sites/)
- [OSI Systems Data Breach Investigation | Strauss Borrelli](https://straussborrelli.com/2026/03/13/osi-systems-data-breach-investigation/)
- [OSI Systems Data Breach | BreachSense](https://www.breachsense.com/breaches/osi-systems-data-breach/)
- [Fidelity Settles Data Breach Claim for $2.5 Million | NAPA](https://www.napa-net.org/news/2026/3/fidelity-settles-data-breach-claim-for-$2.5-million)
- [Threat Brief: March 2026 Iran Escalation | Palo Alto Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [Stryker Cyber Attack - Handala Claims | Cyber Magazine](https://cybermagazine.com/news/iran-war-cyber-front-stryker-cyber-attack)
- [Seedworm Active on U.S. Networks | security.com](https://www.security.com/threat-intelligence/iran-cyber-threat-activity-us)
- [Iranian Cyber Capability 2026 | Trellix](https://www.trellix.com/blogs/research/the-iranian-cyber-capability-2026/)
- [TELUS Investigating Breach | Bloomberg](https://www.bloomberg.com/news/articles/2026-03-12/canadian-telecom-telus-says-it-s-investigating-cyber-breach)
- [CYFIRMA Weekly Intelligence Report March 13 2026](https://www.cyfirma.com/news/weekly-intelligence-report-13-march-2026/)
- [Ransomware Without Encryption Surging | Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Top Data Breaches March 2026 | SharkStriker](https://sharkstriker.com/blog/march-data-breaches-today-2026/)
- [ZDI March 2026 Security Update Review](https://www.zerodayinitiative.com/blog/2026/3/10/the-march-2026-security-update-review)
- [Patch Tuesday March 2026 Talos Analysis](https://blog.talosintelligence.com/microsoft-patch-tuesday-march-2026/)

---

*Report generated by CTI Sensei | TLP:CLEAR*
