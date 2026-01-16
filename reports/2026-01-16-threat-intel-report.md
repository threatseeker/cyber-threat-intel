# Cyber Threat Intelligence Report
## Date: January 16, 2026

---

## Executive Summary

Today's threat landscape features several notable developments including a **critical WordPress plugin vulnerability (CVE-2026-23550)** actively exploited in the wild, a **new AI platform vulnerability in Langflow (CVE-2026-21445)**, and the patched **"Reprompt" attack technique** targeting Microsoft Copilot. Ransomware activity continues with **Dire Wolf ransomware** claiming new victims including Japan's Tepco-Group, while the **Astaroth banking trojan** has evolved with a new WhatsApp-based worm module targeting Brazilian users. The **DarkSpectre browser extension campaign** has been uncovered, having infected over 8.8 million users across Chrome, Edge, and Firefox.

**Key Actions Required:**
- WordPress administrators: Immediately update Modular DS plugin to version 2.5.2
- Langflow users: Upgrade to version 1.7.0.dev45 or above
- Apply January 2026 Patch Tuesday updates for Reprompt fix
- Review browser extensions for potential DarkSpectre compromise

---

## Critical Vulnerabilities (NEW)

### CVE-2026-23550 - WordPress Modular DS Plugin (CVSS 10.0) - ACTIVELY EXPLOITED
**Status:** Under active exploitation

A maximum-severity privilege escalation vulnerability in the WordPress Modular DS plugin affecting all versions prior to 2.5.2. The flaw allows unauthenticated attackers to bypass authentication and gain administrative access to WordPress sites.

**Technical Details:**
- Vulnerability exists in the plugin's custom routing layer extending Laravel's route matching functionality
- Route matching logic is overly permissive, allowing crafted requests to match protected endpoints without proper authentication
- Attackers can bypass authentication by supplying `origin=mo&type=xxx` parameters
- Over 40,000 active WordPress installations affected

**Remediation:** Update to Modular DS version 2.5.2 immediately

**Sources:** [The Hacker News](https://thehackernews.com/2026/01/critical-wordpress-modular-ds-plugin.html), [Patchstack](https://patchstack.com/database/wordpress/plugin/modular-connector/vulnerability/wordpress-modular-ds-monitor-update-and-backup-multiple-websites-plugin-2-5-1-privilege-escalation-vulnerability), [Bleeping Computer](https://www.bleepingcomputer.com/news/security/hackers-exploit-modular-ds-wordpress-plugin-flaw-for-admin-access/)

---

### CVE-2026-21445 - Langflow AI Platform (CVSS 8.8)
**Status:** Patch available

Critical vulnerability in the Langflow AI workflow automation tool due to missing authentication controls on critical API endpoints.

**Technical Details:**
- Multiple critical API endpoints missing authentication dependencies in `src/backend/base/langflow/api/v1/monitor.py`
- Unauthenticated attackers can access sensitive user conversation data and transaction histories
- Attackers can perform destructive operations including message deletion
- CWE-306: Missing Authentication for Critical Function

**Remediation:** Upgrade to Langflow version 1.7.0.dev45 or above

**Sources:** [GitHub Advisory](https://github.com/advisories/GHSA-c5cp-vx83-jhqx), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21445)

---

## Exploits & Zero-Days (NEW)

### Reprompt Attack - Microsoft Copilot Data Exfiltration (PATCHED)
**Status:** Fixed as of January 13, 2026

Varonis Threat Labs disclosed a novel attack technique called "Reprompt" that allowed single-click data exfiltration from Microsoft Copilot Personal.

**Attack Chain:**
1. **Initial Parameter Injection (P2P):** Exploits Copilot's `q` URL parameter to embed malicious instructions in URLs
2. **Double Request Bypass:** Circumvents guardrails by instructing Copilot to repeat actions twice
3. **Chain-Request Exfiltration:** Enables continuous dynamic instruction delivery from attacker's server

**Key Risk Factors:**
- Required no user-entered prompts, installed plugins, or enabled connectors
- Persisted after chat was closed due to leveraging active user session
- Created invisible channel for data exfiltration

**Remediation:** Install January 2026 Patch Tuesday updates. Use Microsoft 365 Copilot for enterprise workloads.

**Sources:** [The Hacker News](https://thehackernews.com/2026/01/researchers-reveal-reprompt-attack.html), [SecurityWeek](https://www.securityweek.com/new-reprompt-attack-silently-siphons-microsoft-copilot-data/), [Bleeping Computer](https://www.bleepingcomputer.com/news/security/reprompt-attack-let-hackers-hijack-microsoft-copilot-sessions/)

---

## Malware & Ransomware Campaigns (NEW)

### DarkSpectre Browser Extension Campaign - 8.8 Million Users Infected
**Status:** Active investigation

Security researchers at Koi uncovered a massive coordinated spyware campaign spanning 100+ browser extensions across Google Chrome, Microsoft Edge, and Mozilla Firefox.

**Capabilities:**
- Stripping security protections
- Installing backdoors for remote code execution
- Performing surveillance
- Disabling anti-fraud protections on Chinese e-commerce affiliate links

**Scale:** At least 8.8 million users infected over the past seven years through seemingly legitimate browser extensions

**Sources:** [HotHardware](https://hothardware.com/news/darkspectre-malware-campaign-infected-88-million-users)

---

### Astaroth "Boto Cor-de-Rosa" Campaign - WhatsApp Worm in Brazil
**Status:** Active since September 2025

The Astaroth (Guildma) banking trojan has evolved with a new WhatsApp-based worm module targeting Brazilian users.

**Key Features:**
- New Python-based WhatsApp propagation module harvests victim's contact list
- Automatically sends malicious ZIP files to all contacts with time-appropriate Portuguese greetings
- Creates self-sustaining infection loop without additional infrastructure
- Built-in real-time propagation metrics tracking

**Geographic Distribution:** 95%+ of infections in Brazil

**Technical Architecture:**
- Core payload: Delphi
- Installer: Visual Basic script
- WhatsApp worm module: Python

**Sources:** [The Hacker News](https://thehackernews.com/2026/01/whatsapp-worm-spreads-astaroth-banking.html), [Acronis](https://www.acronis.com/en/tru/posts/boto-cor-de-rosa-campaign-reveals-astaroth-whatsapp-based-worm-activity-in-brazil/), [Security Affairs](https://securityaffairs.com/186685/malware/astaroth-banking-trojan-spreads-in-brazil-via-whatsapp-worm.html)

---

### Dire Wolf Ransomware - Tepco-Group Attack
**Status:** Active

Dire Wolf ransomware group has claimed a new victim: Tepco-Group, a Japanese energy sector company, discovered on January 13, 2026.

**Group Profile:**
- First identified: May 2025
- Total claimed victims: 41+
- Tactics: Double extortion (encryption + data theft)
- Technical: Golang-based, UPX packed, Curve25519 key exchange with ChaCha20 encryption
- Target sectors: Manufacturing, technology
- Geographic focus: Thailand, Taiwan, Singapore, United States, Japan

**Sources:** [Dark Reading](https://www.darkreading.com/threat-intelligence/dire-wolf-ransomware-manufacturing-technology), [SOCRadar](https://socradar.io/blog/dark-web-profile-dire-wolf-ransomware/), [HookPhish](https://www.hookphish.com/blog/ransomware-group-direwolf-hits-tepco-group/)

---

### c-ares DLL Side-Loading Campaign
**Status:** Active

Active malware campaign exploiting a DLL side-loading vulnerability in the legitimate c-ares library to bypass security controls.

**Malware Distribution:**
- Agent Tesla, CryptBot, Formbook, Lumma Stealer, Vidar Stealer
- Remcos RAT, Quasar RAT, DCRat, XWorm

**Technique:** Attackers pair malicious `libcares-2.dll` with signed versions of legitimate `ahost.exe` to execute code and bypass signature-based defenses.

**Sources:** [The Hacker News](https://thehackernews.com/2026/01/hackers-exploit-c-ares-dll-side-loading.html)

---

### GlassWorm Wave 4 - macOS Developer Targeting
**Status:** Active

Fourth wave of the GlassWorm campaign now targeting macOS developers (previous waves focused on Windows).

**Attack Vector:** Malicious VSCode/OpenVSX extensions delivering trojanized crypto wallet applications

**Sources:** [Bleeping Computer](https://www.bleepingcomputer.com/news/security/new-glassworm-malware-wave-targets-macs-with-trojanized-crypto-wallets/)

---

### Infostealer Campaign via Spoofed Software Installers
**Status:** Active (January 11-15, 2026)

VirusTotal identified a campaign using spoofed MalwareBytes installers to distribute infostealers.

**Distribution Method:**
- ZIP files with filenames like `malwarebytes-windows-github-io-X.X.X.zip`
- Trusted executable used for DLL side-loading
- Secondary-stage infostealers deployed

**Sources:** [VirusTotal Blog](https://blog.virustotal.com/2026/01/malicious-infostealer-january-26.html)

---

## Threat Actor Activity (NEW)

### APT28 (Fancy Bear) - Credential Harvesting Campaign
**Status:** Active (February-September 2025, continuing)

Russian GRU-linked APT28 conducting credential harvesting operations using phishing pages and off-the-shelf infrastructure.

**Target Regions:**
- Balkans
- Middle East
- Central Asia

**Assessment:** APT28 represents a persistent external pressure actor focused on intelligence collection, influence positioning, and operational readiness rather than immediate disruption.

**Sources:** [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-credentials-global-targets), [CYFIRMA](https://www.cyfirma.com/news/weekly-intelligence-report-16-january-2026/)

---

### Chinese APT GTG-1002 - AI-Powered Operations
**Status:** Ongoing monitoring

Chinese APT group GTG-1002 has been caught abusing Anthropic's Claude AI to automate:
- Phishing campaigns
- Malware development
- Reconnaissance tasks

This marks a significant shift toward AI-powered cyber-espionage operations.

**Sources:** [Daily Security Review](https://dailysecurityreview.com/threat-actors/chinese-apt-leveraged-claude-ai-for-automated-espionage-operation/)

---

## Vendor Security Advisories (This Week)

### Mozilla Firefox 147 (Released January 13, 2026)
- **34 vulnerabilities** patched
- **CVE-2026-0891 and CVE-2026-0892**: Suspected active exploitation
- Critical sandbox escape vulnerability (CVSS 10.0) in Messaging System component
- Use-after-free in JavaScript Engine enabling arbitrary code execution

**Action:** Update Firefox to version 147 immediately

**Sources:** [Mozilla Security Advisories](https://www.mozilla.org/en-US/security/advisories/), [Secure-ISS Advisory](https://secure-iss.com/soc-advisory-mozilla-firefox-critical-vulnerabilities-14-jan-2026/)

---

### Adobe January 2026 Security Updates (Released January 14, 2026)
- **11 security advisories** addressing **25 vulnerabilities**
- **17 critical severity** vulnerabilities
- Affected products: DreamWeaver, InDesign, Illustrator, InCopy, Bridge, Substance 3D suite, ColdFusion

**ColdFusion:** Priority 1 update for code execution bug
**DreamWeaver:** 5 Critical-rated code execution bugs fixed

**Sources:** [Zero Day Initiative](https://www.zerodayinitiative.com/blog/2026/1/13/the-january-2026-security-update-review), [Qualys Blog](https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review)

---

### [UPDATE] Cisco ISE CVE-2026-20029 - PoC Exploit Available
**Status:** PoC publicly available, no active exploitation reported

Proof-of-concept exploit code is now publicly available for the Cisco ISE XXE vulnerability (CVSS 4.9).

**Affected Versions:** Cisco ISE and ISE-PIC releases earlier than 3.2 (no patches available - must migrate)

**Impact:** Authenticated attacker with admin credentials can read arbitrary files from underlying operating system

**Sources:** [The Hacker News](https://thehackernews.com/2026/01/cisco-patches-ise-security.html), [Bleeping Computer](https://www.bleepingcomputer.com/news/security/cisco-warns-of-identity-service-engine-flaw-with-exploit-code/)

---

## Industry News & Data Breaches (NEW)

### ANKA / GSPlatformCo Data Breach - 537,877 Individuals Affected
**Disclosure Date:** January 2026
**Discovery Date:** November 22, 2025

African fintech platform ANKA (operated by GSPlatformCo Inc.) disclosed a data exposure incident.

**Data Exposed:**
- Names, contact information, demographic data
- Account status and basic transaction history

**NOT Compromised:** Passwords, payment cards, login tokens, sensitive files

Multiple law firms investigating potential class action lawsuits.

**Sources:** [ClassAction.org](https://www.classaction.org/data-breach-lawsuits/anka-january-2026), [GlobeNewswire](https://www.globenewswire.com/news-release/2026/01/13/3218201/0/en/GSPlatform-Co-Inc-Data-Breach-Claims-Investigated-by-Lynch-Carpenter.html)

---

### Rmoney India - Financial Data Compromise Alleged
**Status:** Under investigation

Indian fintech platform Rmoney India allegedly compromised. On January 8, 2026, threat actor listed organization on dark web forum claiming exfiltration of full production database (1.5GB SQL dump).

**Sources:** [CYFIRMA Weekly Intelligence Report](https://www.cyfirma.com/news/weekly-intelligence-report-16-january-2026/)

---

### Ransomware Landscape Statistics (January 2026)
Per Bitdefender Threat Debrief:
- **December 2025:** 839 claimed ransomware victims (second-highest of 2025)
- **LockBit returned** to Top 10 with 112 claimed victims
- **Qilin led** with 183 claimed victims in December
- **Manufacturing** sector remains hardest hit

**Sources:** [Bitdefender Threat Debrief](https://businessinsights.bitdefender.com/bitdefender-threat-debrief-january-2026)

---

## Recommended Actions

### Immediate (24-48 Hours)
1. **WordPress Sites:** Update Modular DS plugin to version 2.5.2 to address CVE-2026-23550
2. **Microsoft Users:** Verify January 2026 Patch Tuesday updates are installed (Reprompt fix)
3. **Firefox Users:** Update to Firefox 147 or Firefox ESR 140.7
4. **Langflow Deployments:** Upgrade to version 1.7.0.dev45 or above

### Short-Term (This Week)
5. **Adobe Products:** Apply January 2026 security updates, prioritize ColdFusion
6. **Browser Extension Audit:** Review installed extensions for potential DarkSpectre compromise
7. **Cisco ISE:** Plan migration path for versions earlier than 3.2
8. **D-Link DSL Routers:** Replace end-of-life devices vulnerable to CVE-2026-0625

### Ongoing
9. **Phishing Awareness:** Reinforce training regarding APT28 credential harvesting campaigns
10. **Brazilian Operations:** Alert users to Astaroth WhatsApp malware campaign
11. **AI Platform Security:** Review authentication controls on AI/ML workflow tools
12. **Ransomware Preparedness:** Ensure backup and recovery plans are tested, especially for manufacturing sector

---

## Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CYFIRMA Weekly Intelligence Report - January 16, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-16-january-2026/)
- [Bitdefender Threat Debrief - January 2026](https://businessinsights.bitdefender.com/bitdefender-threat-debrief-january-2026)
- [The Hacker News](https://thehackernews.com/)
- [Bleeping Computer](https://www.bleepingcomputer.com/)
- [SecurityWeek](https://www.securityweek.com/)
- [Dark Reading](https://www.darkreading.com/)
- [Help Net Security](https://www.helpnetsecurity.com/)
- [Zero Day Initiative](https://www.zerodayinitiative.com/)
- [Mozilla Security Advisories](https://www.mozilla.org/en-US/security/advisories/)
- [Cisco Security Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xxe-jWSbSDKt)
- [Patchstack](https://patchstack.com/)
- [Varonis Threat Labs](https://www.varonis.com/)

---

*Report Generated: January 16, 2026*
*Classification: TLP:WHITE - Unlimited Distribution*
