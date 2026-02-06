# Cyber Threat Intelligence Report
**Date:** February 6, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0206

---

## Executive Summary

- **NEW**: CISA adds SmarterMail CVE-2026-24423 and React Native CLI CVE-2025-11953 to KEV - SmarterMail flaw actively exploited in ransomware attacks
- **NEW**: Conduent breach balloons to 25M+ Americans - Safepay ransomware stole 8.5TB including SSNs, medical data from govtech giant
- **NEW**: Harvard & UPenn breached by ShinyHunters - 2.2M+ records exposed after universities refused ransom; vishing attack vector
- **NEW**: vLLM CVE-2026-22778 (CVSS 9.8) - Critical two-stage RCE chain threatens millions of AI inference servers via malicious video URLs
- **NEW**: n8n CVE-2026-25049 (CVSS 9.4) - Fourth critical n8n flaw in two months; sandbox escape bypasses previous patches
- **NEW**: Amaranth-Dragon (APT-41 linked) exposed - China-nexus group targeted SE Asian governments exploiting WinRAR CVE-2025-8088
- **NEW**: React2Shell NGINX hijacking campaign - 1,083 IPs exploiting CVE-2025-55182 to hijack web traffic via config injection
- **DEADLINE TODAY**: SolarWinds WHD CVE-2025-40551 - CISA deadline **February 6, 2026**

---

## Critical Vulnerabilities

### DEADLINE TODAY: SolarWinds Web Help Desk CVE-2025-40551

**CISA Remediation Deadline:** February 6, 2026 (TODAY)
**CVE:** CVE-2025-40551
**CVSS:** 9.8 (Critical)
**Status:** Actively exploited

Organizations must patch to Web Help Desk 2026.1 by end of day today. Unauthenticated RCE via deserialization in AjaxProxy.

**Source:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### NEW: CISA KEV Additions (February 5, 2026)

Two vulnerabilities added with evidence of active exploitation:

| CVE | Product | CVSS | Deadline |
|-----|---------|------|----------|
| CVE-2026-24423 | SmarterTools SmarterMail | Critical | **Feb 26, 2026** |
| CVE-2025-11953 | React Native Community CLI | High | **Feb 26, 2026** |

**Sources:** [CISA Alert](https://www.cisa.gov/news-events/alerts/2026/02/05/cisa-adds-two-known-exploited-vulnerabilities-catalog), [Security Affairs](https://securityaffairs.com/187675/security/u-s-cisa-adds-smartertools-smartermail-and-react-native-community-cli-flaws-to-its-known-exploited-vulnerabilities-catalog.html)

---

### NEW: SmarterMail CVE-2026-24423 - Exploited in Ransomware Attacks

**CVE:** CVE-2026-24423
**Type:** Missing Authentication for Critical Function (ConnectToHub API)
**Impact:** Unauthenticated Remote Code Execution
**Status:** Active ransomware exploitation confirmed
**CISA Deadline:** February 26, 2026

**Details:**
The vulnerability allows attackers to direct SmarterMail servers to a malicious HTTP server that delivers OS commands, which the vulnerable application executes. No authentication required.

**Affected:** SmarterMail versions prior to build 9511
**Fixed:** Build 9511 (released January 15, 2026)

**Why Critical:** Self-hosted email servers are high-value targets - compromise provides access to all organizational email, credentials, and internal communications.

**Sources:** [Help Net Security](https://www.helpnetsecurity.com/2026/02/06/ransomware-smartermail-cve-2026-24423/), [SecurityWeek](https://www.securityweek.com/critical-smartermail-vulnerability-exploited-in-ransomware-attacks/), [VulnCheck](https://www.vulncheck.com/blog/smartermail-connecttohub-rce-cve-2026-24423)

---

### NEW: vLLM CVE-2026-22778 - AI Server Takeover via Video URL

**CVE:** CVE-2026-22778
**CVSS:** 9.8 (Critical)
**Disclosed:** February 2, 2026
**Discovered by:** Orca Security
**Type:** Chained information leak + heap overflow

**Two-Stage Attack Chain:**

1. **Information Leak**: PIL error handling exposes heap address via exception message, reducing ASLR effectiveness from ~4 billion combinations to ~8 guesses
2. **Heap Overflow**: JPEG2000 decoder in OpenCV's FFmpeg dependency allows channel remapping via "cdef" box, triggering heap corruption

**Impact:** Unauthenticated RCE - out-of-the-box vLLM installations have no authentication, meaning any attacker with network access can exploit this

**Affected:** vLLM 0.8.3 through 0.14.0
**Fixed:** vLLM 0.14.1

**Why Critical:** vLLM is the most widely deployed open-source LLM inference engine. Organizations running multimodal video model support are immediately at risk.

**Sources:** [Orca Security](https://orca.security/resources/blog/cve-2026-22778-vllm-rce-vulnerability/), [OX Security](https://www.ox.security/blog/cve-2026-22778-vllm-rce-vulnerability/), [The Cyber Express](https://thecyberexpress.com/cve-2026-22778-vllm-rce-malicious-video-link/)

---

### NEW: n8n CVE-2026-25049 - Sandbox Escape (Fourth Critical Flaw)

**CVE:** CVE-2026-25049
**CVSS:** 9.4 (Critical)
**Status:** Patch bypass for CVE-2025-68613 (patched December 2025)
**Disclosed:** February 5, 2026

**Details:**
Insufficient input sanitization in n8n's expression handling logic. A mismatch between TypeScript compile-time types and JavaScript runtime behavior allows attackers to craft malicious expressions that bypass sanitization checks entirely.

**Exploitation:** Combined with n8n's public webhook feature, exploitation requires no authentication. A single line of JavaScript using destructuring syntax triggers remote command execution.

**Affected:** All n8n versions before 1.123.17 and 2.5.2
**Fixed:** n8n 1.123.17 and 2.5.2

**n8n Critical Vulnerability Timeline (2025-2026):**

| CVE | CVSS | Date | Description |
|-----|------|------|-------------|
| CVE-2026-21858 | 10.0 | Jan 2026 | Unauthenticated RCE via file-handling |
| CVE-2026-1470 | 9.9 | Feb 2026 | Security control bypass |
| CVE-2026-0863 | 8.5 | Feb 2026 | Full service takeover |
| CVE-2026-25049 | 9.4 | Feb 2026 | Sandbox escape bypasses Dec fix |

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html), [SecurityWeek](https://www.securityweek.com/critical-n8n-sandbox-escape-could-lead-to-server-compromise/), [The Register](https://www.theregister.com/2026/02/05/n8n_security_woes_roll_on)

---

### NEW: React Native CLI CVE-2025-11953 - Command Injection

**CVE:** CVE-2025-11953
**Type:** OS Command Injection in Metro dev server
**Status:** Added to CISA KEV (Feb 5, 2026)
**CISA Deadline:** February 26, 2026

**Details:**
React Native CLI's Metro dev server binds to external interfaces by default and exposes a command injection flaw, allowing unauthenticated attackers to send POST requests to execute arbitrary programs.

**Risk:** Development servers inadvertently exposed to the internet become trivially exploitable.

**Sources:** [GBHackers](https://gbhackers.com/cisa-alerts-exploited-react-native-community-security-flaw/), [CISA](https://www.cisa.gov/news-events/alerts/2026/02/05/cisa-adds-two-known-exploited-vulnerabilities-catalog)

---

### NEW: Apple iOS 26.2 - Two Zero-Days Patched

**CVEs:** CVE-2025-43529, CVE-2025-14174
**Type:** WebKit use-after-free and memory corruption
**Status:** Actively exploited in "extremely sophisticated" targeted attacks

**Targets:** Journalists, activists, dissidents, and political figures - consistent with commercial spyware (Pegasus/Predator class)

**Concern:** Only ~4.6% of active iPhones are on iOS 26.2; ~84% remain on vulnerable older releases.

**Sources:** [Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/update-ios-26-2-apple-flags-webkit-flaws-exploited-hackers), [Apple](https://support.apple.com/en-us/125884), [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/01/why-iphone-users-should-update-and-restart-their-devices-now)

---

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2025-40551 | SolarWinds Web Help Desk | **TODAY (Feb 6)** |
| CVE-2026-20045 | Cisco Unified CM/Webex | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |
| CVE-2019-19006/CVE-2025-64328 | FreePBX/Sangoma | February 24, 2026 |
| CVE-2021-39935 | GitLab CE/EE | February 24, 2026 |
| CVE-2026-24423 | SmarterTools SmarterMail | February 26, 2026 |
| CVE-2025-11953 | React Native CLI | February 26, 2026 |

---

## Exploits & Active Campaigns

### NEW: React2Shell NGINX Web Traffic Hijacking Campaign

**CVE:** CVE-2025-55182 (CVSS 10.0)
**Discovered by:** Datadog Security Labs
**Campaign Period:** January 26 - February 2, 2026
**Scale:** 1,083 unique source IPs involved in exploitation

**How It Works:**
Attackers exploit React Server Components vulnerability to inject malicious NGINX configurations that intercept legitimate web traffic and route it through attacker-controlled backend servers via `proxy_pass` directives.

**Targets:** Asian TLDs (.in, .id, .pe, .bd, .th), Chinese hosting infrastructure (Baota Panel), government and educational domains (.edu, .gov)

**Why Hard to Detect:**
- No malicious binaries installed
- No exploit signatures to match
- Injected directives are syntactically valid NGINX config
- Standard config checks that verify NGINX starts without errors will miss this entirely

**Post-Exploitation:**
- Cryptomining binary deployment
- Reverse shell access

**Top Attackers:** Two IPs (193.142.147[.]209 and 87.121.84[.]24) account for 56% of all exploitation attempts.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/hackers-exploit-react2shell-to-hijack.html), [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/web-traffic-hijacking-nginx-configuration-malicious/), [Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182), [Darktrace](https://www.darktrace.com/blog/react2shell-how-opportunist-attackers-exploited-cve-2025-55182-within-hours)

---

### NEW: Chrome Security Updates

Google released Chrome updates addressing:

| CVE | Type | Severity |
|-----|------|----------|
| CVE-2026-1862 | V8 Type Confusion | High |
| CVE-2026-1861 | Heap Corruption via crafted HTML | High |

No confirmed in-the-wild exploitation yet, but V8 type confusion bugs have historically been weaponized rapidly.

**Source:** [TechRepublic](https://www.techrepublic.com/article/news-google-chrome-security-update-february-2026/)

---

## APT & Threat Actor Activity

### NEW: Amaranth-Dragon (APT-41 Ecosystem) - Southeast Asia Espionage

**Threat Actor:** Amaranth-Dragon
**Attribution:** China-nexus, linked to APT-41 ecosystem
**Discovered by:** Check Point Research
**Targets:** Government and law enforcement in Cambodia, Thailand, Laos, Indonesia, Singapore, Philippines
**Active:** Throughout 2025

**Key Details:**
- Campaigns timed to coincide with sensitive political developments and regional security events
- Infrastructure configured to interact only with victims in specific target countries
- Weaponized CVE-2025-8088 (WinRAR) within 10 days of disclosure

**Malware:**
- **Amaranth Loader** - Previously unknown loader sharing similarities with DodgeBox, Dustpan, and Dusttrap (APT-41 tools)
- **Havoc Framework** - Open-source C2 platform used as primary payload

**Operational Pattern:**
- File compilation timestamps and campaign timelines consistent with UTC+8 (China Standard Time)
- Highly controlled targeting with geographic restrictions on attack infrastructure

**Sources:** [Check Point Research](https://research.checkpoint.com/2026/amaranth-dragon-weaponizes-cve-2025-8088-for-targeted-espionage/), [The Hacker News](https://thehackernews.com/2026/02/china-linked-amaranth-dragon-exploits.html), [Security Affairs](https://securityaffairs.com/187647/apt/china-linked-amaranth-dragon-hackers-target-southeast-asian-governments-in-2025.html)

---

### NEW: SonicWall SMA1000 Chained Zero-Day Exploitation

**CVEs:** CVE-2025-40602 (CVSS 6.6) chained with CVE-2025-23006 (CVSS 9.8)
**Product:** SonicWall Secure Mobile Access (SMA) 1000
**Impact:** Unauthenticated RCE with root privileges

**Details:**
CVE-2025-40602 (local privilege escalation in AMC) is being chained with the older CVE-2025-23006 (critical deserialization flaw) to achieve full unauthenticated remote root access.

**Fixed:** SMA1000 versions 12.4.3-03245+ and 12.5.0-02283+

**Mitigations:**
- Restrict AMC access to VPN or specific admin IPs
- Disable SSL VPN management interface from public internet

**Sources:** [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/sonicwall-edge-devices-zero-day-attacks), [Tenable](https://www.tenable.com/blog/cve-2025-40602-sonicwall-secure-mobile-access-sma-1000-zero-day-exploited)

---

## Data Breaches

### NEW: Conduent - 25M+ Americans Affected (Updated)

**Victim:** Conduent (government technology provider)
**Attack Date:** January 2025
**Threat Actor:** Safepay ransomware group
**Affected:** 25.9M+ confirmed (15.4M in Texas alone, 10.5M in Oregon)
**Data Stolen:** 8.5 terabytes
**Estimated Final Count:** Could exceed 25M+; potentially one of top 5 largest healthcare breaches in US history

**Data Compromised:**
- Names, Social Security numbers
- Medical data, health insurance information
- Government benefits data

**Financial Impact:**
- $9M in breach costs through September 2025
- Additional $16M expected by Q1 2026
- 10+ class action lawsuits filed
- Credit monitoring deadline: March 31, 2026

**Significance:** Conduent provides claims administration and benefits processing for government agencies. This breach exposes the systemic risk of centralized govtech providers.

**Sources:** [TechCrunch](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/), [HIPAA Journal](https://www.hipaajournal.com/conduent-business-solutions-data-breach/), [SecurityWeek](https://www.securityweek.com/millions-impacted-by-conduent-data-breach/)

---

### NEW: Harvard University & UPenn - ShinyHunters (2.2M+ Records)

**Victims:** Harvard University, University of Pennsylvania
**Threat Actor:** ShinyHunters (Scattered LAPSUS$ Hunters collective)
**Published:** February 4, 2026
**Total Records:** 2.2M+ combined (115K from Harvard AAD, 1M+ per university)

**Attack Vector:** Voice phishing (vishing) - attackers used social engineering to obtain legitimate credentials

**Harvard Data Exposed:**
- Email addresses, phone numbers
- Home and business addresses
- Event attendance, donation details
- Alumni biographical information
- Family relationships and wealth band data

**Why Published:** Both universities refused to pay ransom.

**Timeline:**
- November 18, 2025: Harvard discovers compromise
- February 4, 2026: ShinyHunters publishes stolen data

**Significance:** The data maps the "social graph" of wealthy alumni - family members, wealth bands, domestic relationships - making it extremely valuable for targeted social engineering and whaling attacks.

**Sources:** [TechCrunch](https://techcrunch.com/2026/02/04/hackers-publish-personal-information-stolen-during-harvard-upenn-data-breaches/), [InfoStealers](https://www.infostealers.com/article/a-technical-and-ethical-post-mortem-of-the-feb-2026-harvard-university-shinyhunters-data-breach/), [Bank Info Security](https://www.bankinfosecurity.com/harvard-upenn-data-leaked-in-shinyhunters-shakedown-a-30677)

---

## Vendor Advisories

### Microsoft Patch Tuesday - February 10, 2026

**Scheduled:** February 10, 2026
**Expected:** Monthly security updates for Windows 11 25H2/24H2 and Windows 10 ESU, plus three rounds of out-of-band patches from January.

**New Features (Windows 11):** Cross-Device Resume, MIDI upgrades, Smart App Control changes

**Sources:** [Help Net Security](https://www.helpnetsecurity.com/2026/02/06/february-2026-patch-tuesday-forecast/), [MSFTNewsNow](https://msftnewsnow.com/microsoft-patch-tuesday-february-10-2026-windows/)

### Apple

- iOS 26.2 / iPadOS 26.2 patches two actively exploited WebKit zero-days
- Update all Apple devices immediately

### Google

- Chrome 143 security update addresses V8 type confusion and heap corruption

### SmarterTools

- SmarterMail build 9511 patches CVE-2026-24423 (unauthenticated RCE)
- All prior builds vulnerable; active ransomware exploitation

### n8n

- Versions 1.123.17 and 2.5.2 patch CVE-2026-25049
- This is the fourth critical vulnerability in under two months

### SonicWall

- SMA1000 versions 12.4.3-03245+ and 12.5.0-02283+ patch chained zero-day

---

## Recommended Actions

### Immediate Priority (Next 24 Hours)

1. **SolarWinds WHD** - Patch to 2026.1 TODAY - CISA deadline is **February 6, 2026**
2. **SmarterMail** - Upgrade to build 9511 immediately; active ransomware exploitation of CVE-2026-24423
3. **n8n** - Update to 1.123.17 or 2.5.2; fourth critical RCE in two months (CVE-2026-25049)
4. **vLLM** - Upgrade to 0.14.1; unauthenticated RCE via video URL (CVE-2026-22778)
5. **Apple devices** - Update to iOS/iPadOS 26.2 for WebKit zero-day patches

### High Priority (This Week)

6. **Cisco UCM/Webex** - Patch CVE-2026-20045 before February 11 deadline
7. **SonicWall SMA1000** - Update to patched versions; chained zero-day exploitation active
8. **Chrome** - Update to 143.0.7499.192+
9. **React Native CLI** - Audit for Metro dev servers exposed to internet (CVE-2025-11953)

### Threat Hunting

10. **NGINX configurations** - Audit for injected `proxy_pass` directives redirecting traffic (React2Shell campaign)
11. **WinRAR exploitation** - Hunt for Amaranth-Dragon indicators; malicious RAR archives exploiting CVE-2025-8088
12. **Email infrastructure** - Review SmarterMail ConnectToHub API access logs
13. **AI infrastructure** - Audit vLLM deployments for authentication enforcement

### Breach Response

14. **Conduent** - If your organization uses Conduent services, proactively notify affected individuals
15. **Harvard/UPenn alumni** - Monitor for targeted phishing using leaked social graph data
16. **Substack/Reddit** (from Feb 5) - Continue monitoring for credential abuse

---

## Sources

- [CISA - February 5 KEV Additions](https://www.cisa.gov/news-events/alerts/2026/02/05/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Help Net Security - SmarterMail Ransomware](https://www.helpnetsecurity.com/2026/02/06/ransomware-smartermail-cve-2026-24423/)
- [SecurityWeek - SmarterMail Exploitation](https://www.securityweek.com/critical-smartermail-vulnerability-exploited-in-ransomware-attacks/)
- [VulnCheck - SmarterMail Analysis](https://www.vulncheck.com/blog/smartermail-connecttohub-rce-cve-2026-24423)
- [TechCrunch - Conduent Breach](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [HIPAA Journal - Conduent](https://www.hipaajournal.com/conduent-business-solutions-data-breach/)
- [TechCrunch - Harvard/UPenn Breach](https://techcrunch.com/2026/02/04/hackers-publish-personal-information-stolen-during-harvard-upenn-data-breaches/)
- [InfoStealers - Harvard Post-Mortem](https://www.infostealers.com/article/a-technical-and-ethical-post-mortem-of-the-feb-2026-harvard-university-shinyhunters-data-breach/)
- [Orca Security - vLLM RCE](https://orca.security/resources/blog/cve-2026-22778-vllm-rce-vulnerability/)
- [The Hacker News - n8n CVE-2026-25049](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [The Register - n8n Security Woes](https://www.theregister.com/2026/02/05/n8n_security_woes_roll_on)
- [Check Point - Amaranth-Dragon](https://research.checkpoint.com/2026/amaranth-dragon-weaponizes-cve-2025-8088-for-targeted-espionage/)
- [The Hacker News - Amaranth-Dragon](https://thehackernews.com/2026/02/china-linked-amaranth-dragon-exploits.html)
- [Datadog - NGINX Hijacking](https://securitylabs.datadoghq.com/articles/web-traffic-hijacking-nginx-configuration-malicious/)
- [Google Cloud - React2Shell](https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182)
- [Dark Reading - SonicWall Zero-Day](https://www.darkreading.com/vulnerabilities-threats/sonicwall-edge-devices-zero-day-attacks)
- [Tenable - SonicWall SMA1000](https://www.tenable.com/blog/cve-2025-40602-sonicwall-secure-mobile-access-sma-1000-zero-day-exploited)
- [Apple - iOS 26.2 Security Content](https://support.apple.com/en-us/125884)
- [TechRepublic - Chrome Security Update](https://www.techrepublic.com/article/news-google-chrome-security-update-february-2026/)
- [Help Net Security - Feb 2026 Patch Tuesday Forecast](https://www.helpnetsecurity.com/2026/02/06/february-2026-patch-tuesday-forecast/)
- [Security Affairs - CISA KEV Updates](https://securityaffairs.com/187675/security/u-s-cisa-adds-smartertools-smartermail-and-react-native-community-cli-flaws-to-its-known-exploited-vulnerabilities-catalog.html)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 2-5, 2026 reports:

- CVE-2025-40551 SolarWinds WHD (initial disclosure and KEV addition)
- CVE-2025-22224/22225/22226 VMware ESXi chain (ransomware exploitation confirmed)
- CVE-2026-21509 Microsoft Office zero-day / APT28 Operation Neusploit
- CVE-2026-20045 Cisco UCM/Webex zero-day
- CVE-2026-21858/CVE-2026-1470/CVE-2026-0863 n8n vulnerabilities (prior three)
- CVE-2025-12743 Google Looker "LookOut" vulnerabilities
- CVE-2026-20805 Microsoft DWM zero-day (deadline passed Feb 3)
- CVE-2026-24061 GNU InetUtils telnetd
- CVE-2026-0625 D-Link DSL routers (no patch available)
- APT28 Operation Neusploit details
- Iranian APT Infy (Prince of Persia) - Telegram C2
- Phantom Taurus NET-STAR malware suite
- Under Armour breach (72.7M accounts)
- Nike/WorldLeaks (1.4TB)
- Crunchbase breach (2M+ records)
- Target source code theft (860 GB)
- Substack data breach (Feb 5)
- Reddit data breach (Feb 5)
- Hawk Law Group - INC ransomware
- Energy/utilities sector 60%+ ransomware surge
- Oleg Nefedov - EU Most Wanted ransomware leader

---

*Report generated: 2026-02-06*
*Next report: 2026-02-07*
*Classification: TLP:CLEAR*
