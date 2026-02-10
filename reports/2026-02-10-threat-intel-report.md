# Cyber Threat Intelligence Report
**Date:** February 10, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0210

---

## Executive Summary

- **NEW**: Microsoft Patch Tuesday TODAY - 63 vulnerabilities, 8 critical, 2 actively exploited zero-days including CVE-2026-20876 (Windows VBS Enclave EoP)
- **NEW**: UNC3886 (China) targeted all 4 Singapore telecoms - largest national cyber response in Singapore history; zero-day + rootkits used; 100+ defenders mobilized for 11 months
- **NEW**: Salt Typhoon confirmed in Norway - first major European public attribution; Norwegian PST says "most serious security situation since WWII"
- **NEW**: Claude Desktop Extensions zero-click RCE (CVSS 10.0) - malicious Google Calendar event triggers code execution on 10,000+ users; Anthropic declines to fix
- **NEW**: DockerDash vulnerability in Docker's Ask Gordon AI - malicious image metadata enables RCE via MCP context injection; patched in Docker Desktop 4.50.0
- **NEW**: Evolve Mortgage Services breach - INC RANSOM stole 20TB including SSNs, credit histories dating to 2016; notifications began Feb 3
- **UPDATE**: Ivanti EPMM zero-days now linked to ~100 victims including Dutch government and European Commission infrastructure
- **UPDATE**: Warlock ransomware breached SmarterTools' own network using unpatched SmarterMail vulnerabilities

---

## Critical Vulnerabilities

### NEW: Microsoft Patch Tuesday - February 10, 2026

**Released:** Today, February 10, 2026
**Total CVEs:** 63 vulnerabilities (8 critical, 55 important)
**Zero-Days:** 2 actively exploited

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-20805 | Desktop Window Manager | Information Disclosure | High | Actively exploited |
| CVE-2026-20876 | Windows VBS Enclave | Elevation of Privilege | Critical | Actively exploited |
| CVE-2026-20854 | Microsoft Excel | Remote Code Execution | Critical | - |
| CVE-2026-20944 | Microsoft Office | Remote Code Execution | Critical | - |
| CVE-2026-20952 | Windows LSASS | Remote Code Execution | Critical | - |
| CVE-2026-20953 | Windows LSASS | Remote Code Execution | Critical | - |
| CVE-2026-20955 | Microsoft Office | Remote Code Execution | Critical | - |
| CVE-2026-20957 | Microsoft Office | Remote Code Execution | Critical | - |

**CVE-2026-20805** leaks memory addresses via DWM, enabling ASLR bypass for multi-stage attacks. **CVE-2026-20876** allows privilege escalation in Virtualization-Based Security enclaves.

This release also includes all January out-of-band patches (CVE-2026-21509 Office zero-day).

**Action:** Deploy KB5074105 for Windows 11 immediately. Prioritize the two actively exploited zero-days.

**Sources:** [Zecurit Patch Tuesday Analysis](https://zecurit.com/endpoint-management/patch-tuesday/), [Dark Reading](https://www.darkreading.com/application-security/microsoft-fixes-exploited-zero-day-light-patch-tuesday), [SecPod](https://www.secpod.com/blog/three-zero-days-114-flaws-fixed-microsoft-kicks-off-2026-with-a-major-patch-tuesday/)

---

### NEW: Claude Desktop Extensions - Zero-Click RCE (CVSS 10.0)

**Discovered by:** LayerX Security
**CVSS:** 10.0 (no CVE assigned)
**Affected:** 50+ DXT extensions, 10,000+ active users
**Status:** Anthropic has declined to fix; considers behavior by-design

**Attack Mechanism:**
1. Attacker embeds malicious instructions in a Google Calendar event
2. Claude's MCP server reads calendar data as context
3. A benign user prompt (e.g., "take care of it") triggers the AI to interpret and execute the embedded commands
4. MCP Gateway executes commands with full system privileges - no sandboxing

**Why Critical:** Unlike browser extensions that run sandboxed, Claude's MCP servers run with full host privileges. The MCP Gateway cannot distinguish between descriptive metadata and executable instructions ("Meta-Context Injection").

**Mitigation:** Disconnect high-privilege local MCP extensions if also using connectors that ingest untrusted external data (email, calendar).

**Sources:** [LayerX Blog](https://layerxsecurity.com/blog/claude-desktop-extensions-rce/), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/zeroclick-flaw-claude-dxt/), [Cybersecurity News](https://cybersecuritynews.com/claude-desktop-extensions-0-click-vulnerability/), [GBHackers](https://gbhackers.com/0-click-rce-found-in-claude-desktop-extensions/)

---

### NEW: DockerDash - AI Supply Chain Attack via Docker Metadata

**Discovered by:** Noma Security
**Product:** Docker Ask Gordon AI assistant
**Patched:** Docker Desktop 4.50.0 (November 2025)

**How It Works:**
Attackers embed malicious instructions in Docker image LABEL fields. When Ask Gordon AI reads container metadata for context, the MCP Gateway interprets the labels as instructions and executes them. A three-stage chain: Gordon reads metadata -> MCP Gateway processes it -> MCP tools execute commands.

**Impact:** RCE in CLI/cloud environments; data exfiltration in Docker Desktop via embedded outbound requests.

**Significance:** Demonstrates a new class of AI supply chain attacks where poisoned metadata in trusted repositories can compromise AI-assisted development workflows.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/docker-fixes-critical-ask-gordon-ai.html), [SecurityWeek](https://www.securityweek.com/dockerdash-flaw-in-docker-ai-assistant-leads-to-rce-data-theft/), [Noma Security](https://noma.security/noma-labs/dockerdash/), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/dockerdash-weakness-dockers-ask)

---

### UPDATE: Ivanti EPMM Zero-Days - ~100 Victims, European Government Impact

**CVEs:** CVE-2026-1281 (CVSS 9.8), CVE-2026-1340 (CVSS 9.8)
**Previous Coverage:** Feb 6 report (initial disclosure)

**What's New:**
- Shadowserver identified **86 confirmed compromised instances**, with total victims approaching ~100
- **Dutch government agencies** confirmed among victims
- **European Commission** infrastructure affected
- 1,600 exposed EPMM instances worldwide
- Exploitation attempts surging: 130+ unique IPs within 24 hours of disclosure, with 58% directly targeting these CVEs
- Dominant payloads: reverse shells over port 443 and webshell deployment

**Permanent Fix:** Expected in EPMM version 12.8.0.0 (Q1 2026); temporary patches available now.

**Sources:** [Rapid7](https://www.rapid7.com/blog/post/etr-critical-ivanti-endpoint-manager-mobile-epmm-zero-day-exploited-in-the-wild-eitw-cve-2026-1281-1340/), [SOCRadar](https://socradar.io/blog/cve-2026-1281-1340-ivanti-epmm-0day-rce/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/ivanti-warns-of-two-epmm-flaws-exploited-in-zero-day-attacks/)

---

### CISA KEV Deadlines This Week

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20045 | Cisco Unified CM/Webex | **Tomorrow (Feb 11)** |
| CVE-2025-31125 | Vite Vitejs | **Feb 12 (Wed)** |
| CVE-2025-34026 | Versa Concerto | **Feb 12 (Wed)** |
| CVE-2025-68645 | Zimbra ZCS | **Feb 12 (Wed)** |
| CVE-2026-21509 | Microsoft Office | Feb 16 |
| CVE-2019-19006/CVE-2025-64328 | FreePBX/Sangoma | Feb 24 |
| CVE-2021-39935 | GitLab CE/EE | Feb 24 |
| CVE-2026-24423 | SmarterTools SmarterMail | Feb 26 |
| CVE-2025-11953 | React Native CLI | Feb 26 |

---

## Threat Actors

### NEW: UNC3886 (China) - Singapore Telecom Sector Espionage

**Threat Actor:** UNC3886 (China-nexus)
**Targets:** All four major Singapore telecom operators - M1, SIMBA Telecom, Singtel, StarHub
**Disclosed:** February 10, 2026
**Operation Duration:** 11+ months of containment

**Attack Details:**
- Used zero-day exploits and custom rootkits to penetrate telecom infrastructure
- Stole technical reconnaissance data (network topology, system configurations)
- No customer data compromised; no service disruption

**Singapore's Response - Operation Cyber Guardian:**
- Largest multi-agency cyber response in Singapore history
- 100+ cyber defenders from multiple government agencies
- CSA (Cyber Security Agency of Singapore) led the operation
- Minister Josephine Teo made the public disclosure

**Significance:** UNC3886 is the same group known for exploiting VMware ESXi and Fortinet zero-days. Targeting all four national telecoms simultaneously represents a strategic intelligence collection operation against critical communications infrastructure.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/china-linked-unc3886-targets-singapore.html), [The Record](https://therecord.media/singapore-attributes-telecoms-hacks-unc3886), [CSA Singapore](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/), [Fintech Singapore](https://fintechnews.sg/126113/security/singapore-telco-cyberattack-unc3886/)

---

### NEW: Salt Typhoon Confirmed in Norway - First Major European Attribution

**Threat Actor:** Salt Typhoon (China-nexus)
**Targets:** Norwegian organizations (companies, likely telecoms/critical infrastructure)
**Disclosed:** February 6-10, 2026
**Source:** Norwegian Police Security Service (PST) annual threat assessment

**Details:**
- Salt Typhoon exploited vulnerable routers, firewalls, and VPN appliances
- Gained persistent access with minimal on-host footprint
- PST Director General Beate Gangas stated Norway faces "its most serious security situation since World War II"

**Why This Matters:**
- First major European public confirmation of Salt Typhoon operations
- Salt Typhoon previously known primarily for US telecom breaches (AT&T, Verizon, T-Mobile)
- Demonstrates the campaign's global scope extends well beyond North America
- European governments can no longer treat Salt Typhoon as a US-centric problem

**Sources:** [The Record](https://therecord.media/norawy-intelligence-discloses-salt-typhoon-attacks), [TechCrunch](https://techcrunch.com/2026/02/06/chinas-salt-typhoon-hackers-broke-into-norwegian-companies/), [BankInfoSecurity](https://www.bankinfosecurity.com/norway-says-salt-typhoon-hackers-hit-vulnerable-systems-a-30721), [IT Pro](https://www.itpro.com/security/cyber-attacks/salt-typhoon-norway-cyber-espionage-warning)

---

### NEW: VoidLink - Multi-Cloud Linux Malware Framework

**Discovered by:** Ontinue researchers
**Platform:** Linux-based
**Capabilities:**

- Persists across enterprise and multi-cloud environments (AWS, Azure, GCP, Alibaba, Tencent)
- Credential theft and system fingerprinting
- Container escape capabilities
- Kernel-level hiding
- Encrypted traffic mimicking normal web activity

**Significance:** Purpose-built for modern cloud infrastructure; designed to move laterally across cloud providers while evading detection.

**Source:** [CISO Series](https://cisoseries.com/cybersecurity-news-february-10-2026/)

---

## Malware & Ransomware

### NEW: Warlock Ransomware Breaches SmarterTools

**Victim:** SmarterTools (vendor of SmarterMail)
**Threat Actor:** Warlock ransomware group
**Attack Vector:** Exploited two critical SmarterMail vulnerabilities on an unpatched SmarterTools server

**Details:**
- Warlock used the same CVE-2026-24423 (unauthenticated RCE) and an authentication bypass flaw to breach SmarterTools' own network
- Compromised approximately a dozen Windows machines
- Both vulnerabilities were fixed in SmarterMail build 9511 (January 15, 2026) - but SmarterTools had an unpatched server

**Irony:** The vendor whose product had critical vulnerabilities was itself breached through those same vulnerabilities.

**Source:** [CISO Series](https://cisoseries.com/cybersecurity-news-february-10-2026/)

---

### NEW: Iron Mountain / Everest Ransomware - Limited Impact

**Victim:** Iron Mountain (information management)
**Threat Actor:** Everest ransomware group
**Claimed:** 1.4 TB stolen
**Actual Impact:** Limited to a single folder on a public-facing file-sharing server

**Iron Mountain's Investigation:**
- A single compromised credential accessed a specific folder on a third-party file-sharing site
- Contents limited to marketing materials
- No customer confidential or sensitive information involved
- No ransomware deployed; core infrastructure unaffected

**Assessment:** Despite Everest's dramatic claims, the actual breach was minimal. This demonstrates a growing trend of ransomware groups inflating breach claims for reputational leverage.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/iron-mountain-data-breach-mostly-limited-to-marketing-materials/), [SC Media](https://www.scworld.com/brief/iron-mountain-reports-limited-impact-from-everest-gang-breach), [Iron Mountain Statement](https://www.ironmountain.com/about-us/media-center/press-releases/2026/february/iron-mountain-statement-cybersecurity-issue)

---

### NEW: 0APT - Likely Fake Ransomware Operation

**Group:** 0APT (appeared January 28, 2026)
**Claims:** 71 organizations compromised in 48 hours
**Assessment:** Likely a scam / fake ransomware group

**Evidence of Fraud:**
- Leak site source code contains developer comments in Hindi/Urdu
- Data leak files found to be empty shells or infinite streams of random data
- No credible proof of compromise for claimed victims
- Targeted Epworth HealthCare (Australia) claiming 920GB stolen; Epworth found no evidence of breach after investigation
- Phishing kits mimic Okta/SSO portals (myadyensso.com, weworksso.com, cnainsurancesso.com)

**Why It Matters:** Even fake ransomware groups cause real harm - organizations spend resources investigating claims, and the threat of publication creates pressure to pay without verification.

**Sources:** [SOCRadar](https://socradar.io/blog/dark-web-profile-0apt-ransomware/), [Blackswan Cybersecurity](https://blackswan-cybersecurity.com/threat-advisory-0apt-ransomware-group-february-2-2026/), [CtrlAltNod](https://www.ctrlaltnod.com/news/new-ransomware-group-0apt-hits-71-orgs-in-48-hours/), [Cyber News Centre](https://www.cybernewscentre.com/9th-february-2026-cyber-update-fake-ransomware-group-targets-epworth-healthcare-in-data-extortion-bluff/)

---

## Data Breaches

### NEW: Evolve Mortgage Services - 20TB Stolen (INC RANSOM)

**Victim:** Evolve Mortgage Services / Evolve Bank & Trust
**Threat Actor:** INC RANSOM
**Data Stolen:** 20 TB (including 2 TB of sensitive databases)
**Notification Date:** February 3, 2026

**Data Exposed:**
- Social Security numbers
- Client ID scans
- Home and work addresses
- Personal and work phone numbers
- Full credit histories and confidential PII forms dating back to 2016
- Evolve account numbers, dates of birth

**Affected:** Personal, mortgage, trust, and small business banking customers, plus Open Banking partner customers

**Remediation:** Evolve offering 2 years free credit monitoring and identity theft protection

**Sources:** [ClassAction.org](https://www.classaction.org/data-breach-lawsuits/evolve-mortgage-services-february-2026), [ClaimDepot](https://www.claimdepot.com/data-breach/evolve-mortgage-services-2026), [Evolve Statement](https://www.getevolved.com/cybersecurity-incident/)

---

### UPDATE: Conduent Breach Continues to Expand

Previous reports covered the 25.9M+ figure (Feb 6). The breach has now been confirmed to affect at least 15.4 million in Texas alone. Total count may reach dozens of millions. Credit monitoring deadline: March 31, 2026.

**Source:** [TechCrunch](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)

---

## Vendor Advisories

### Microsoft
- **Patch Tuesday released TODAY** - 63 CVEs, 8 critical, 2 actively exploited zero-days
- Deploy KB5074105 for Windows 11 immediately
- Includes all January OOB patches

### Cisco
- **CVE-2026-20045 deadline TOMORROW** (Feb 11) - Unified CM/Webex RCE
- Federal agencies must have patches applied

### Ivanti
- EPMM temporary patches available; permanent fix (v12.8.0.0) expected Q1 2026
- ~100 confirmed victims and growing

### Docker
- DockerDash patched in Desktop 4.50.0; verify AI assistant settings

### Anthropic
- Claude Desktop Extensions zero-click RCE disclosed; no fix planned
- Users must manually restrict MCP extension permissions

---

## Recommended Actions

### Immediate Priority (Next 24 Hours)

1. **Microsoft Patch Tuesday** - Deploy KB5074105 today; prioritize CVE-2026-20805 and CVE-2026-20876 (both actively exploited)
2. **Cisco UCM/Webex** - CISA deadline is **tomorrow, February 11** for CVE-2026-20045
3. **Ivanti EPMM** - Apply temporary patches if not already done; ~100 victims and exploitation surging
4. **Claude Desktop** - Audit MCP extension configurations; disconnect high-privilege extensions connected to external data sources

### High Priority (This Week)

5. **Vite/Versa/Zimbra** - Three CISA KEV deadlines on **February 12**
6. **Docker Desktop** - Verify updated to 4.50.0+ to address DockerDash
7. **Evolve Bank customers** - If using Evolve services, verify breach notification and credit monitoring enrollment
8. **SmarterMail** - Ensure upgraded to build 9511; even the vendor was breached through these flaws

### Threat Hunting

9. **Telecom infrastructure** - Hunt for UNC3886 indicators; focus on edge devices (routers, firewalls, VPN appliances)
10. **Salt Typhoon indicators** - European organizations should actively hunt for Salt Typhoon TTPs; no longer a US-only threat
11. **Docker image metadata** - Audit Docker images for suspicious LABEL fields that could contain injection payloads
12. **AI tool permissions** - Review all AI assistant MCP configurations for excessive privilege grants

### Strategic

13. **AI supply chain security** - Both Claude DXT and DockerDash vulnerabilities highlight that AI assistants with MCP/tool access create new attack surfaces; establish governance for AI tool permissions
14. **Fake ransomware assessment** - Before paying ransom demands, verify the threat actor's legitimacy; 0APT demonstrates groups fabricating breach claims for profit
15. **Edge device security** - Salt Typhoon and UNC3886 both target network edge devices; align with CISA BOD 26-02 principles regardless of sector

---

## Sources

- [Zecurit - February Patch Tuesday](https://zecurit.com/endpoint-management/patch-tuesday/)
- [Dark Reading - Microsoft Patch Tuesday](https://www.darkreading.com/application-security/microsoft-fixes-exploited-zero-day-light-patch-tuesday)
- [The Hacker News - UNC3886 Singapore](https://thehackernews.com/2026/02/china-linked-unc3886-targets-singapore.html)
- [The Record - Singapore Telecoms](https://therecord.media/singapore-attributes-telecoms-hacks-unc3886)
- [CSA Singapore - Operation Cyber Guardian](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [The Record - Norway Salt Typhoon](https://therecord.media/norawy-intelligence-discloses-salt-typhoon-attacks)
- [TechCrunch - Salt Typhoon Norway](https://techcrunch.com/2026/02/06/chinas-salt-typhoon-hackers-broke-into-norwegian-companies/)
- [BankInfoSecurity - Norway](https://www.bankinfosecurity.com/norway-says-salt-typhoon-hackers-hit-vulnerable-systems-a-30721)
- [LayerX - Claude DXT RCE](https://layerxsecurity.com/blog/claude-desktop-extensions-rce/)
- [Infosecurity Magazine - Claude DXT](https://www.infosecurity-magazine.com/news/zeroclick-flaw-claude-dxt/)
- [The Hacker News - DockerDash](https://thehackernews.com/2026/02/docker-fixes-critical-ask-gordon-ai.html)
- [SecurityWeek - DockerDash](https://www.securityweek.com/dockerdash-flaw-in-docker-ai-assistant-leads-to-rce-data-theft/)
- [Noma Security - DockerDash](https://noma.security/noma-labs/dockerdash/)
- [Rapid7 - Ivanti EPMM](https://www.rapid7.com/blog/post/etr-critical-ivanti-endpoint-manager-mobile-epmm-zero-day-exploited-in-the-wild-eitw-cve-2026-1281-1340/)
- [SOCRadar - Ivanti EPMM](https://socradar.io/blog/cve-2026-1281-1340-ivanti-epmm-0day-rce/)
- [BleepingComputer - Iron Mountain](https://www.bleepingcomputer.com/news/security/iron-mountain-data-breach-mostly-limited-to-marketing-materials/)
- [Iron Mountain Statement](https://www.ironmountain.com/about-us/media-center/press-releases/2026/february/iron-mountain-statement-cybersecurity-issue)
- [SOCRadar - 0APT Profile](https://socradar.io/blog/dark-web-profile-0apt-ransomware/)
- [Blackswan - 0APT Advisory](https://blackswan-cybersecurity.com/threat-advisory-0apt-ransomware-group-february-2-2026/)
- [ClassAction.org - Evolve Mortgage](https://www.classaction.org/data-breach-lawsuits/evolve-mortgage-services-february-2026)
- [Evolve Statement](https://www.getevolved.com/cybersecurity-incident/)
- [CISO Series - Feb 10 2026](https://cisoseries.com/cybersecurity-news-february-10-2026/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Vulnerability Summary Feb 2 Week](https://www.cisa.gov/news-events/bulletins/sb26-040)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 6-9, 2026 reports:

- CVE-2026-1731 BeyondTrust RS/PRA (CVSS 9.9, pre-auth RCE)
- CVE-2026-24858 Fortinet FortiCloud SSO (auth bypass)
- CVE-2026-24423 SmarterMail (ransomware exploitation)
- CVE-2026-22778 vLLM (RCE via video URL)
- CVE-2026-25049/21858/1470/0863 n8n (16 total vulns, 6 critical)
- CVE-2025-40551 SolarWinds WHD (deadline passed Feb 6)
- CVE-2025-22224/22225/22226 VMware ESXi chain
- CVE-2026-21509 Microsoft Office zero-day / APT28 Operation Neusploit
- CVE-2026-20045 Cisco UCM/Webex zero-day
- CVE-2025-40602 SonicWall SMA1000 chained zero-day
- CVE-2025-55182 React2Shell NGINX hijacking
- CVE-2025-11953 React Native CLI command injection
- Apple iOS 26.2 WebKit zero-days
- Chrome 143 security update
- CISA BOD 26-02 edge device directive
- TGR-STA-1030 Shadow Campaigns (37 countries)
- Signal account hijacking campaign (Germany/Europe)
- Google IPIDEA residential proxy disruption
- Chinese hackers Congressional staff emails
- Two US cybersecurity pros guilty as BlackCat affiliates
- Amaranth-Dragon SE Asia espionage
- AI-powered law firm cloning campaign (150+ domains)
- Panera Bread 5.1M records (ShinyHunters)
- Chat & Ask AI 300M messages exposed
- Conduent breach (25.9M+ - updated total above)
- Harvard/UPenn breach (ShinyHunters)
- Illinois DHS breach (700K)
- Spain Ministry of Science breach
- AT&T breach data resurface
- Under Armour, Nike/WorldLeaks, Crunchbase, Target breaches
- Substack, Reddit breaches
- Hawk Law Group (INC ransomware)
- Sedgwick Government Solutions (TridentLocker)
- FTC ransomware report to Congress
- Energy sector 60%+ ransomware surge

---

*Report generated: 2026-02-10*
*Next report: 2026-02-11*
*Classification: TLP:CLEAR*
