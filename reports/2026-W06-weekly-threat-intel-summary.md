# Weekly Threat Intelligence Summary
**Week:** 6 (February 2 - February 8, 2026)
**Classification:** TLP:CLEAR
**Report ID:** CTI-WEEKLY-2026-W06

---

## Executive Summary

### Week at a Glance

| Metric | Count |
|--------|-------|
| Critical CVEs (CVSS 9+) | 12 |
| Zero-Days | 5 |
| Active Exploits (CISA KEV) | 8 |
| Ransomware Incidents | 6+ |
| Data Breaches | 7 |
| Vendor Advisories | 10 |
| CISA KEV Additions | 6 |
| Nations Targeted by Espionage | 37+ |

### Key Takeaways

1. **Edge devices and remote access tools are the primary attack surface** - BeyondTrust (CVE-2026-1731, CVSS 9.9), Fortinet FortiCloud SSO (CVE-2026-24858, CVSS 9.4), SonicWall SMA1000 (chained zero-day), and CISA's new BOD 26-02 ordering removal of unsupported edge devices all converge on the same theme: perimeter infrastructure is under siege.

2. **Exploitation speed continues accelerating** - APT28 weaponized CVE-2026-21509 within 24 hours of disclosure. Industry-wide, 29% of KEVs in 2025 were exploited on or before CVE publication day (up from 24% in 2024). The patch-to-exploit window is effectively zero for high-value targets.

3. **Nation-state espionage at unprecedented scale** - TGR-STA-1030 (Asia-based) compromised 70+ organizations across 37 countries including parliaments and national law enforcement. Amaranth-Dragon (China-nexus) targeted SE Asian governments. APT28 (Russia) ran Operation Neusploit across 8+ NATO-aligned countries.

4. **Insider threat from cybersecurity professionals** - Two US cybersecurity professionals (a ransomware negotiator and an incident response manager) pleaded guilty as ALPHV/BlackCat affiliates, highlighting a disturbing trust exploitation vector.

5. **Ransomware evolution: data theft over encryption** - 2026 marks the shift to pure exfiltration attacks, with 8,000+ organizations targeted in 2025 (up 33% from 2024). Conduent breach affecting 25.9M+ Americans exemplifies the mass-scale impact.

---

## Top Vulnerabilities of the Week

### Most Critical (CISA KEV / Active Exploitation)

| Rank | CVE ID | Product | CVSS | Status | Day(s) |
|------|--------|---------|------|--------|--------|
| 1 | CVE-2026-1731 | BeyondTrust RS/PRA | 9.9 | Pre-auth RCE; ~8,500 on-prem exposed | Feb 8 |
| 2 | CVE-2026-24858 | Fortinet FortiCloud SSO | 9.4 | Auth bypass; actively exploited since Jan 20 | Feb 8 |
| 3 | CVE-2026-24423 | SmarterMail | Critical | Unauth RCE; ransomware exploitation confirmed | Feb 6 |
| 4 | CVE-2026-22778 | vLLM | 9.8 | AI server RCE via malicious video URL | Feb 6 |
| 5 | CVE-2026-25049 | n8n | 9.4 | Sandbox escape; 4th critical flaw in 2 months | Feb 6 |
| 6 | CVE-2025-40551 | SolarWinds WHD | 9.8 | Unauth RCE; CISA deadline passed Feb 6 | Feb 5-6 |
| 7 | CVE-2026-21509 | Microsoft Office | 7.8 | Zero-day; APT28 weaponized in 24 hours | Feb 5 |
| 8 | CVE-2025-22224/25/26 | VMware ESXi | 9.3/8.2/7.1 | VM escape chain; ransomware confirmed | Feb 5 |

### High Impact (CVSS 9+)

| CVE ID | Product | CVSS | Patch Status |
|--------|---------|------|--------------|
| CVE-2026-21858 | n8n | 10.0 | Patched (1.123.17 / 2.5.2) |
| CVE-2025-55182 | React Server Components | 10.0 | Patched |
| CVE-2026-1470 | n8n | 9.9 | Patched |
| CVE-2026-24858 | Fortinet FortiCloud SSO | 9.4 | FortiOS 7.4.11 |
| CVE-2025-40602 | SonicWall SMA1000 | Chained to 9.8 | Patched |
| CVE-2025-11953 | React Native CLI | High | KEV deadline Feb 26 |

### Notable Trends

- **n8n had 4 critical CVEs in under two months** (CVSS 10.0, 9.9, 9.4, 8.5) - suggesting systemic security architecture issues
- **AI infrastructure emerging as attack surface** - vLLM CVE-2026-22778 targets the most widely deployed open-source LLM inference engine
- **Network edge devices dominate** - 5 of the top 8 vulnerabilities target perimeter/remote access products

---

## Exploits & Zero-Days Roundup

### Zero-Days Exploited This Week

| CVE ID | Product | Discovery/Exploit Date | Status |
|--------|---------|----------------------|--------|
| CVE-2026-21509 | Microsoft Office | Jan 26 OOB patch; APT28 exploiting Jan 29+ | Patched |
| CVE-2026-24858 | Fortinet FortiCloud SSO | Exploited since ~Jan 20 | Patched (FortiOS 7.4.11) |
| CVE-2025-43529 / CVE-2025-14174 | Apple iOS/iPadOS WebKit | "Extremely sophisticated" targeted attacks | Patched (iOS 26.2) |
| CVE-2025-40602 | SonicWall SMA1000 | Chained with CVE-2025-23006 for root RCE | Patched |
| CVE-2026-1731 | BeyondTrust RS/PRA | Discovered Jan 31; SaaS patched Feb 2 | On-prem needs manual patch |

### Significant Exploit Campaigns

- **React2Shell NGINX Hijacking** (CVE-2025-55182): 1,083 unique IPs exploiting React Server Components to inject NGINX configs; targets Asian TLDs; no malicious binaries - pure config injection makes detection difficult
- **APT28 Operation Neusploit** (CVE-2026-21509): RTF-based exploit targeting NATO allies; multi-stage payloads including MiniDoor, NotDoor, BEARDSHELL, and PixyNetLoader
- **SmarterMail Ransomware Exploitation** (CVE-2026-24423): Active ransomware groups targeting self-hosted email servers via unauthenticated ConnectToHub API

### Exploitation Speed Analysis

| Vulnerability | Time to Weaponization |
|--------------|----------------------|
| CVE-2026-21509 (Office) | <24 hours post-disclosure |
| CVE-2025-8088 (WinRAR) | 10 days post-disclosure (Amaranth-Dragon) |
| CVE-2026-24858 (Fortinet) | Exploited before patch available (true zero-day) |

**Industry Trend:** 29% of KEVs exploited on or before CVE publication date (VulnCheck), up from 24% in 2024. Network edge devices remain the #1 targeted technology category.

---

## Ransomware & Malware Activity

### Weekly Statistics

- **267 ransomware victims** in February (through Feb 8), **1,078 YTD**
- **8,000+ organizations targeted** in 2025 (Emsisoft), up 33% from 2024
- Active groups increased ~30% compared to 2024
- Global ransomware cost projection for 2026: **$74 billion**

### Most Active Groups This Week

| Group | Notable Activity | Sectors |
|-------|-----------------|---------|
| Safepay | Conduent breach (25.9M+ Americans, 8.5TB stolen) | Government services, healthcare |
| ShinyHunters | Harvard/UPenn data published (2.2M+ records) | Education |
| INC | Hawk Law Group (client litigation data) | Legal |
| ALPHV/BlackCat | Two affiliates pleaded guilty | Cross-sector |
| 0APT | Newly emerged RaaS (Jan 28); assessed as low risk | TBD |

### Key Ransomware Trends

1. **Data exfiltration replacing encryption** - Faster, cheaper, harder to detect; groups like Everest rely primarily on data-leak extortion
2. **Insider recruitment accelerating** - RaaS operators targeting English-speaking corporate insiders
3. **Geographic diversification** - 2026 marks first year new ransomware groups outside Russia outnumber those within
4. **Bundled RaaS services** - Chaos group now provides DDoS to all affiliates
5. **Energy sector 60%+ surge** - Cyfirma reports significant increase in ransomware targeting energy/utilities

### Malware Campaigns

- **Amaranth Loader** - New China-nexus loader (APT-41 ecosystem) shares code with DodgeBox, Dustpan, Dusttrap
- **Havoc Framework** - Open-source C2 adopted by Amaranth-Dragon for SE Asia espionage
- **MiniDoor/NotDoor/BEARDSHELL** - APT28's toolkit for Operation Neusploit email theft and backdoor access

---

## Threat Actor Intelligence

### APT / Nation-State Activity

| Actor | Attribution | Activity | Targets | Days Reported |
|-------|-------------|----------|---------|---------------|
| TGR-STA-1030 | Asia (state-aligned) | Shadow Campaigns - 70+ orgs in 37 countries | Parliaments, law enforcement, finance ministries, telecom | Feb 8 |
| APT28 (Fancy Bear) | Russia (GRU) | Operation Neusploit - CVE-2026-21509 exploitation | NATO allies: Ukraine, Poland, Slovakia, Romania, Turkey, Greece, UAE | Feb 5 |
| Amaranth-Dragon | China (APT-41 linked) | WinRAR CVE-2025-8088 exploitation | SE Asian governments: Cambodia, Thailand, Laos, Indonesia, Singapore, Philippines | Feb 6 |
| State-backed (suspected Russia) | Russia (suspected) | Signal account hijacking | European politicians, military, diplomats, journalists | Feb 8 |
| Infy (Prince of Persia) | Iran | Telegram C2 with Foudre v34, Tonnerre v17/v50 | Global cyberespionage | Feb 5 (appendix) |
| Phantom Taurus | China | NET-STAR malware suite | Africa, Middle East, Asia government entities | Feb 5 (appendix) |

### Emerging TTPs

- **Signal social engineering** - No malware, no technical exploits; pure social engineering impersonating platform support to link attacker devices
- **NGINX config injection** (React2Shell) - No binaries deployed; valid NGINX configs used for traffic hijacking, evading traditional detection
- **FortiCloud SSO abuse** - Cloud authentication bypass enabling cross-tenant device access
- **AI infrastructure targeting** - vLLM video URL exploitation chain (info leak + heap overflow)

### Campaign Evolution Tracking

| Campaign | Start of Week Status | End of Week Status |
|----------|--------------------|--------------------|
| Operation Neusploit | Initial disclosure (Feb 4-5) | Full TTP analysis published; 60+ Ukrainian targets confirmed |
| Conduent breach | Initial notification | Scope expanded to 25.9M+ victims; top-5 US healthcare breach |
| n8n vulnerabilities | 3 critical CVEs known | 4th critical CVE (CVE-2026-25049) disclosed |
| React2Shell | Campaign period Jan 26 - Feb 2 | Full Datadog analysis published; 1,083 source IPs identified |

---

## Data Breaches & Incidents

### Major Breaches

| Organization | Records/Impact | Data Type | Date Disclosed |
|--------------|---------------|-----------|----------------|
| Conduent | 25.9M+ Americans | SSNs, medical data, gov benefits | Feb 5 (expanded scope) |
| Harvard University | 115K+ (AAD) | Alumni data, wealth bands, family relationships | Feb 4 |
| University of Pennsylvania | 1M+ | University records | Feb 4 |
| Under Armour | 72.7M accounts | Customer data | Feb 5 (appendix) |
| AT&T | 73M (repackaged) | Enriched customer profiles, SSNs, emails | Feb 2 (resurfaced) |
| Substack | Undisclosed | Email addresses, phone numbers | Feb 5 |
| Reddit | Internal docs/code | Employee credentials, internal dashboards | Feb 5 |
| Nike/WorldLeaks | 1.4TB | Corporate data | Feb 5 (appendix) |
| Crunchbase | 2M+ records | Business data | Feb 5 (appendix) |
| Target | 860 GB | Source code | Feb 5 (appendix) |

### Breach Patterns

- **Education sector targeted** - Harvard and UPenn both hit via vishing (voice phishing), suggesting coordinated campaign against universities
- **Data repackaging** - AT&T's 2024 breach data resurfacing in enriched, cross-referenced form - old breaches creating new risks
- **Government service providers** - Conduent breach highlights systemic risk of centralized govtech data processors
- **Social graph exposure** - Harvard breach uniquely dangerous because it maps alumni wealth bands, family relationships, and donation patterns

---

## Vendor Advisory Highlights

### Microsoft
- **OOB patch** for CVE-2026-21509 (Office zero-day) released Jan 26
- **Patch Tuesday** February 10 upcoming - KB5074105 for Windows 11; will include all January OOB fixes
- January cycle addressed 112-114 vulnerabilities including CVE-2026-20805 (DWM zero-day)

### BeyondTrust
- CVE-2026-1731 (CVSS 9.9) - Pre-auth RCE in Remote Support and PRA
- SaaS patched automatically Feb 2; on-prem requires manual update

### Fortinet
- CVE-2026-24858 (CVSS 9.4) - FortiCloud SSO authentication bypass
- Global SSO disabled Jan 26, reinstated Jan 27 with mitigations
- FortiOS 7.4.11 released; FortiManager/FortiAnalyzer patches forthcoming

### Apple
- iOS/iPadOS 26.2 patches two WebKit zero-days (CVE-2025-43529, CVE-2025-14174)
- Only ~4.6% of iPhones running patched version

### Google
- Chrome 143 security update addresses V8 type confusion (CVE-2026-1862) and heap corruption (CVE-2026-1861)

### n8n
- Versions 1.123.17 and 2.5.2 address fourth critical vulnerability in two months
- Organizations should evaluate whether n8n's security posture justifies continued use in production

### SmarterTools
- SmarterMail build 9511 patches CVE-2026-24423 (unauth RCE)
- Active ransomware exploitation of unpatched instances

### SonicWall
- SMA1000 versions 12.4.3-03245+ and 12.5.0-02283+ patch chained zero-day

### SolarWinds
- Web Help Desk 2026.1 patches CVE-2025-40551 (CISA deadline passed Feb 6)

### CISA
- BOD 26-02 issued Feb 5 - edge device lifecycle management directive
- 6 new KEV additions across the week

---

## Weekly Trends & Analysis

### Attack Vector Trends

| Vector | Direction | Evidence |
|--------|-----------|---------|
| Network edge device exploitation | Sharply increasing | BeyondTrust, Fortinet, SonicWall, n8n all targeted; CISA BOD 26-02 response |
| Social engineering (vishing/phishing) | Increasing | Signal hijacking campaign, Harvard/UPenn vishing, APT28 RTF lures |
| Configuration injection | Emerging | React2Shell NGINX hijacking - no malware, no binaries |
| AI infrastructure targeting | Emerging | vLLM CVE-2026-22778 - first major AI-serving-infrastructure RCE |
| Data exfiltration (no encryption) | Accelerating | Conduent (8.5TB), ShinyHunters publish-on-refusal model |
| Cloud authentication abuse | Emerging | Fortinet FortiCloud SSO cross-tenant bypass |

### Industry Targeting

| Sector | Threat Activity |
|--------|----------------|
| Government | TGR-STA-1030 (37 countries), APT28, Amaranth-Dragon, Conduent breach |
| Healthcare | Conduent (25.9M), Watson Clinic settlement, energy/utilities surge |
| Education | Harvard, UPenn (ShinyHunters vishing) |
| Legal | Hawk Law Group (INC ransomware, litigation data) |
| Energy/Utilities | 60%+ ransomware surge (Cyfirma) |
| Technology | Under Armour, AT&T, Substack, Reddit, Target, n8n/vLLM vulnerabilities |

### Geographic Patterns

- **Global espionage**: TGR-STA-1030 hit 37 countries; reconnaissance against 155
- **NATO-focused**: APT28 Operation Neusploit targeted 8+ NATO-aligned nations
- **SE Asia**: Amaranth-Dragon targeted Cambodia, Thailand, Laos, Indonesia, Singapore, Philippines
- **Europe**: Signal phishing campaign targeting German and European high-value individuals
- **United States**: 2/3 of all ransomware incidents; Conduent breach is potentially top-5 US healthcare breach

### Emerging Concerns

1. **AI as attack surface** - vLLM vulnerability demonstrates that AI inference infrastructure is now a viable exploitation target
2. **Cybersecurity professional insider threat** - BlackCat affiliate case reveals how IR/negotiation roles can be weaponized
3. **Cloud SSO as single point of failure** - Fortinet SSO bypass enabled cross-tenant access across multiple product lines
4. **Breach data compounding** - AT&T data repackaging shows how old breaches gain new value through enrichment
5. **Edge device obsolescence crisis** - CISA BOD 26-02 acknowledges the systemic risk of unsupported network infrastructure

---

## Consolidated Recommendations

### Immediate Priority (This Weekend / Monday)

1. **Patch BeyondTrust RS/PRA** - CVE-2026-1731 (CVSS 9.9); on-prem instances require manual update; ~8,500 exposed
2. **Upgrade Fortinet products** - FortiOS 7.4.11 for CVE-2026-24858; audit for unauthorized admin accounts created since Jan 20
3. **Prepare for Microsoft Patch Tuesday** (Feb 10) - Pre-stage KB5074105 deployment; includes all January OOB fixes
4. **Patch Cisco UCM/Webex** - CVE-2026-20045 CISA deadline is **February 11**
5. **Update vLLM to 0.14.1** - CVE-2026-22778 requires no authentication to exploit

### This Week

1. **Patch Vite, Versa Concerto, Zimbra ZCS** - CISA deadline **February 12** for all three
2. **Brief executives on Signal security** - Review linked devices, enable Registration Lock, warn about support impersonation
3. **Audit n8n deployments** - Four critical CVEs in two months; evaluate risk of continued use; update to 1.123.17 or 2.5.2
4. **Hunt for NGINX config injection** - Look for unauthorized `proxy_pass` directives (React2Shell indicators)
5. **Review BeyondTrust access logs** - Check for pre-auth exploitation attempts
6. **Begin edge device inventory** - Per CISA BOD 26-02 guidance (applies to federal, recommended for all)

### Strategic (30-Day)

1. **Edge device lifecycle program** - Implement systematic tracking of EOL dates for all network edge infrastructure; plan replacements before vendor support ends
2. **Zero-day response SLA review** - With 29% of KEVs exploited on publication day, evaluate whether patching SLAs match actual exploitation timelines
3. **Insider threat controls** - Review access controls and conflict-of-interest policies for incident response and ransomware negotiation staff
4. **AI infrastructure hardening** - Audit all LLM/ML inference endpoints for authentication enforcement; vLLM exploit demonstrates the risk
5. **Cloud SSO security review** - Assess single-sign-on configurations across all cloud platforms for cross-tenant isolation
6. **Breach data monitoring** - Implement monitoring for enriched/repackaged breach data affecting your organization (AT&T pattern)

---

## Report Sources

### Daily Reports Analyzed

| Date | Filename |
|------|----------|
| Feb 5, 2026 | `2026-02-05-threat-intel-report.md` |
| Feb 6, 2026 | `2026-02-06-threat-intel-report.md` |
| Feb 8, 2026 | `2026-02-08-threat-intel-report.md` |

### External Trend Sources

- [TCE Weekly Roundup: February 2026](https://thecyberexpress.com/tce-weekly-roundup-february-2026/)
- [Help Net Security - Week in Review](https://www.helpnetsecurity.com/2026/02/01/week-in-review-microsoft-fixes-exploited-office-zero-day-fortinet-patches-forticloud-sso-flaw/)
- [Applied Tech - This Week in Cybersecurity Feb 6](https://www.appliedtech.us/resource-hub/this-week-in-cybersecurity-feb6-2026/)
- [Acumen Cyber - CTI Digest Week 5](https://acumencyber.com/cyber-threat-intelligence-digest-february-2026-week-5)
- [CYFIRMA - Weekly Intelligence Report Feb 6](https://www.cyfirma.com/news/weekly-intelligence-report-06-february-2026/)
- [VulnCheck - State of Exploitation 2026](https://www.vulncheck.com/blog/state-of-exploitation-2026)
- [Recorded Future - Ransomware Tactics 2026](https://www.recordedfuture.com/blog/ransomware-tactics-2026)
- [Purple Ops - Ransomware Victims Report Feb 8](https://www.purple-ops.io/cybersecurity-threat-intelligence-blog/daily-ransomware-report-2-8-2026/)
- [Cyble - Ransomware Groups 2025/2026 Trends](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)
- [VikingCloud - Ransomware Statistics 2026](https://www.vikingcloud.com/blog/ransomware-statistics)
- [Morphisec - Pure Exfiltration Attacks](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Check Point - Cyber Security Report 2026](https://research.checkpoint.com/2026/cyber-security-report-2026/)
- [WEF - Global Cybersecurity Outlook 2026](https://www.weforum.org/publications/global-cybersecurity-outlook-2026/)
- [Eye Security - Threat Landscape 2026](https://www.eye.security/blog/cyber-threat-landscape-outpacing-threat-actors-building-resilience)

---

## Appendix: Full CVE List

All CVEs mentioned this week:

| CVE ID | Product | CVSS | Day(s) Reported | Status |
|--------|---------|------|-----------------|--------|
| CVE-2026-1731 | BeyondTrust RS/PRA | 9.9 | Feb 8 | Pre-auth RCE; SaaS patched, on-prem manual |
| CVE-2026-24858 | Fortinet FortiCloud SSO | 9.4 | Feb 8 | Auth bypass; actively exploited; CISA KEV |
| CVE-2026-24423 | SmarterMail | Critical | Feb 6 | Unauth RCE; ransomware exploitation; CISA KEV |
| CVE-2026-22778 | vLLM | 9.8 | Feb 6 | RCE via video URL; patched in 0.14.1 |
| CVE-2026-25049 | n8n | 9.4 | Feb 6 | Sandbox escape; patched 1.123.17/2.5.2 |
| CVE-2026-21858 | n8n | 10.0 | Feb 5-6 | Unauth RCE; patched |
| CVE-2026-1470 | n8n | 9.9 | Feb 5-6 | Security control bypass; patched |
| CVE-2026-0863 | n8n | 8.5 | Feb 5-6 | Service takeover; patched |
| CVE-2025-40551 | SolarWinds WHD | 9.8 | Feb 5-6 | Unauth RCE; CISA KEV; deadline passed Feb 6 |
| CVE-2026-21509 | Microsoft Office | 7.8 | Feb 5 | Zero-day; OOB patched Jan 26; APT28 exploitation |
| CVE-2025-22224 | VMware ESXi | 9.3 | Feb 5 | Heap overflow; ransomware confirmed; CISA KEV |
| CVE-2025-22225 | VMware ESXi | 8.2 | Feb 5 | Kernel write / sandbox escape; CISA KEV |
| CVE-2025-22226 | VMware ESXi | 7.1 | Feb 5 | Info disclosure; CISA KEV |
| CVE-2026-20045 | Cisco UCM/Webex | High | Feb 5-6 | Zero-day; CISA KEV; deadline Feb 11 |
| CVE-2026-20805 | Microsoft DWM | High | Feb 5 | Zero-day; CISA KEV; deadline passed Feb 3 |
| CVE-2025-40602 | SonicWall SMA1000 | 6.6 | Feb 6 | Chained zero-day; patched |
| CVE-2025-23006 | SonicWall SMA1000 | 9.8 | Feb 6 | Deserialization flaw (chain partner) |
| CVE-2025-55182 | React Server Components | 10.0 | Feb 6 | NGINX hijacking; 1,083 IPs exploiting |
| CVE-2025-8088 | WinRAR | High | Feb 6 | Exploited by Amaranth-Dragon |
| CVE-2025-11953 | React Native CLI | High | Feb 6 | Command injection; CISA KEV; deadline Feb 26 |
| CVE-2025-43529 | Apple iOS WebKit | High | Feb 6 | Zero-day; patched in iOS 26.2 |
| CVE-2025-14174 | Apple iOS WebKit | High | Feb 6 | Zero-day; patched in iOS 26.2 |
| CVE-2026-1862 | Chrome V8 | High | Feb 6 | Type confusion; patched |
| CVE-2026-1861 | Chrome | High | Feb 6 | Heap corruption; patched |
| CVE-2026-24061 | GNU InetUtils telnetd | Critical | Feb 5 | Auth bypass |
| CVE-2026-0625 | D-Link DSL routers | Critical | Feb 5 | No patch (EOL) |
| CVE-2025-31125 | Vite Vitejs | High | Feb 6 | CISA KEV; deadline Feb 12 |
| CVE-2025-34026 | Versa Concerto | High | Feb 6 | CISA KEV; deadline Feb 12 |
| CVE-2025-68645 | Zimbra ZCS | High | Feb 6 | CISA KEV; deadline Feb 12 |
| CVE-2019-19006 | Sangoma FreePBX | High | Feb 6 | Auth flaw; CISA KEV; deadline Feb 24 |
| CVE-2025-64328 | Sangoma FreePBX | High | Feb 6 | Command injection; CISA KEV; deadline Feb 24 |
| CVE-2021-39935 | GitLab CE/EE | High | Feb 6 | SSRF; CISA KEV; deadline Feb 24 |

---

*Weekly summary generated: 2026-02-08*
*Consolidating 3 daily reports from 2026-02-05 to 2026-02-08*
*Classification: TLP:CLEAR*
