# Cyber Threat Intelligence Report
**Date:** 2026-02-18
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0218

---

## Executive Summary

- **CRITICAL**: BeyondTrust CVE-2026-1731 (CVSS 9.9) under mass exploitation - patch immediately
- **CRITICAL**: n8n CVE-2026-25049 (CVSS 9.4) enables unauthenticated RCE via webhook - patch to v2.5.2+
- Microsoft Feb 2026 Patch Tuesday patched 58 flaws including **6 actively exploited zero-days**
- Chrome CVE-2026-2441 zero-day patched - first actively exploited Chrome flaw of 2026
- UNC3886 (China-nexus APT) disrupted in Operation CYBER GUARDIAN targeting Singapore telecoms
- Conduent govtech breach expanded to **15.4 million** Americans affected
- ShinyHunters breached Harvard University - 115,000 alumni records exposed
- Ransomware groups increased 30% YoY; "exfiltration-only" model surging

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2026-1731 | BeyondTrust Remote Support & PRA | 9.9 | OS Command Injection | CISA KEV - Mass exploitation (Feb 10+) |
| CVE-2026-25049 | n8n workflow platform | 9.4 | Expression sandbox bypass -> RCE | Unauthenticated via webhook |
| CVE-2026-21510 | Windows Shell | 8.8 | Security feature bypass | CISA KEV - Exploited zero-day |
| CVE-2026-21513 | Windows MSHTML Framework | 8.1 | Security feature bypass | CISA KEV - Exploited zero-day |
| CVE-2026-21519 | Windows Desktop Window Manager | 7.8 | EoP | CISA KEV - Exploited zero-day |
| CVE-2026-21533 | Windows Remote Desktop Services | 7.5 | EoP | CISA KEV - Active since Dec 2025 |
| CVE-2026-21525 | Windows Remote Access Conn. Mgr | 7.5 | Crash/DoS | CISA KEV - Exploited zero-day |
| CVE-2026-21514 | Microsoft Word | 5.5 | Security feature bypass | CISA KEV - Exploited zero-day |
| CVE-2026-20700 | Apple iOS/macOS/tvOS/watchOS/visionOS | N/A | Memory buffer bounds violation -> RCE | Actively exploited |
| CVE-2025-40551 | SolarWinds Web Help Desk | High | Deserialization of Untrusted Data | CISA KEV (Feb 3) |
| CVE-2021-39935 | GitLab CE/EE | High | SSRF | CISA KEV (Feb 3) - legacy, re-added |
| CVE-2019-19006 | Sangoma FreePBX | High | Improper Authentication | CISA KEV (Feb 3) - legacy, re-added |
| CVE-2025-64328 | Sangoma FreePBX | High | OS Command Injection | CISA KEV (Feb 3) |

### BeyondTrust CVE-2026-1731 (Priority 1)
OS command injection in BeyondTrust Remote Support and Privileged Remote Access. Mass exploitation confirmed by watchTowr and Arctic Wolf beginning February 10. First exploitation attempt observed Feb 10, 2026. CVSS 9.9.
- **Fix**: Apply vendor patch immediately
- **Source**: [Orca Security](https://orca.security/resources/blog/cve-2026-1731-beyondtrust-vulnerability/)

### n8n CVE-2026-25049 (Priority 1 - LOCAL EXPOSURE)
Bypass of CVE-2025-68613's sandbox protections via JavaScript destructuring syntax. Allows workflow authors (or unauthenticated users via public webhooks) to execute system-level commands. CVSS 9.4.
- **Fix**: Upgrade n8n to v2.5.2 or later
- **Note**: This affects self-hosted n8n instances including Docker deployments
- **Source**: [The Hacker News](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)

---

## Exploits & Zero-Days

### Microsoft February 2026 Patch Tuesday - 6 Zero-Days
Released February 10, 2026. 58 total CVEs, 5 rated Critical, 6 exploited in the wild prior to patch.
- CVE-2026-21510: Windows Shell SmartScreen bypass - attacker tricks user into opening malicious link/shortcut
- CVE-2026-21513: MSHTML Framework security feature bypass - publicly disclosed pre-patch
- CVE-2026-21514: Microsoft Word security feature bypass - requires opening malicious .docx
- CVE-2026-21519: Windows DWM local EoP - low-privilege user can escalate, no user interaction required
- CVE-2026-21533: Windows RDS EoP - used to add accounts to Administrator group; active since Dec 24, 2025
- CVE-2026-21525: Windows Remote Access Conn. Mgr crash - exploit found in public malware repository
- **Sources**: [Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/), [Zero Day Initiative](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review), [Krebs on Security](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)

### Chrome CVE-2026-2441 Zero-Day
First actively exploited Chrome zero-day of 2026. Remote attacker can execute arbitrary code inside sandbox via crafted HTML page. Patch released.
- **Source**: [The Hacker News](https://thehackernews.com/2026/02/new-chrome-zero-day-cve-2026-2441-under.html)

---

## Malware & Ransomware

### Active Campaigns
- **Play ransomware**: Targeting Esquire Brands (children's footwear) and Garner Foods (hot sauce/food products); data theft + extortion
- **TridentLocker**: Claimed responsibility for Sedgwick (claims administration) breach - ~3.4 GB stolen
- **CrazyHunter**: Emerging strain combining stealthy evasion + aggressive lateral movement; disables security controls early; strong encryption

### Threat Trends
- Ransomware groups increased ~30% YoY (2025 vs 2026); most active: Qiling, Akira, Cl0p, Play, Safepay
- **"Exfiltration-only" ransomware** surging - attackers skip encryption, only steal and extort; harder to detect, lower risk for attackers
- BlackFog reports 49% increase in ransomware attacks YoY
- 2026 CVE forecast: 59,000+ CVEs expected (strategic breaking point for security teams)

### Sources
- [BlackFog State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [Morphisec - Exfiltration Ransomware](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [CYFIRMA Weekly Intelligence](https://www.cyfirma.com/news/weekly-intelligence-report-13-february-2026/)

---

## Threat Actors

### UNC3886 (China-Nexus APT) - Operation CYBER GUARDIAN
Singapore's Cyber Security Agency (CSA) disclosed a major multi-agency operation on February 9, 2026, to oust UNC3886 from Singapore's telecommunications sector. All four major Singapore telcos affected (M1, SIMBA, Singtel, StarHub).
- **TTPs**: Zero-day perimeter firewall exploits; rootkit deployment for persistent undetected access
- **Attribution**: Mandiant-designated China-nexus espionage group; first flagged July 2025
- **Sources**: [Computer Weekly](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor), [CSA Press Release](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)

### Kimsuky (North Korea) - QR Code Phishing
FBI FLASH (January 8, 2026) describes Kimsuky embedding malicious QR codes in spearphishing emails targeting U.S. organizations. QR codes push victims to mobile devices, bypassing email security inspection.
- **Targets**: U.S. defense contractors and government entities
- **Source**: [The Record - Nation-State AI Use](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns)

### Nation-State AI Adoption
Google reports nation-state hackers ramping up use of Gemini for target reconnaissance and malware coding. Multiple APT groups across several nations now leveraging AI assistants for offensive operations.

### Salt Typhoon (China) - Telecom Persistence
Senate letters and FBI reporting reference Chinese actors (likely Salt Typhoon) maintaining access in more than 200 U.S. organizations across 80 countries; may still have presence inside U.S. telecom networks.

---

## Data Breaches

| Organization | Records Affected | Data Exposed | Threat Actor |
|-------------|-----------------|--------------|--------------|
| Conduent (gov-tech) | 15.4M+ (TX alone) | PII, government services data | Ransomware (Jan 2025, expanded Feb 2026) |
| Harvard University AAD | ~115,000 | Alumni PII, financial data | ShinyHunters (deepfake voice phishing) |
| Japan Airlines | Unknown | Names, phone, email, travel data | Unknown (Feb 9) |
| Substack | Unknown | Phone numbers, email addresses | Unknown (Feb 3) |
| Cottage Hospital | ~1,600 | SSN, DL#, bank accounts | Unknown (Oct 2025, disclosed Feb 2026) |
| IRS | N/A | Taxpayer data | Improper internal disclosure to DHS |

### Notable Details
- **Conduent**: Originally disclosed as small breach from January 2025 ransomware attack; now confirmed 15.4M Texans alone - likely to grow
- **Harvard**: ShinyHunters used suspected deepfake voice phishing against admin staff - novel social engineering vector
- **IRS**: Not an external breach - agency shared confidential tax data with DHS for immigration enforcement; bipartisan congressional outcry

### Sources
- [TechCrunch - Conduent](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [InfoStealers - Harvard](https://www.infostealers.com/article/a-technical-and-ethical-post-mortem-of-the-feb-2026-harvard-university-shinyhunters-data-breach/)
- [Privacy Guides Roundup](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)

---

## Vendor Advisories

### Microsoft (February 10, 2026 - Patch Tuesday)
58 CVEs patched; 5 Critical; 6 zero-days. **Patch immediately.**
- Windows Shell, MSHTML, Word, DWM, RDS, Remote Access Conn. Mgr
- Sources: [Tenable](https://www.tenable.com/blog/microsofts-february-2026-patch-tuesday-addresses-54-cves-cve-2026-21510-cve-2026-21513), [Absolute Security](https://www.absolute.com/blog/microsoft-february-2026-patch-tuesday-critical-fixes-updates)

### Google Chrome
CVE-2026-2441 zero-day patched. Update Chrome immediately.

### Apple
CVE-2026-20700: Memory bounds violation allowing arbitrary code execution on iOS, macOS, tvOS, watchOS, visionOS. Apply latest Apple security updates.

### SolarWinds Web Help Desk
CVE-2025-40551: Deserialization vulnerability added to CISA KEV Feb 3. Patch if running WHD.

### n8n (Self-Hosted)
CVE-2026-25049: Upgrade to v2.5.2+ to patch sandbox escape. Critical for any internet-exposed n8n instance.
- [The Hacker News](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)

---

## Recommended Actions

### Priority 1 - Patch Within 24 Hours
1. **n8n**: Upgrade to v2.5.2+ (CVE-2026-25049, CVSS 9.4 - unauthenticated RCE via webhook)
2. **BeyondTrust RS/PRA**: Apply vendor patch (CVE-2026-1731, CVSS 9.9 - mass exploitation active)
3. **Microsoft**: Deploy February Patch Tuesday updates (6 actively exploited zero-days)
4. **Chrome**: Update to latest (CVE-2026-2441 zero-day)
5. **Apple**: Apply latest OS updates (CVE-2026-20700)

### Priority 2 - This Week
6. **SolarWinds Web Help Desk**: Patch CVE-2025-40551 if deployed
7. **GitLab**: Patch CVE-2021-39935 if not already done
8. **FreePBX**: Patch CVE-2019-19006 and CVE-2025-64328

### Priority 3 - Process
9. **Ransomware defenses**: Review backup isolation; consider exfiltration monitoring (DLP) given exfiltration-only trend
10. **QR code phishing**: User awareness training on QR code risks; implement mobile device management policies
11. **Telecom supply chain**: Review vendor access; audit for signs of persistent APT access
12. **IRS/Government data**: Review data sharing agreements with government vendors; audit third-party access to sensitive records

---

## Sources
- [CISA KEV Feb 3 Addition](https://www.cisa.gov/news-events/alerts/2026/02/03/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA KEV Feb 10 Addition](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA KEV Feb 13 Addition](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV - Help Net Security Analysis](https://www.helpnetsecurity.com/2026/02/16/cisa-kev-catalog-video/)
- [Orca Security - BeyondTrust CVE-2026-1731](https://orca.security/resources/blog/cve-2026-1731-beyondtrust-vulnerability/)
- [Tenable - February Patch Tuesday](https://www.tenable.com/blog/microsofts-february-2026-patch-tuesday-addresses-54-cves-cve-2026-21510-cve-2026-21513)
- [Bleeping Computer - Patch Tuesday Zero-Days](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [Zero Day Initiative - Feb 2026 Review](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
- [Krebs on Security - Patch Tuesday](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [Malwarebytes - Six Zero-Days](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)
- [The Hacker News - Chrome Zero-Day](https://thehackernews.com/2026/02/new-chrome-zero-day-cve-2026-2441-under.html)
- [The Hacker News - n8n CVE-2026-25049](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [The Hacker News - CISA KEV Four Flaws](https://thehackernews.com/2026/02/cisa-flags-four-security-flaws-under.html)
- [The Hacker News - SolarWinds WHD](https://thehackernews.com/2026/02/cisa-adds-actively-exploited-solarwinds.html)
- [BlackFog - State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [Morphisec - Exfiltration Ransomware](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [CYFIRMA Weekly Intel Feb 13](https://www.cyfirma.com/news/weekly-intelligence-report-13-february-2026/)
- [Computer Weekly - Singapore APT](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [CSA Singapore - Operation CYBER GUARDIAN](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [The Record - Nation-State AI Use](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns)
- [TechCrunch - Conduent Breach](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [InfoStealers - Harvard Breach](https://www.infostealers.com/article/a-technical-and-ethical-post-mortem-of-the-feb-2026-harvard-university-shinyhunters-data-breach/)
- [Privacy Guides Breach Roundup](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [SecurityWeek - In Other News](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)
- [FTC Ransomware Report to Congress](https://www.ftc.gov/news-events/news/press-releases/2026/02/ftc-issues-second-report-congress-its-work-fight-ransomware-other-cyberattacks/)
- [Hackerstorm - 2026 CVE Forecast](https://www.hackerstorm.com/index.php/articles/our-blog/hackerstorm/50k-cves-2026-vulnerability-management-strategy)
- [ExploreSec February 2026 Newsletter](https://www.exploresec.com/blog/2026/2/16/february-2026-exploresec-cybersecurity-threat-intelligence-newsletter)
