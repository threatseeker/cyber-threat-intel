# Cyber Threat Intelligence Report
## Date: January 17, 2026

---

## Executive Summary

Today's report highlights several **new and developing threats**:

- **[NEW] Victorian Department of Education breach** affecting all 1,700 government schools in Victoria, Australia - student data compromised
- **[NEW] Keylogger attack** targeting 200,000+ employees at a top 3 US bank via employee merchandise store
- **[NEW] Malicious Chrome extensions** impersonating Workday, NetSuite, and SuccessFactors stealing enterprise credentials
- **[NEW] RondoDox Botnet** actively exploiting React2Shell vulnerability (CVE-2025-55182) with 150,000 daily exploit attempts
- **[NEW] Everest ransomware group claims Nissan breach** - alleges 900GB of data stolen
- **[UPDATE] CVE-2025-64155 (FortiSIEM)** - PoC released, active exploitation confirmed against ~15 threat actors
- **[NEW] University of Phoenix breach disclosure** - 3.5M individuals affected via Oracle EBS zero-day (CVE-2025-61882)
- **[NEW] 700Credit breach** affecting 5.6M consumers and 18,000 auto dealerships

---

## Critical Vulnerabilities

### [UPDATE] CVE-2025-64155 - Fortinet FortiSIEM OS Command Injection
| Attribute | Detail |
|-----------|--------|
| CVSS Score | 9.4 (Critical) |
| Affected Product | FortiSIEM 7.4 and below |
| Status | **PoC Released, Active Exploitation Confirmed** |
| Fix | Upgrade to 7.4.1, 7.3.5, 7.2.7, or 7.1.9+ |

**Update (Jan 15-17):** Horizon3.ai released a PoC exploit on January 15, 2026. Defused Cyber reports exploitation has expanded to ~15 differentiated actors targeting honeypots. Organizations with internet-exposed FortiSIEM (TCP port 7900) should patch immediately or restrict access to the phMonitor port.

**Source:** [Horizon3.ai](https://horizon3.ai/attack-research/vulnerabilities/cve-2025-64155-fortinet-fortisiem/), [Help Net Security](https://www.helpnetsecurity.com/2026/01/15/fortisiem-vulnerability-cve-2025-64155-poc-exploit/)

---

### [UPDATE] CVE-2025-55182 - React2Shell (Next.js/React Server Components)
| Attribute | Detail |
|-----------|--------|
| CVSS Score | 10.0 (Critical) |
| Affected Product | Next.js with React Server Components |
| Status | **Active Mass Exploitation by RondoDox Botnet** |
| Fix | Update Next.js to patched version |

**Update:** The RondoDox botnet has weaponized this vulnerability and is conducting 150,000 daily exploit attempts. Approximately 90,300 vulnerable instances are exposed globally, primarily in the US, Germany, France, and India.

**Source:** [The Hacker News](https://thehackernews.com/2026/01/rondodox-botnet-exploits-critical.html), [CloudSEK](https://www.cloudsek.com/blog/rondodox-botnet-weaponizes-react2shell)

---

### [PREVIOUSLY REPORTED - ONGOING] n8n Workflow Automation Vulnerabilities

Organizations should confirm they have patched these maximum-severity flaws:

| CVE | CVSS | Description | Fixed Version |
|-----|------|-------------|---------------|
| CVE-2026-21858 | 10.0 | Unauthenticated RCE via Content-Type confusion | 1.121.0+ |
| CVE-2026-21877 | 10.0 | Authenticated RCE in self-hosted and cloud | 1.121.3+ |
| CVE-2025-68613 | 9.9 | Expression injection RCE | 1.120.4, 1.121.1, 1.122.0+ |

**Source:** [Canadian Cyber Centre Advisory](https://www.cyber.gc.ca/en/alerts-advisories/al26-001-vulnerabilities-affecting-n8n-cve-2026-21858-cve-2026-21877-cve-2025-68613)

---

## Exploits & Zero-Days

### No New Zero-Days Disclosed Today

All zero-days being actively exploited were disclosed in prior days. Key ongoing exploitation:
- **CVE-2026-0625** (D-Link DSL routers) - No patch forthcoming; replace affected devices
- **CVE-2026-20805** (Windows DWM) - Patched in January 2026 Patch Tuesday

---

## Malware & Ransomware

### [NEW] RondoDox Botnet - Mass Exploitation Campaign
**First Reported:** January 17, 2026

The RondoDox botnet has evolved into a large-scale operation deploying:
- Cryptominers
- Mirai-based botnet variants
- Linux-focused "nuts/bolts" persistence framework

**Technical Details:**
- Targets WordPress, Drupal, Struts2, and IoT devices
- Weaponizing React2Shell (CVE-2025-55182) since December 8, 2025
- Persistence mechanism kills competing malware every ~45 seconds
- Second variant purges Docker payloads and rival botnets

**Mitigations:**
1. Update Next.js immediately
2. Segment IoT devices into dedicated VLANs
3. Deploy Web Application Firewalls (WAFs)
4. Block known C2 infrastructure

**Source:** [SecurityWeek](https://www.securityweek.com/rondodox-botnet-exploiting-react2shell-vulnerability/), [Security Boulevard](https://securityboulevard.com/2026/01/rondodox-botnet-operators-set-react2shell-flaw-in-their-sights/)

---

### [NEW] Malicious Chrome Extensions - Enterprise Credential Theft
**Discovered:** January 2026

Five coordinated Chrome extensions masquerade as HR/ERP platforms (Workday, NetSuite, SuccessFactors) to:
- Exfiltrate authentication cookies every 60 seconds
- Block access to 44 administrative pages within Workday
- Enable session hijacking via cookie injection

**Known Extensions:**
- DataByCloud Access (251 installs)
- Tool Access 11 (101 installs)
- DataByCloud 1 & 2 (~2,000 installs combined)
- Software Access (still available on third-party sites)

**Actions Required:**
1. Audit installed Chrome extensions
2. Remove any matching these names/patterns
3. Reset passwords from clean systems
4. Review authentication logs for anomalous access

**Source:** [The Hacker News](https://thehackernews.com/2026/01/five-malicious-chrome-extensions.html), [Socket.dev](https://socket.dev/blog/5-malicious-chrome-extensions-enable-session-hijacking)

---

### [NEW] Keylogger Attack on Major US Bank Employee Store
**Discovered:** January 15, 2026 (Active ~18 hours)

Security firm Sansec discovered a keylogger on the employee merchandise store of a top 3 US bank, potentially affecting 200,000+ employees.

**Impact:**
- Login credentials harvested
- Payment card numbers captured
- Personal information stolen

**Concern:** Bank employees often reuse corporate credentials, potentially providing attackers footholds into internal banking systems.

**Source:** [Sansec Research](https://sansec.io/research/keylogger-major-us-bank-employees), [CyberPress](https://cyberpress.org/malware-targets-us-bank-employees-login-credentials/)

---

### Ransomware Statistics (January 2026)
| Metric | Value |
|--------|-------|
| Victims through Jan 15 | 285 |
| Most Active Group | Qilin (1,000+ victims in 2025) |
| Q4 2025 Victims | 2,287 (highest quarter on record) |

**Source:** [InfoSec Bulletin](https://infosecbulletin.com/ransomware-statistics-for-the-1st-15-days-of-2026/)

---

### [NEW] Everest Ransomware Claims Nissan Breach
**Claimed:** January 10, 2026

The Russia-linked Everest ransomware group claims to have:
- Exfiltrated ~900GB of data from Nissan Motor Corporation
- Accessed internal file storage including reports, dealership info, and certification data
- Released all stolen data on the dark web

**Status:** Pending verification - Nissan has not confirmed or denied.

**Source:** [Hackread](https://hackread.com/everest-ransomware-nissan-data-breach/), [SC Media](https://www.scworld.com/brief/everest-ransomware-group-claims-nissan-breach-demands-response)

---

## Threat Actors

### APT Activity Summary

| Actor | Attribution | Recent Activity |
|-------|-------------|-----------------|
| APT28 (Fancy Bear) | Russia/GRU | Credential harvesting in Balkans, Middle East, Central Asia |
| UAT-7290 | China-nexus | Targeting telecom providers in South Asia, expanding to SE Europe |
| UAT-8837 | China-nexus | Targeting North American critical infrastructure |

**No new APT disclosures today.** Ongoing campaigns continue as previously reported.

**Source:** [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-credentials-global-targets), [Cisco Talos](https://blog.talosintelligence.com/uat-7290/)

---

## Vendor Advisories

### No New Major Advisories Released Today (January 17)

Organizations should continue patching from this week's advisories:

| Vendor | Advisory Date | Key Items |
|--------|---------------|-----------|
| Microsoft | Jan 14 | 114 CVEs, 3 zero-days (1 actively exploited) |
| SAP | Jan 14 | 19 CVEs including 4 critical |
| Fortinet | Jan 13 | CVE-2025-64155 (FortiSIEM) - Now actively exploited |
| Adobe | Jan 14 | 25 CVEs across multiple products |

**Source:** [Qualys Blog](https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review), [SecurityWeek](https://www.securityweek.com/saps-january-2026-security-updates-patch-critical-vulnerabilities/)

---

## Industry News - Data Breaches

### [NEW] Victorian Department of Education (Australia)
**Disclosed:** January 14, 2026

| Detail | Information |
|--------|-------------|
| Affected | All 1,700 Victorian government schools |
| Data Compromised | Student names, school names, year levels, school-issued emails, encrypted passwords |
| Status | All student passwords reset as precaution |

**Entry Point:** School network compromised, providing access to Department database.

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/victorian-department-of-education-notifies-parents-of-data-breach/), [Cyber Daily](https://www.cyberdaily.au/security/13095-all-1-700-victorian-government-schools-caught-up-in-cyber-attack-student-data-accessed)

---

### [NEW] University of Phoenix - 3.5 Million Affected
**Disclosed:** January 2026

| Detail | Information |
|--------|-------------|
| Individuals Affected | 3,489,274 |
| Attack Period | August 13-22, 2025 |
| Detected | November 21, 2025 |
| Root Cause | CVE-2025-61882 (Oracle EBS zero-day) |
| Attribution | Clop ransomware gang |

**Data Compromised:** Names, dates of birth, Social Security numbers, bank account/routing numbers.

**Also Affected:** Harvard University, University of Pennsylvania, Dartmouth College via same campaign.

**Source:** [SecurityWeek](https://www.securityweek.com/3-5-million-affected-by-university-of-phoenix-data-breach/), [TechCrunch](https://techcrunch.com)

---

### [NEW] 700Credit - 5.6 Million Auto Finance Customers
**Disclosure Ongoing:** Late 2025 - January 2026

| Detail | Information |
|--------|-------------|
| Individuals Affected | 5.6 million+ |
| Dealerships Affected | ~18,000 |
| Attack Period | May - October 2025 |
| Root Cause | Compromised integration partner |

**Data Compromised:** Names, addresses, dates of birth, Social Security numbers.

**Dark Web Activity:** Dataset advertised for $2,500 on Exploit and DarkForums (November 16, 2025).

**Source:** [TechCrunch](https://techcrunch.com/2025/12/12/data-breach-at-credit-check-giant-700credit-affects-at-least-5-6-million/), [Fox News](https://www.foxnews.com/tech/700credit-data-breach-exposes-ssns-5-8m-consumers)

---

## Recommended Actions

### Immediate (Within 24-48 Hours)
1. **Patch FortiSIEM** if running version 7.4 or below - active exploitation confirmed
2. **Audit Chrome extensions** for malicious HR/ERP impersonators
3. **Update Next.js** deployments to mitigate React2Shell exploitation
4. **Block RondoDox C2 infrastructure** at network perimeter

### Short-Term (This Week)
5. Complete Microsoft January 2026 Patch Tuesday deployment
6. Apply SAP January 2026 security patches
7. Verify n8n workflow automation platforms are patched to latest versions
8. Review Oracle EBS deployments for October 2025 emergency patches

### Ongoing
9. Monitor for credential reuse if employees used affected bank merchandise store
10. Implement extension management policies in Chrome/Edge
11. Segment IoT and development environments from production networks

---

## Sources

- [The Hacker News](https://thehackernews.com/)
- [BleepingComputer](https://www.bleepingcomputer.com/)
- [SecurityWeek](https://www.securityweek.com/)
- [Dark Reading](https://www.darkreading.com/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Horizon3.ai](https://horizon3.ai/)
- [Sansec Research](https://sansec.io/research/)
- [CloudSEK](https://www.cloudsek.com/)
- [Canadian Centre for Cyber Security](https://www.cyber.gc.ca/)
- [Qualys Blog](https://blog.qualys.com/)
- [Socket.dev](https://socket.dev/)

---

*Report compiled: January 17, 2026*
*Classification: TLP:CLEAR*
