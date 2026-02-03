# Cyber Threat Intelligence Report
**Date:** February 3, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0203

---

## Executive Summary

- **DEADLINE TODAY**: Microsoft DWM CVE-2026-20805 - CISA remediation deadline **February 3, 2026**
- **NEW**: Under Armour breach confirmed - 72.7M accounts exposed by Everest ransomware; data now on HIBP
- **NEW**: n8n additional critical flaws - CVE-2026-1470 (9.9) and CVE-2026-0863 (8.5) join CVE-2026-21858 (10.0)
- **NEW**: Nike claimed by WorldLeaks - 1.4TB internal data allegedly stolen including supply chain documents
- **NEW**: Crunchbase breach - ShinyHunters leaks 2M+ records after ransom refusal
- **NEW**: Phantom Taurus Chinese APT update - Unit 42 reveals NET-STAR malware suite targeting IIS servers
- **UPDATE**: AT&T breach data resurfaces with enhanced profiles being circulated
- **UPDATE**: Multiple ransomware groups active (Akira, Qilin, Rhysida, DragonForce) hitting BASF, Honeywell, Linde

---

## Critical Vulnerabilities

### DEADLINE TODAY: Microsoft DWM CVE-2026-20805

**CISA Remediation Deadline:** February 3, 2026 (TODAY)
**CVE:** CVE-2026-20805
**CVSS:** 5.5
**Status:** Actively exploited zero-day

Federal Civilian Executive Branch agencies must apply patches by end of day. Microsoft's first zero-day of 2026, this information disclosure vulnerability in Desktop Window Manager is under active exploitation.

**Sources:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [SOC Prime](https://socprime.com/blog/cve-2026-20805-vulnerability/), [The Register](https://www.theregister.com/2026/01/14/patch_tuesday_january_2026/)

---

### NEW: n8n Additional Critical Vulnerabilities

Two additional critical flaws discovered alongside CVE-2026-21858:

| CVE | CVSS | Impact |
|-----|------|--------|
| CVE-2026-21858 | 10.0 | Unauthenticated RCE via file-handling bypass |
| CVE-2026-1470 | 9.9 | Security control bypass, arbitrary code execution |
| CVE-2026-0863 | 8.5 | Full service takeover, credential access |

**Impact:** Combined, these flaws enable attackers to bypass security controls, execute arbitrary code, gain full control over n8n services, and access credentials and API keys.

**Scale:** n8n has over 100 million Docker pulls and is used by thousands of enterprises.

**Remediation:** Update n8n immediately to latest version.

**Source:** [SecurityWeek](https://www.securityweek.com/critical-vulnerability-exposes-n8n-instances-to-takeover-attacks/)

---

### Cisco Zero-Day CVE-2026-20045

**CVE:** CVE-2026-20045
**Products:** Cisco Unified Communications Manager, Webex
**Impact:** Unauthenticated RCE
**CISA Deadline:** February 11, 2026

Actively exploited zero-day enabling unauthenticated remote code execution. CISA has added to KEV catalog.

**Source:** [The Hacker News](https://thehackernews.com/2026/01/cisco-fixes-actively-exploited-zero-day.html)

---

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | **TODAY (Feb 3)** |
| CVE-2026-20045 | Cisco Unified CM/Webex | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |

---

### GNU InetUtils Critical Auth Bypass

**CVE:** CVE-2026-24061
**Product:** GNU InetUtils telnetd
**Impact:** Remote authentication bypass via "-f root" argument injection
**Scope:** Hundreds of thousands of telnet servers globally

**Source:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Data Breaches

### NEW: Under Armour - 72.7 Million Accounts

**Victim:** Under Armour
**Threat Actor:** Everest ransomware group
**Attack Date:** November 2025
**Data Posted:** January 18, 2026
**Affected:** 72.7 million accounts
**Data Volume:** 343 GB

**Timeline:**
- Nov 16, 2025: Everest posted breach claims with 7-day ultimatum
- Jan 18, 2026: Data leaked on cybercrime forum
- Jan 2026: Have I Been Pwned ingested data and notified users

**Data Exposed:**
- Names, dates of birth, genders
- Email addresses
- Physical addresses, zip codes
- Purchase history

**NOT Exposed (per Under Armour):** Passwords, financial information, payment data

**Under Armour Response:** Denies "sensitive personal information of tens of millions of customers has been compromised" and says payment systems were not affected.

**Sources:** [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/01/under-armour-ransomware-breach-data-of-72-million-customers-appears-on-the-dark-web), [The Register](https://www.theregister.com/2026/01/21/under_armour_everest/), [SecurityWeek](https://www.securityweek.com/under-armour-looking-into-data-breach-affecting-customers-email-addresses/)

---

### NEW: Nike - WorldLeaks Claims 1.4TB Stolen

**Victim:** Nike
**Threat Actor:** WorldLeaks extortion group
**Claimed Data:** 1.4 TB internal data
**Contents:** Supply chain and manufacturing documents, internal archives

**Status:** Under investigation. No official confirmation from Nike.

**Source:** [BreachSense](https://www.breachsense.com/breaches/2026/february/)

---

### NEW: Crunchbase - 2M+ Records

**Victim:** Crunchbase (private company intelligence platform)
**Threat Actor:** ShinyHunters
**Trigger:** Ransom demand refused
**Affected:** 2+ million records

**Data Exposed:**
- Customer names and contact details
- Partner contracts
- Internal corporate documents

**Company Response:** Crunchbase confirmed breach, stated operations were not disrupted.

**Source:** [BreachSense](https://www.breachsense.com/breaches/)

---

### UPDATE: AT&T Breach Data Resurfaces

**Date Circulated:** February 2, 2026
**Status:** Private circulation on dark web

**Significance:** This dataset includes more complete profiles than previous leaks—more email addresses, more SSNs, and more complete records per person, making it more valuable for identity fraud.

**Source:** [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/att-breach-data-resurfaces-with-new-risks-for-customers)

---

### Multiple Organizations Breached (Feb 3)

| Victim | Threat Actor | Sector |
|--------|--------------|--------|
| BASF SE | Unknown | Chemical/Manufacturing |
| Honeywell | Unknown | Industrial |
| Linde plc | Unknown | Industrial Gas |
| Ferretti Group | Akira | Luxury Yachts |
| Family Health Centers | Termite | Healthcare |
| Various | Qilin, Rhysida, DragonForce | Multiple |

**Source:** [Check Point Research](https://research.checkpoint.com/2026/2nd-february-threat-intelligence-report/)

---

## APT & Threat Actor Activity

### UPDATE: Phantom Taurus - NET-STAR Malware Suite Revealed

**Threat Actor:** Phantom Taurus
**Attribution:** China-nexus (PRC state interests)
**Discovered by:** Palo Alto Unit 42
**Active:** 2+ years
**Targets:** Government, telecommunications across Africa, Middle East, Asia

**Key Characteristics:**
- **Surgical precision:** Targets high-value systems directly instead of phishing end users
- **Unprecedented persistence:** Resurfaces within hours or days after discovery (vs weeks/months for typical APTs)
- **Custom toolkit:** NET-STAR malware suite for Microsoft IIS servers

**NET-STAR Malware:**
- Developed in .NET
- Three previously undocumented IIS backdoors
- In-memory VBScript implants
- DNS tunneling (TunnelSpecter)
- RAT capabilities (SweetSpecter)

**Additional Tools:** Agent Racoon, PlugX, Gh0st RAT, China Chopper, Mimikatz, Impacket

**Initial Access:** Exploits known vulnerabilities in Microsoft Exchange and IIS servers

**Data Exfiltration:** Custom batch script (mssq.bat) extracts SQL database contents via WMI

**Infrastructure:** Shares operational infrastructure with Iron Taurus (APT27), Starchy Taurus (Winnti), and Stately Taurus (Mustang Panda)

**Sources:** [Unit 42](https://unit42.paloaltonetworks.com/phantom-taurus/), [SecurityWeek](https://www.securityweek.com/chinese-apt-phantom-taurus-targeting-organizations-with-net-star-malware/), [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)

---

## Ransomware Activity

### Everest Ransomware Profile

Following the Under Armour breach, key facts about the Everest group:

**Operational Since:** 2020
**Longevity:** Unusually durable for ransomware groups

**Revenue Streams:**
1. Double extortion ransomware
2. Network access brokerage (selling access to other criminals)
3. Insider recruitment program

**Source:** [TechRepublic](https://www.techrepublic.com/article/news-under-armour-ransomware-attack/)

---

### 2026 Ransomware Predictions

**AI-Autonomous Attacks Imminent:**
> "By mid-2026, at least one major global enterprise will fall to a breach caused or significantly advanced by a fully autonomous agentic AI system."
> — Michael Freeman, Armis Head of Threat Intelligence

These systems will use reinforcement learning and multi-agent coordination to autonomously execute entire attack lifecycles: reconnaissance, payload generation, lateral movement, and exfiltration.

**DDoS Resurgence Expected:**
Security experts warn 2026 may see record-setting DDoS activity as attackers revert to denial-of-service when ransomware becomes less viable.

**Sources:** [SecurityWeek](https://www.securityweek.com/cyber-insights-2026-malware-and-cyberattacks-in-the-age-of-ai/)

---

### BlackCat/Alphv Sentencing Update

Two US cybersecurity professionals who pleaded guilty to BlackCat ransomware involvement face sentencing **March 12, 2026**:

| Name | Role | Company | Max Sentence |
|------|------|---------|--------------|
| Ryan Goldberg (40) | Incident Response Manager | Sygnia | 20 years |
| Kevin Martin (36) | Ransomware Negotiator | DigitalMint | 20 years |

**Known Ransom:** $1.2 million Bitcoin from one victim

**Source:** [SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)

---

## Vulnerability Statistics

### 2025-2026 Trend Data

| Metric | Value |
|--------|-------|
| CVEs tracked in 2025 | 48,000+ |
| Year-over-year increase | ~20% |
| Increase from 2023 | 66% |
| Projected 2026 CVEs | 57,600 - 79,680 |
| Exploitation within 1 day | 28% of vulnerabilities |
| Time to exploit (2020) | 30 days average |
| Time to exploit (2025) | <1 day (28% of cases) |

**Key Insight:** Attackers exploited 28% of vulnerabilities within one day of CVE disclosure in 2025, compared to an average of 30 days in 2020.

**Source:** [Cyble](https://cyble.com/blog/weekly-vulnerabilities-surge-trend-2026/)

---

## Recommended Actions

### Immediate Priority (Today)

1. **Microsoft DWM** - Patch CVE-2026-20805 **TODAY** - CISA deadline
2. **n8n** - Update immediately; three critical vulnerabilities (CVSS 10.0, 9.9, 8.5)
3. **Check HIBP** - Under Armour users should check haveibeenpwned.com

### High Priority (This Week)

4. **Cisco UCM/Webex** - Patch CVE-2026-20045 before February 11 deadline
5. **GNU InetUtils** - Patch or disable telnetd (CVE-2026-24061)
6. **Microsoft Office** - Patch CVE-2026-21509 before February 16 deadline

### Threat Hunting

7. **IIS servers** - Hunt for NET-STAR indicators (Phantom Taurus)
8. **Exchange servers** - Review for exploitation attempts by Chinese APTs
9. **SQL databases** - Monitor for WMI-based data extraction (mssq.bat)

### Breach Response

10. **Under Armour customers** - Monitor for identity fraud; consider credit freeze
11. **AT&T customers** - Enhanced monitoring recommended given data enrichment
12. **Crunchbase partners** - Review contractual exposure

---

## Sources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Malwarebytes - Under Armour Breach](https://www.malwarebytes.com/blog/news/2026/01/under-armour-ransomware-breach-data-of-72-million-customers-appears-on-the-dark-web)
- [The Register - Under Armour](https://www.theregister.com/2026/01/21/under_armour_everest/)
- [SecurityWeek - Under Armour](https://www.securityweek.com/under-armour-looking-into-data-breach-affecting-customers-email-addresses/)
- [SecurityWeek - n8n Vulnerabilities](https://www.securityweek.com/critical-vulnerability-exposes-n8n-instances-to-takeover-attacks/)
- [Unit 42 - Phantom Taurus](https://unit42.paloaltonetworks.com/phantom-taurus/)
- [Dark Reading - Phantom Taurus](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)
- [The Hacker News - Cisco Zero-Day](https://thehackernews.com/2026/01/cisco-fixes-actively-exploited-zero-day.html)
- [Check Point - Feb 3 Threat Report](https://research.checkpoint.com/2026/2nd-february-threat-intelligence-report/)
- [Malwarebytes - AT&T Data](https://www.malwarebytes.com/blog/news/2026/02/att-breach-data-resurfaces-with-new-risks-for-customers)
- [BreachSense - February 2026](https://www.breachsense.com/breaches/2026/february/)
- [SecurityWeek - BlackCat Guilty Pleas](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [Cyble - Vulnerability Trends](https://cyble.com/blog/weekly-vulnerabilities-surge-trend-2026/)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 2, 2026 report:

- CVE-2026-21858 n8n Critical RCE (CVSS 10.0) - first disclosure
- SimonMed Imaging ransomware (Medusa, 1.27M patients)
- Illinois DHS breach (600K+ affected)
- China-linked APT UAT-8837 exploiting Sitecore zero-day
- VMware ESXi zero-days weaponized by Chinese actors
- Sedgwick Government Solutions ransomware
- University of Phoenix breach (3.5M)
- 1st MidAmerica Credit Union breach
- APT28/Fancy Bear credential harvesting campaign
- Iranian APT Infy resurgence
- ClickFix attacks adopted by APTs

---

*Report generated: 2026-02-03*
*Next report: 2026-02-04*
*Classification: TLP:CLEAR*
