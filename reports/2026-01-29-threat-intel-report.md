# Cyber Threat Intelligence Report
**Date:** January 29, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0129

---

## Executive Summary

- **NEW**: CVE-2026-24858 - Critical Fortinet FortiCloud SSO zero-day under active exploitation; CISA KEV added January 27
- **NEW**: Osiris ransomware - new sophisticated family using POORTRY driver in BYOVD attacks discovered
- **NEW**: Condé Nast/WIRED breach confirmed - 2.3M records leaked, threat actor claims 40M more records pending
- **NEW**: Two US cybersecurity professionals plead guilty to BlackCat/Alphv ransomware attacks
- **UPDATE**: WinRAR CVE-2025-8088 exploitation continues by Russia/China nation-state actors
- **UPDATE**: Ransomware attacks up 47% over last 2 years; 57 new groups observed in 2025
- **REMINDER**: Microsoft DWM zero-day CVE-2026-20805 - CISA deadline **February 3, 2026** (5 days)

---

## Critical Vulnerabilities

### NEW: Fortinet CVE-2026-24858 - FortiCloud SSO Zero-Day (Active Exploitation)

**Severity:** Critical (Zero-Day, Actively Exploited)
**Added to CISA KEV:** January 27, 2026
**Products:** FortiOS, FortiManager, FortiAnalyzer, FortiProxy, FortiWeb (under investigation)

Authentication bypass vulnerability allowing attackers with a FortiCloud account to log into devices registered to other accounts when FortiCloud SSO is enabled.

**Observed Malicious Activity:**
- Unauthorized firewall configuration changes on FortiGate devices
- Unauthorized account creation
- VPN configuration changes to grant access to new accounts

**Timeline:**
- January 20: Fortinet customers report unauthorized access to FortiGate firewalls
- January 22: Two malicious FortiCloud accounts locked out
- January 26: Fortinet disabled FortiCloud SSO globally
- January 27: SSO re-enabled with vulnerable version blocking
- January 28: CISA releases guidance

**Remediation:**
- Upgrade to FortiOS 7.4.11 immediately
- Other product patches releasing shortly
- Note: Even if patched for CVE-2025-59718/59719, you are still vulnerable

**Sources:** [CISA Alert](https://www.cisa.gov/news-events/alerts/2026/01/28/fortinet-releases-guidance-address-ongoing-exploitation-authentication-bypass-vulnerability-cve-2026), [Help Net Security](https://www.helpnetsecurity.com/2026/01/28/fortinet-forticloud-sso-zero-day-vulnerability-cve-2026-24858/)

---

### CISA KEV Updates (January 27, 2026)

| CVE | Product | Type | Deadline |
|-----|---------|------|----------|
| CVE-2026-24858 | Fortinet Multiple Products | Auth Bypass | **TBD** |

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | **February 3, 2026** |
| CVE-2026-20045 | Cisco Unified Communications | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |

---

## Malware & Ransomware

### NEW: Osiris Ransomware Family

**First Observed:** November 2025 (disclosed January 2026)
**Target:** Major food service franchisee operator in Southeast Asia
**Attribution:** Possibly linked to Inc ransomware affiliates

**Technical Characteristics:**
- Uses POORTRY malicious driver in BYOVD (Bring Your Own Vulnerable Driver) attacks
- Hybrid cryptographic model with unique key per file
- Terminates security software, backup platforms (Veeam), VSS
- Data exfiltration to Wasabi cloud storage (same TTP as Inc ransomware)
- Ransom note: `Osiris-MESSAGE.txt`

**Significance:** This is a new, sophisticated family - NOT related to 2016 Locky variant of same name.

**Source:** [The Hacker News](https://thehackernews.com/2026/01/new-osiris-ransomware-emerges-as-new.html), [Security.com](https://www.security.com/threat-intelligence/new-ransomware-osiris)

---

### Ransomware Landscape Update

**2025 Statistics (Cyble/Emsisoft):**
- ~6,500 incidents (47% increase over last 2 years)
- 57 new ransomware groups observed
- 27 new extortion groups
- 350+ new ransomware strains (mostly MedusaLocker, Chaos, Makop based)
- 8,000+ US organizations targeted (up from 6,000 in 2024)

**Most Active Groups:**
| Group | Status |
|-------|--------|
| Qilin | Most active |
| Akira | Highly active |
| Cl0p | Active |
| Play | Active |
| Safepay | Active |

**Trend Alert:** "Ransomware without encryption" attacks are surging - pure exfiltration attacks that steal data without deploying encryption, making detection much harder.

**Source:** [Cyble - Ransomware Trends](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)

---

### BlackCat/Alphv - US Cybersecurity Professionals Plead Guilty

**Development:** Two US cybersecurity professionals have pleaded guilty to participating in BlackCat/Alphv ransomware attacks.

**Key Individual:** Ryan Goldberg from Georgia, who worked as an incident response manager at cybersecurity company Sygnia.

**Charges:** Hacking into company systems, stealing information, deploying BlackCat ransomware.

**Sentencing:** March 12, 2026 (face up to 20 years)

**Source:** [SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)

---

## Data Breaches

### NEW: Condé Nast / WIRED Breach

**Victims:** WIRED magazine subscribers, potentially other Condé Nast properties
**Records Leaked:** 2.3 million (WIRED database)
**Threat Actor:** "Lovely"
**Status:** Confirmed by Hudson Rock; added to Have I Been Pwned December 27, 2025

**Data Exposed:**
- Email addresses
- Display names
- Some users: name, phone, DOB, gender, physical address

**Root Cause:** Insecure Direct Object Reference (IDOR) flaws and broken access controls in account management. Subscriber profiles used predictable sequential IDs.

**Pending Threat:** Attacker claims 40 million additional records for Vogue, The New Yorker, Vanity Fair to be released.

**Company Response:** No public statement or notification to affected subscribers as of January 2026.

**Source:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/hacker-claims-to-leak-wired-database-with-23-million-records/), [SecurityWeek](https://www.securityweek.com/hacker-claims-theft-of-40-million-conde-nast-records-after-wired-data-leak/)

---

### NEW: Ledger / Global-e Breach

**Victim:** Ledger hardware crypto wallet customers
**Cause:** Third-party payment processor Global-e was hacked
**Data Exposed:** Customer names and contact information

**Source:** [Ledger Support](https://support.ledger.com/article/Global-e-Incident-to-Order-Data---January-2026)

---

### NEW: Gulshan Management Services

**Incident Date:** September 17, 2025
**Disclosure:** January 2026
**Method:** Successful phishing attack

**Data Exposed:**
- Names and contact information
- Social Security numbers
- Driver's license numbers

**Source:** [ClassAction.org](https://www.classaction.org/data-breach-lawsuits/gulshan-management-services-january-2026)

---

## Threat Actors

### UPDATE: WinRAR CVE-2025-8088 - Continued Nation-State Exploitation

**Latest:** Google warned January 28, 2026 that Russia and China nation-state actors continue actively exploiting this vulnerability for initial access and payload deployment.

**Remediation:** Update WinRAR immediately if not already done.

---

### Regional Update: North Carolina Ransomware Surge

North Carolina reported ransomware attacks up nearly 50% - from 843 incidents to 1,215 in 2024. Ransomware contributed to more than half of all data breaches reported.

**Source:** [WRAL](https://www.wral.com/news/investigates/ransomeware-attacks-surge-nc-hacker-negotiator-shares-why-jan-2026/)

---

### Teenage Hacking Collective: "The Com"

**Members:** ~1,000 people
**Associated Groups:** Scattered Spider, ShinyHunters, Lapsus$, SLSH
**Impact Since 2022:** Infiltrated companies with $1+ trillion collective market cap
**Status:** FBI actively hunting

**Source:** [Fortune](https://fortune.com/2026/01/01/feds-hunt-teenagers-hacking-crypto-gaming/)

---

## Vendor Advisories

### January 29, 2026 Priority Patches

| Vendor | Product | CVE | Severity | Status |
|--------|---------|-----|----------|--------|
| Fortinet | FortiOS/FortiManager | CVE-2026-24858 | **Critical** | **Zero-Day Active** |
| Microsoft | Windows DWM | CVE-2026-20805 | Medium | **KEV Deadline Feb 3** |
| RARLAB | WinRAR | CVE-2025-8088 | Critical | APT Exploitation |
| Oracle | HTTP Server/WebLogic | CVE-2026-21962 | **10.0** | Patch Available |
| n8n | Workflow Automation | CVE-2025-68668 | 9.9 | Fixed in 2.0.0 |

---

## Recommended Actions

### Immediate Priority (Next 24-48 Hours)

1. **Fortinet** - Upgrade to FortiOS 7.4.11+ immediately; CVE-2026-24858 is under active zero-day exploitation
2. **Fortinet** - Hunt for unauthorized admin accounts, firewall changes, VPN modifications
3. **Microsoft DWM** - Patch CVE-2026-20805 before **February 3, 2026** CISA deadline

### High Priority (This Week)

4. **WinRAR** - Verify all endpoints updated; nation-state exploitation continues
5. **Condé Nast properties** - Users should monitor for phishing; change passwords on related accounts
6. **BYOVD Protection** - Review endpoint protection against driver-based attacks (Osiris/POORTRY)

### Threat Hunting

7. **Fortinet environments** - Search for IOCs related to CVE-2026-24858 exploitation
8. **Wasabi cloud storage** - Monitor for unauthorized data exfiltration (Osiris/Inc TTP)
9. **POORTRY driver** - Hunt for malicious driver deployment attempts

### Awareness

10. **Insider Threat** - BlackCat guilty pleas highlight risk from cybersecurity professionals
11. **IDOR vulnerabilities** - Review public-facing applications for predictable object references

---

## Sources

- [CISA - Fortinet CVE-2026-24858 Guidance](https://www.cisa.gov/news-events/alerts/2026/01/28/fortinet-releases-guidance-address-ongoing-exploitation-authentication-bypass-vulnerability-cve-2026)
- [Help Net Security - Fortinet Zero-Day](https://www.helpnetsecurity.com/2026/01/28/fortinet-forticloud-sso-zero-day-vulnerability-cve-2026-24858/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News - Osiris Ransomware](https://thehackernews.com/2026/01/new-osiris-ransomware-emerges-as-new.html)
- [Security.com - Osiris Analysis](https://www.security.com/threat-intelligence/new-ransomware-osiris)
- [Cyble - Ransomware Trends 2026](https://cyble.com/knowledge-hub/10-new-ransomware-groups-of-2025-threat-trend-2026/)
- [SecurityWeek - BlackCat Guilty Pleas](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [BleepingComputer - WIRED Breach](https://www.bleepingcomputer.com/news/security/hacker-claims-to-leak-wired-database-with-23-million-records/)
- [SecurityWeek - Condé Nast 40M Threat](https://www.securityweek.com/hacker-claims-theft-of-40-million-conde-nast-records-after-wired-data-leak/)
- [Fortune - The Com Hacking Collective](https://fortune.com/2026/01/01/feds-hunt-teenagers-hacking-crypto-gaming/)
- [WRAL - NC Ransomware Surge](https://www.wral.com/news/investigates/ransomeware-attacks-surge-nc-hacker-negotiator-shares-why-jan-2026/)
- [Eclypsium - Fortinet Network Edge Attacks](https://eclypsium.com/blog/fortinet-authentication-bypass-network-edge-attacks-cve-2020-12812/)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in January 27-28, 2026 reports and are not repeated unless updated:
- Phantom Taurus Chinese APT
- Sandworm Poland power grid attack
- Konni AI-generated malware
- Oracle January 2026 CPU (337 patches)
- n8n CVE-2025-68668
- Microsoft Office CVE-2026-21509 (deadline only)
- Brightspeed breach investigation
- Manage My Health breach
- Secure Boot certificate expiration (June 2026)
- California/Oklahoma breach notification law changes

---

*Report generated: 2026-01-29*
*Next report: 2026-01-30*
*Classification: TLP:CLEAR*
