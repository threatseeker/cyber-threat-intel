# Cyber Threat Intelligence Report
**Date:** January 30, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0130

---

## Executive Summary

- **NEW**: SolarWinds Web Help Desk - Four critical RCE/auth bypass vulnerabilities (CVE-2025-40551/52/53/54) require urgent patching
- **NEW**: eScan antivirus supply chain breach - Malicious update pushed to customers during 2-hour window on Jan 20
- **NEW**: 700Credit breach - 5.6M+ consumers affected; SSNs, addresses leaked; data sold on dark web for $2,500
- **NEW**: Blue Shield of California - Record merge issue exposed member PHI in January 2026
- **NEW**: Google disrupts IPIDEA - Largest residential proxy botnet taken down via legal action
- **UPDATE**: Fortinet CVE-2026-24858 - CISA remediation deadline **TODAY (January 30, 2026)**
- **REMINDER**: Microsoft DWM CVE-2026-20805 - CISA deadline **February 3, 2026** (4 days)

---

## Critical Vulnerabilities

### NEW: SolarWinds Web Help Desk - Four Critical Flaws

**Disclosure Date:** January 28-29, 2026
**Severity:** Critical (Multiple CVSS 9.0+)
**Fixed Version:** Web Help Desk 2026.1

| CVE | Type | CVSS | Impact |
|-----|------|------|--------|
| CVE-2025-40551 | Deserialization RCE | Critical | Remote unauthenticated RCE |
| CVE-2025-40552 | Authentication Bypass | Critical | RCE via auth bypass |
| CVE-2025-40553 | Deserialization RCE | Critical | Remote unauthenticated RCE |
| CVE-2025-40554 | Authentication Bypass | Critical | RCE via auth bypass |
| CVE-2025-40536 | Access Control Bypass | High | Access restricted functionality |
| CVE-2025-40537 | Hardcoded Credentials | High | Admin access under certain conditions |

**Background:** SolarWinds WHD has a history of exploitation. In September 2025, a patch bypass (CVE-2025-26399) was addressed for a flaw CISA flagged as actively exploited.

**Remediation:** Update to Web Help Desk 2026.1 immediately. No active exploitation reported yet, but given WHD's history, this is urgent.

**Sources:** [Help Net Security](https://www.helpnetsecurity.com/2026/01/29/solarwinds-web-help-desk-rce-vulnerabilities/), [Rapid7](https://www.rapid7.com/blog/post/etr-multiple-critical-solarwinds-web-help-desk-vulnerabilities-cve-2025-40551-40552-40553-40554/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/solarwinds-warns-of-critical-web-help-desk-rce-auth-bypass-flaws/), [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/solarwinds-critical-rce-bug-requires-urgent-patch)

---

### DEADLINE TODAY: Fortinet CVE-2026-24858

**CISA Remediation Deadline:** January 30, 2026 (TODAY)
**Status:** Zero-day actively exploited since January 20

Organizations running FortiOS, FortiManager, FortiAnalyzer, or FortiProxy with FortiCloud SSO enabled must have patched to FortiOS 7.4.11+ by end of day.

**Source:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | **February 3, 2026** |
| CVE-2026-20045 | Cisco Unified Communications | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| VMware vCenter | Out-of-bounds Write | February 13, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |

---

## Supply Chain Attack

### NEW: eScan Antivirus Update Server Compromise

**Vendor:** MicroWorld Technologies (eScan)
**Incident Date:** January 20, 2026
**Duration:** ~2 hours
**Discovery:** Internal monitoring + Morphisec external detection

**Attack Vector:**
Attackers breached eScan's regional update server and injected malicious code into the update distribution path. Customers downloading updates from that cluster received trojanized updates.

**Malicious Payload (Reload.exe):**
- Digitally signed to appear legitimate
- Connected to attacker C2 infrastructure
- Downloaded additional payloads
- Modified HOSTS file to block future AV updates
- Tampered with registry to prevent remote remediation
- Established persistence mechanisms

**Response:**
- eScan isolated affected infrastructure within 1 hour
- Global update system taken offline for 8+ hours
- Credentials rotated
- Remediation updates released

**Dispute:** Morphisec and eScan disagree on timeline and severity. eScan claims Morphisec's report contains "demonstrably false technical claims" and is consulting legal counsel.

**Historical Note:** In 2024, North Korean APT Kimsuky exploited the same eScan update mechanism to deploy malware in corporate networks (discovered by Avast).

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/escan-confirms-update-server-breached-to-push-malicious-update/), [Help Net Security](https://www.helpnetsecurity.com/2026/01/29/escan-antivirus-update-supply-chain-compromised/), [The Register](https://www.theregister.com/2026/01/29/escan_morphisec_dispute/), [Securelist](https://securelist.com/escan-supply-chain-attack/118688/)

---

## Data Breaches

### NEW: 700Credit - 5.6 Million Consumers

**Victim:** 700Credit LLC (credit reports/ID verification for auto dealerships)
**Discovered:** October 25, 2025
**Disclosed:** December 12, 2025
**Affected:** 5,836,521 individuals (per Oregon AG); ~18,000 dealerships

**Root Cause:**
Third-party integration partner was compromised in July 2025. Attackers took over partner systems and obtained API credentials used to pull consumer data. Partner did not notify 700Credit of initial compromise.

**Data Exposed:**
- Full names
- Dates of birth
- Physical addresses
- Social Security numbers
- Employment information (some records)

**Dark Web Activity:**
On November 16, 2025, user "ROOTBOY" advertised 8.4 million 700Credit records on Exploit and DarkForums for $2,500 USD, posting sample records as proof.

**Legal Status:** Multiple class action lawsuits filed alleging negligence. Breach reported to 10 state AGs.

**Sources:** [TechCrunch](https://techcrunch.com/2025/12/12/data-breach-at-credit-check-giant-700credit-affects-at-least-5-6-million/), [Bright Defense](https://www.brightdefense.com/news/700credit-breach/), [AutoNews](https://www.autonews.com/retail/an-700credit-data-breach-1202/), [Security Affairs](https://securityaffairs.com/185692/data-breach/u-s-fintech-and-data-services-firm-700credit-suffered-a-data-breach-impacting-at-least-5-6-million-people.html)

---

### NEW: Blue Shield of California - Record Merge Issue

**Victim:** Blue Shield of California members
**Incident Date:** January 2026
**Disclosed:** January 5, 2026
**Type:** Accidental exposure (system enhancement error)

**What Happened:**
During a system enhancement to improve portal performance, a record merge issue allowed some members to view another member's information in their portal account.

**Data Exposed:**
- Name
- Date of birth
- Subscriber ID number
- Claims information
- Diagnosis
- Medications

**NOT Exposed:** SSN, driver's license, financial information

**Remediation:** Blue Shield offering complimentary Experian IdentityWorks to affected members.

**Source:** [Blue Shield of California](https://news.blueshieldca.com/january-5-2026-blue-shield-of-california-notifies-members-of-potential-data-breach)

---

## Threat Actor Activity

### NEW: Google Disrupts IPIDEA Residential Proxy Botnet

**Action Date:** January 2026
**Target:** IPIDEA - described as one of the largest residential proxy networks in the world
**Method:** Legal action to take down dozens of domains used to control infected devices

**Impact:** IPIDEA's website is no longer accessible as of reporting.

**Significance:** Residential proxy networks are commonly used by threat actors to:
- Mask attack origin
- Bypass geo-restrictions
- Credential stuffing campaigns
- Ad fraud
- Web scraping at scale

**Source:** [Cyware](https://social.cyware.com/cyber-security-news-articles)

---

### NEW: GhostChat Android Spyware Campaign

**Target Region:** Pakistan
**Method:** Romance scam tactics
**Delivery:** Disguised as chat service app
**Capability:** Routes conversations through WhatsApp for data exfiltration

**Source:** [Cyware](https://social.cyware.com/cyber-security-news-articles)

---

### NEW: Malicious VSCode Extension - "ClawdBot Agent"

**Extension Name:** ClawdBot Agent - AI Coding Assistant
**Platform:** Official VSCode Extension Marketplace
**Lure:** Poses as free AI coding assistant for "Moltbot"
**Impact:** Stealthily deploys malware on compromised developer systems

**Recommended Action:** Audit installed VSCode extensions; remove if present.

**Source:** [Cyware](https://social.cyware.com/cyber-security-news-articles)

---

## Vendor Advisories

### January 30, 2026 Priority Patches

| Vendor | Product | CVE(s) | Severity | Status |
|--------|---------|--------|----------|--------|
| SolarWinds | Web Help Desk | CVE-2025-40551/52/53/54 | **Critical** | **Patch Now** |
| Fortinet | FortiOS | CVE-2026-24858 | **Critical** | **CISA Deadline TODAY** |
| Microsoft | Windows DWM | CVE-2026-20805 | Medium | **KEV Deadline Feb 3** |
| Atlassian | Server/Data Center | Multiple | High | Bulletin Jan 20 |
| eScan | Antivirus | N/A (Supply Chain) | Critical | Verify remediation |

### Atlassian January 2026 Security Bulletin

Released January 20, 2026. Addresses multiple vulnerabilities in Server and Data Center products (non-critical but high severity). Cloud customers automatically patched.

**Action:** Update to Fixed Versions listed in bulletin.

**Source:** [Atlassian Security Bulletin](https://confluence.atlassian.com/security/security-bulletin-january-20-2026-1712324819.html)

---

## Regulatory & Policy Updates

### CISA 2015 Extension Expires Today

The Cybersecurity Information Sharing Act of 2015 (CISA 2015), which enables cyber threat indicator sharing between federal government and private sector, was temporarily extended through **January 30, 2026**.

**Status:** No clear plan for further reauthorization. Unclear if provisions will apply beyond today.

**Impact:** May affect threat intelligence sharing between government and private sector organizations.

---

## Critical Infrastructure Alert

### OT Network Cybersecurity Gaps Study

A study by OMICRON revealed widespread cybersecurity gaps in operational technology (OT) networks of:
- Substations
- Power plants
- Control centers

**Key Finding:** Data from 100+ installations shows recurring technical, organizational, and functional issues leaving critical energy infrastructure vulnerable.

**Context:** This follows the December 2025 Sandworm attack on Poland's power grid (unsuccessful but "largest cyber attack" on their power system).

---

## Recommended Actions

### Immediate Priority (Next 24-48 Hours)

1. **SolarWinds WHD** - Upgrade to Web Help Desk 2026.1 immediately; four critical vulnerabilities with no mitigations
2. **Fortinet** - Verify CVE-2026-24858 patching complete (CISA deadline TODAY)
3. **Microsoft DWM** - Patch CVE-2026-20805 before **February 3, 2026** CISA deadline
4. **eScan Users** - Verify remediation update applied; check HOSTS file for modifications

### High Priority (This Week)

5. **Atlassian** - Apply January 2026 security bulletin patches
6. **700Credit Affected** - Enroll in offered credit monitoring; freeze credit reports
7. **Blue Shield CA Members** - Monitor accounts for unauthorized activity

### Threat Hunting

8. **VSCode Extensions** - Audit for "ClawdBot Agent" or suspicious AI coding assistants
9. **Supply Chain** - Review third-party integration security; verify partners' incident notification SLAs
10. **eScan Networks** - Hunt for Reload.exe indicators, HOSTS file modifications, suspicious registry changes

### Developer Security

11. **Extension Security** - Implement policy requiring approval for VSCode/IDE extensions
12. **API Security** - Review third-party API credential storage (700Credit lesson)

---

## Sources

- [Help Net Security - SolarWinds WHD](https://www.helpnetsecurity.com/2026/01/29/solarwinds-web-help-desk-rce-vulnerabilities/)
- [Rapid7 - SolarWinds Analysis](https://www.rapid7.com/blog/post/etr-multiple-critical-solarwinds-web-help-desk-vulnerabilities-cve-2025-40551-40552-40553-40554/)
- [BleepingComputer - SolarWinds](https://www.bleepingcomputer.com/news/security/solarwinds-warns-of-critical-web-help-desk-rce-auth-bypass-flaws/)
- [BleepingComputer - eScan Breach](https://www.bleepingcomputer.com/news/security/escan-confirms-update-server-breached-to-push-malicious-update/)
- [Help Net Security - eScan Supply Chain](https://www.helpnetsecurity.com/2026/01/29/escan-antivirus-update-supply-chain-compromised/)
- [The Register - eScan Dispute](https://www.theregister.com/2026/01/29/escan_morphisec_dispute/)
- [TechCrunch - 700Credit](https://techcrunch.com/2025/12/12/data-breach-at-credit-check-giant-700credit-affects-at-least-5-6-million/)
- [Blue Shield of California - Breach Notice](https://news.blueshieldca.com/january-5-2026-blue-shield-of-california-notifies-members-of-potential-data-breach)
- [Atlassian Security Bulletin](https://confluence.atlassian.com/security/security-bulletin-january-20-2026-1712324819.html)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Cyware Daily News](https://social.cyware.com/cyber-security-news-articles)
- [Dark Reading - SolarWinds](https://www.darkreading.com/vulnerabilities-threats/solarwinds-critical-rce-bug-requires-urgent-patch)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in January 27-29, 2026 reports and are not repeated unless updated:

- CVE-2026-24858 Fortinet FortiCloud SSO zero-day (deadline reminder only)
- Osiris ransomware family
- Condé Nast / WIRED breach
- BlackCat/Alphv guilty pleas
- WinRAR CVE-2025-8088 nation-state exploitation
- Phantom Taurus Chinese APT
- Sandworm Poland power grid attack
- Konni AI-generated malware
- Oracle January 2026 CPU (337 patches)
- n8n CVE-2025-68668
- Brightspeed breach investigation
- Manage My Health breach
- Ledger / Global-e breach
- D-Link CVE-2026-0625 (no patch available)
- Secure Boot certificate expiration (June 2026)
- California/Oklahoma breach notification law changes

---

*Report generated: 2026-01-30*
*Next report: 2026-01-31*
*Classification: TLP:CLEAR*
