# Cyber Threat Intelligence Report
**Date:** February 5, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0205

---

## Executive Summary

- **NEW**: APT28 "Operation Neusploit" - Russian hackers weaponized CVE-2026-21509 within 24 hours of disclosure; targeting NATO allies
- **NEW**: VMware ESXi CVE-2025-22225 confirmed in ransomware attacks - CISA adds to KEV; 41,500+ exposed instances
- **NEW**: Substack data breach confirmed - Email addresses and phone numbers compromised (Feb 5)
- **NEW**: Reddit data breach confirmed - Employee credentials stolen; internal docs, code, dashboards accessed (Feb 5)
- **NEW**: Hawk Law Group ransomware - INC group steals client data including litigation files
- **DEADLINE TOMORROW**: SolarWinds WHD CVE-2025-40551 - CISA deadline **February 6, 2026**
- **UPDATE**: Energy/utilities sector facing 60%+ surge in ransomware targeting

---

## Critical Vulnerabilities

### DEADLINE TOMORROW: SolarWinds Web Help Desk CVE-2025-40551

**CISA Remediation Deadline:** February 6, 2026 (TOMORROW)
**CVE:** CVE-2025-40551
**CVSS:** 9.8 (Critical)
**Status:** Actively exploited

Organizations must patch to Web Help Desk 2026.1 by end of day tomorrow.

**Source:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### UPDATE: VMware ESXi CVE-2025-22225 - Now Confirmed in Ransomware Attacks

**CVE:** CVE-2025-22225
**CVSS:** 8.2 (Important)
**Type:** Arbitrary kernel write → sandbox escape
**Status:** Added to CISA KEV; active ransomware exploitation confirmed

**Details:**
CISA has officially confirmed this vulnerability is being leveraged in active ransomware operations. The flaw allows attackers to escape VM sandboxes and execute code on the underlying ESXi host.

**Part of Exploitation Chain:**
| CVE | CVSS | Type |
|-----|------|------|
| CVE-2025-22224 | 9.3 | Heap overflow |
| CVE-2025-22225 | 8.2 | Arbitrary kernel write |
| CVE-2025-22226 | 7.1 | Information disclosure |

**Exposure:** 41,500+ ESXi instances remain vulnerable according to scans.

**Why Targeted:** Compromising a single hypervisor enables encryption of multiple servers and critical workloads simultaneously.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-vmware-esxi-flaw-now-exploited-in-ransomware-attacks/), [GBHackers](https://gbhackers.com/cisa-confirms-vmware-esxi-0-day-vulnerability/), [Security Affairs](https://securityaffairs.com/187637/security/cve-2025-22225-in-vmware-esxi-now-used-in-active-ransomware-attacks.html)

---

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2025-40551 | SolarWinds Web Help Desk | **February 6, 2026** |
| CVE-2026-20045 | Cisco Unified CM/Webex | February 11, 2026 |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |
| Ivanti EPMM | Code Injection | February 24, 2026 |

---

## APT & Threat Actor Activity

### NEW: APT28 "Operation Neusploit" - CVE-2026-21509 Weaponization

**Threat Actor:** APT28 (Fancy Bear / UAC-0001)
**Attribution:** Russia (GRU-linked)
**Campaign Name:** Operation Neusploit
**Discovered by:** Zscaler ThreatLabz, Trellix
**Attribution Confidence:** High

**Timeline:**
- Jan 26, 2026: Microsoft releases OOB patch for CVE-2026-21509
- Jan 29, 2026: ThreatLabz observes active exploitation
- Feb 4, 2026: Campaign publicly attributed to APT28

**Speed of Exploitation:** Within 24 hours of public disclosure

**Targets:**
- **Countries:** Ukraine, Slovakia, Romania, Poland, Slovenia, Turkey, Greece, UAE
- **Sectors:** Military, government, maritime, transport
- **CERT-UA Alert:** 60+ email addresses at Ukrainian central executive authorities targeted

**Attack Chain:**
1. Specially crafted RTF files exploit CVE-2026-21509
2. Bypasses OLE mitigations in Microsoft Office
3. Multi-stage payload delivery

**Malware Arsenal:**

| Tool | Purpose |
|------|---------|
| MiniDoor | Lightweight email theft DLL |
| NotDoor | Outlook VBA backdoor |
| BEARDSHELL | Custom C++ implant |
| PixyNetLoader | Loader for Covenant Grunt |

**TTPs:**
- Encrypted payloads
- Legitimate cloud services for C2
- In-memory execution
- Process injection to minimize forensic artifacts
- Registry modification to weaken Outlook security

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/apt28-uses-microsoft-office-cve-2026.html), [Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/apt28-leverages-cve-2026-21509-operation-neusploit), [Security Affairs](https://securityaffairs.com/187581/apt/apt28-exploits-microsoft-office-flaw-in-operation-neusploit.html)

---

### Energy & Utilities Sector Alert

**Finding:** Cyfirma reports 60%+ surge in ransomware targeting energy/utilities sector over the last quarter

**Key Observations:**
- Predominance of suspected state-linked actors
- Broad geographic distribution: US, Asia, allied nations
- Primary targets: web applications, operating systems
- Most activity occurred in January; new campaign emerging in early February

**Source:** [Industrial Cyber](https://industrialcyber.co/utilities-energy-power-water-waste/energy-and-utilities-cyber-threats-escalate-as-ransomware-and-apt-activity-rise-cyfirma-reports/)

---

## Data Breaches

### NEW: Substack Data Breach (February 5, 2026)

**Victim:** Substack
**Confirmed:** February 5, 2026
**Data Compromised:** Email addresses, phone numbers
**Method:** Unauthorized third-party access

**Source:** [Substack Disclosure](https://satiricalplanet.substack.com/p/improtant-message-reports-as-of-today)

---

### NEW: Reddit Data Breach (February 5, 2026)

**Victim:** Reddit
**Confirmed:** February 5, 2026
**Method:** Single employee credential compromise

**Accessed:**
- Internal docs and code
- Internal dashboards
- Business systems
- Limited contact info (current/former employees)
- Limited advertiser information

**NOT Breached:** Primary production systems

**Reddit Statement:** CTO Christopher Slowe confirmed the attack was successful "after successfully obtaining a single employee's credentials."

**Source:** [BreachSense](https://www.breachsense.com/breaches/)

---

### NEW: Hawk Law Group - INC Ransomware

**Victim:** Hawk Law Group
**Threat Actor:** INC Ransomware
**Data Compromised:**
- Client personal information
- Government-issued IDs
- Civil and criminal litigation case data

**Significance:** Law firm data particularly sensitive due to attorney-client privilege implications.

**Source:** [SharkStriker](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)

---

### Watson Clinic Settlement Deadline TODAY

**Deadline:** February 5, 2026
**Settlement Amount:** $10 million
**Maximum Claim:** $75,000 per patient
**Hearing:** March 9, 2026

**Background:** Dark web exposure of patient data.

**Source:** [ABC10](https://www.abc10.com/article/news/nation-world/watson-clinic-data-breach-settlement-information/507-dd2ed3d3-35fc-45a9-8537-e66014d420d6)

---

## Ransomware Activity

### Law Enforcement Action: Ransomware Leader on Most Wanted List

**Suspect:** Oleg Evgenievich Nefedov (35, Russian national)
**Status:** Added to EU Most Wanted and INTERPOL Red Notice
**Role:** Alleged ransomware group leader

**Specialization:**
- Technical hacking of protected systems
- Preparation of cyberattacks using ransomware
- "Hash cracking" - extracting passwords from information systems

**Source:** [The Hacker News](https://thehackernews.com/)

---

### 2026 Ransomware Cost Projection

**Predicted Annual Cost:** $74 billion globally

**Source:** [Cybersecurity Ventures](https://cybersecurityventures.com/ransomware-damage-to-cost-the-world-74b-in-2026/)

---

### Regional Impact: North Carolina

**2024 Statistics:**
- Ransomware attacks up nearly 50% (843 → 1,215 incidents)
- Ransomware contributed to >50% of all data breaches

**Source:** [WRAL](https://www.wral.com/news/investigates/ransomeware-attacks-surge-nc-hacker-negotiator-shares-why-jan-2026/)

---

## Nation-State Threat Landscape

### 2026 Predictions

**Key Warning:** Security experts predict more nation-state cyberattacks against critical infrastructure, with adversaries having embedded themselves in systems for months or years before activation.

**Blurring Lines:** "Nation-state proxies now mix with financially motivated APTs, blurring the line between espionage, sabotage, and profit."

**High-Risk Groups:**
- Volt Typhoon (China) - Critical infrastructure pre-positioning
- APT41 (China) - Power grids, telecoms, federal systems

**Source:** [SecurityWeek](https://www.securityweek.com/cyber-insights-2026-cyberwar-and-rising-nation-state-threats/)

---

## Recommended Actions

### Immediate Priority (Next 24 Hours)

1. **SolarWinds WHD** - Patch to 2026.1 before **February 6** CISA deadline
2. **VMware ESXi** - Apply Broadcom patches immediately; 41,500+ exposed instances
3. **Microsoft Office** - Ensure CVE-2026-21509 patches deployed; APT28 actively exploiting

### High Priority (This Week)

4. **Cisco UCM/Webex** - Patch CVE-2026-20045 before February 11 deadline
5. **Reddit employees/advertisers** - Monitor for credential abuse
6. **Substack users** - Enable MFA; monitor for phishing using leaked contact info

### Threat Hunting

7. **RTF files** - Hunt for malicious RTF documents exploiting CVE-2026-21509
8. **Outlook registry changes** - Monitor for MiniDoor indicators weakening security controls
9. **ESXi environments** - Hunt for VM escape indicators; review SonicWall VPN logs
10. **Energy sector** - Elevated monitoring recommended; 60%+ attack surge

### Legal/Healthcare

11. **Law firms** - Review security posture; INC ransomware targeting litigation data
12. **Watson Clinic patients** - File claims by end of day

---

## Sources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News - APT28 Operation Neusploit](https://thehackernews.com/2026/02/apt28-uses-microsoft-office-cve-2026.html)
- [Zscaler ThreatLabz - Operation Neusploit](https://www.zscaler.com/blogs/security-research/apt28-leverages-cve-2026-21509-operation-neusploit)
- [BleepingComputer - VMware ESXi Ransomware](https://www.bleepingcomputer.com/news/security/cisa-vmware-esxi-flaw-now-exploited-in-ransomware-attacks/)
- [Security Affairs - ESXi Exploitation](https://securityaffairs.com/187637/security/cve-2025-22225-in-vmware-esxi-now-used-in-active-ransomware-attacks.html)
- [Industrial Cyber - Energy Sector Threats](https://industrialcyber.co/utilities-energy-power-water-waste/energy-and-utilities-cyber-threats-escalate-as-ransomware-and-apt-activity-rise-cyfirma-reports/)
- [BreachSense - Reddit Breach](https://www.breachsense.com/breaches/)
- [SharkStriker - February 2026 Breaches](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)
- [SecurityWeek - Nation-State Threats](https://www.securityweek.com/cyber-insights-2026-cyberwar-and-rising-nation-state-threats/)
- [Cybersecurity Ventures - Ransomware Costs](https://cybersecurityventures.com/ransomware-damage-to-cost-the-world-74b-in-2026/)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 2-4, 2026 reports:

- CVE-2025-40551 SolarWinds WHD (initial disclosure)
- CVE-2025-12743 Google Looker "LookOut" vulnerabilities
- CVE-2026-21858/CVE-2026-1470/CVE-2026-0863 n8n critical vulnerabilities
- CVE-2026-20805 Microsoft DWM zero-day (deadline passed Feb 3)
- CVE-2026-20045 Cisco UCM/Webex zero-day
- CVE-2026-24061 GNU InetUtils telnetd
- CVE-2026-0625 D-Link DSL routers (no patch available)
- Iranian APT Infy (Prince of Persia) - Telegram C2
- Phantom Taurus NET-STAR malware suite
- Under Armour breach (72.7M accounts)
- Nike/WorldLeaks (1.4TB)
- Crunchbase breach (2M+ records)
- Target source code theft (860 GB)
- ITRC 2025 Report
- Monroe University breach (320K)
- BASF, Honeywell, Linde ransomware incidents

---

*Report generated: 2026-02-05*
*Next report: 2026-02-06*
*Classification: TLP:CLEAR*
