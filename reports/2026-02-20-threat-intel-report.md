# Cyber Threat Intelligence Report
**Date:** 2026-02-20
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0220

---

## Executive Summary

- **NEW - CISA KEV**: Two RoundCube Webmail vulnerabilities (CVE-2025-49113, CVE-2025-68461) added to KEV today - patch email servers immediately
- **NEW - CRITICAL**: Dell RecoverPoint CVE-2026-22769 (CVSS 10.0) - hardcoded credentials allow unauthenticated root access; exploited by China-nexus UNC6201 since mid-2024
- **NEW - CRITICAL**: Windows Admin Center CVE-2026-26119 - privilege escalation to domain admin from standard user account
- **NEW - UPDATE**: BeyondTrust CVE-2026-1731 post-exploitation confirmed using VShell RAT and SparkRAT; China-nexus attribution strengthened
- **NEW**: Advantest (chip testing giant) hit by ransomware on Feb 15 - IT network intrusion ongoing
- **NEW**: Qilin ransomware hits Conpet, Romania's national oil pipeline operator
- **NEW**: MedRevenu and EyeCare Partners disclose healthcare data breaches
- **NEW**: Two US cybersecurity professionals plead guilty to ransomware conspiracy

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2026-22769 | Dell RecoverPoint for VMs | **10.0** | Hardcoded credentials - root RCE | Exploited in wild by UNC6201 |
| CVE-2026-26119 | Windows Admin Center | Critical | Privilege escalation - domain compromise | Patched Dec 2025; disclosure Feb 19 |
| CVE-2025-49113 | RoundCube Webmail | High | Deserialization of Untrusted Data | **CISA KEV - Added Feb 20** |
| CVE-2025-68461 | RoundCube Webmail | Medium | Cross-Site Scripting (XSS) | **CISA KEV - Added Feb 20** |

### CVE-2026-22769 - Dell RecoverPoint (CVSS 10.0)

**Product:** Dell RecoverPoint for Virtual Machines
**Type:** Hardcoded credential vulnerability - unauthenticated OS root access
**Status:** Actively exploited in the wild; attributed to China-nexus UNC6201

An unauthenticated remote attacker with knowledge of the hardcoded credential can gain root-level OS access and establish persistent footholds. UNC6201 has reportedly exploited this vulnerability since at least mid-2024 - meaning many environments may already be compromised without awareness.

- **Action**: Audit Dell RecoverPoint deployments immediately; apply vendor patch; hunt for indicators of UNC6201 persistence (webshells, scheduled tasks, new accounts)
- **Source**: [SOC Prime - CVE-2026-22769](https://socprime.com/blog/cve-2026-22769-vulnerability/)

### CVE-2026-26119 - Windows Admin Center

**Product:** Microsoft Windows Admin Center
**Type:** Privilege escalation
**Patched:** December 2025 (out-of-band); publicly disclosed February 19, 2026
**Impact:** Standard user can escalate to full domain admin under certain conditions

Windows Admin Center manages critical Windows Server infrastructure. A successful exploit allows an attacker starting with low-privilege credentials to fully compromise Active Directory domains.

- **Action**: Verify December 2025 WAC patch is applied; restrict WAC access to administrative accounts only
- **Source**: [Help Net Security - CVE-2026-26119](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)

### CISA KEV - February 20 Additions (RoundCube Webmail)

CISA added two RoundCube vulnerabilities to the Known Exploited Vulnerabilities catalog today:

- **CVE-2025-49113**: Deserialization of Untrusted Data in RoundCube Webmail - allows remote code execution
- **CVE-2025-68461**: Cross-Site Scripting in RoundCube Webmail - allows session hijacking/credential theft

RoundCube is widely deployed in enterprise and government mail servers. These are the first KEV additions since February 13.

- **Action**: Patch RoundCube immediately. If running RoundCube, treat as actively exploited.
- **Source**: [CISA KEV - Feb 20](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)

---

## Exploits & Zero-Days

### [UPDATE] BeyondTrust CVE-2026-1731 - VShell RAT & SparkRAT Post-Exploitation Identified

**Previous Coverage:** Feb 13, 16, 18 reports (mass exploitation confirmed)

**What's New:** Palo Alto Unit 42 researchers have published analysis identifying the specific malware deployed in post-exploitation of CVE-2026-1731:

- **VShell**: A China-developed open-source RAT with C2 over WebSocket; provides persistent remote access, file exfiltration, and command execution
- **SparkRAT**: Cross-platform Go-based RAT with C2 over WebSocket; provides full remote control capabilities

Both tools share characteristics with prior China-nexus intrusion sets. This strengthens the attribution hypothesis that exploitation of BeyondTrust systems is a Chinese state-sponsored operation.

**Significance:** Organizations that applied the BeyondTrust patch but did not hunt for implants may still be compromised. VShell and SparkRAT can persist independently of the initial vulnerability.

**Indicators of Compromise (IOCs):** See Unit 42 report for full IOC list.

- **Action**: Hunt for VShell and SparkRAT artifacts on systems that ran BeyondTrust RS/PRA even if patched. Check for WebSocket-based C2 channels.
- **Sources**: [Palo Alto Unit 42 - CVE-2026-1731 VShell SparkRAT](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)

---

## Malware & Ransomware

### NEW: Advantest (Semiconductor Testing Giant) - Ransomware Attack

**Victim:** Advantest Corporation (Japan-based chip testing equipment manufacturer)
**Incident Date:** February 15, 2026
**Status:** Active investigation; preliminary findings confirm ransomware deployment

Advantest detected an IT network intrusion on February 15. The company confirmed unauthorized third-party access and ransomware deployment on portions of its network. Advantest serves major semiconductor fabs globally; disruption to chip testing services could cascade into production delays.

- **Threat Actor:** Not yet attributed
- **Action**: Monitor Advantest supply chain notifications; validate vendor network segmentation
- **Source**: [SecurityWeek - Advantest Ransomware](https://www.securityweek.com/chip-testing-giant-advantest-hit-by-ransomware/)

### NEW: Qilin Ransomware Hits Conpet - Romania's National Oil Pipeline Operator

**Victim:** Conpet S.A. (Romanian national oil pipeline transport company)
**Threat Actor:** Qilin ransomware group
**Status:** Attack confirmed; operational impact under investigation

Qilin, one of the most active ransomware groups of 2025-2026, has claimed responsibility for attacking Romania's national oil pipeline infrastructure. Critical energy infrastructure attacks by ransomware groups represent elevated risk of physical/operational disruption.

- **Source**: [CYFIRMA Weekly Intelligence - Feb 20](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)

### Ransomware Trends (Ongoing Context)

- Pro-Russian hacktivist groups have intensified activity since the 2026 Winter Olympics opened in Milan/Cortina d'Ampezzo (Feb 6) due to Russia's exclusion
- Ransomware annual cost projected at **$74 billion** for 2026
- "Exfiltration-only" ransomware model continues to surge (skip encryption, only steal and extort)

---

## Threat Actors

### UNC6201 (China-Nexus) - Dell RecoverPoint Exploitation Campaign

**Attribution:** China-nexus cluster (Mandiant designation UNC6201)
**Active Since:** At least mid-2024
**Newly Disclosed:** February 2026

UNC6201 has been exploiting CVE-2026-22769 (CVSS 10.0) in Dell RecoverPoint for Virtual Machines since mid-2024. The long dwell time before public disclosure suggests this actor has had extensive access to victim environments - many organizations may be compromised without knowing.

**TTPs:**
- Initial access via hardcoded credential exploitation (no authentication required)
- Root-level OS persistence
- Likely targeting backup/recovery infrastructure to blind victim organizations during follow-on operations

- **Source**: [SOC Prime - CVE-2026-22769](https://socprime.com/blog/cve-2026-22769-vulnerability/)

### Winter Olympics 2026 - Pro-Russian Hacktivist Surge

**Event:** 2026 Winter Olympics, Milan/Cortina d'Ampezzo (Feb 6 - Feb 22)
**Pattern:** Elevated pro-Russian hacktivist DDoS and defacement activity tied to Russia's exclusion from the Games
**Targets:** Italian government and Olympics infrastructure; Olympic sponsor organizations

- **Source**: [WEF Cybersecurity News Feb 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)

---

## Data Breaches

| Organization | Records Affected | Data Exposed | Notes |
|-------------|-----------------|--------------|-------|
| MedRevenu | TBD | Healthcare billing/PII | Notified state AGs Feb 2026 |
| EyeCare Partners | TBD | Patient PII, possibly PHI | 55+ days of unauthorized email access |
| Advantest | Unknown | Potential IP/operational data | Active investigation, Feb 15 ransomware |
| Conpet (Romania) | Unknown | Energy infrastructure data | Qilin ransomware |

### MedRevenu & EyeCare Partners - Healthcare Sector Breaches

Two healthcare sector breaches were formally disclosed this week:

- **MedRevenu**: Healthcare revenue cycle management company; filed breach notifications with state attorneys general in February 2026
- **EyeCare Partners**: Ophthalmology group; breach involved 55+ days of unauthorized access to employee email accounts, potentially exposing patient records

Healthcare remains the highest-targeted vertical for ransomware and data theft due to the value of PHI.

- **Source**: [HIPAA Journal - MedRevenu & EyeCare Partners](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)

---

## Legal & Law Enforcement

### Two US Cybersecurity Professionals Plead Guilty to Ransomware

**Case:** Two US-based cybersecurity professionals entered guilty pleas in connection with ransomware conspiracy charges.
**Significance:** Insider threat dimension to ransomware ecosystem - security professionals with deep knowledge of enterprise defenses enabling ransomware operations represents a serious emerging threat vector.

- **Source**: [SecurityWeek - US Cybersecurity Pros Ransomware Guilty](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)

---

## Vendor Advisories

### Microsoft - Windows Admin Center
- **CVE-2026-26119**: Critical privilege escalation patched December 2025; disclosed publicly February 19, 2026. Verify patch deployment across all WAC instances.
- **Source**: [Help Net Security](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)

### Dell
- **CVE-2026-22769**: RecoverPoint for Virtual Machines hardcoded credential flaw (CVSS 10.0). Actively exploited by UNC6201. Apply vendor patch immediately.
- **Source**: [SOC Prime](https://socprime.com/blog/cve-2026-22769-vulnerability/)

### RoundCube Webmail
- **CVE-2025-49113 & CVE-2025-68461**: Both added to CISA KEV today (Feb 20). Treat as actively exploited. Update RoundCube immediately.
- **Source**: [CISA Alert Feb 20](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)

### February 2026 Patch Report - Broader Vendor Context
Microsoft, SAP, Intel, Adobe, and 60+ additional vendors released February 2026 security patches. Key highlights:
- SAP: Multiple critical patches for S/4HANA and Business Suite
- Intel: Firmware advisories for several processor families
- Adobe: Critical patches for Creative Cloud components

- **Source**: [Rescana - February 2026 Security Patch Report](https://www.rescana.com/post/february-2026-security-patch-report-microsoft-sap-intel-adobe-and-60-vendors-address-critical)

---

## CISA KEV Deadline Tracker (Updated)

| CVE | Product | CISA Deadline | Days Remaining |
|-----|---------|---------------|----------------|
| CVE-2019-19006 | FreePBX | Feb 24 | **4 days** |
| CVE-2025-64328 | Sangoma FreePBX | Feb 24 | **4 days** |
| CVE-2021-39935 | GitLab CE/EE | Feb 24 | **4 days** |
| CVE-2026-21510/21513/21514/21519/21525/21533 | Microsoft (6 zero-days) | Mar 3 | 11 days |
| CVE-2024-43468 | Microsoft SCCM | ~Mar 5 | ~13 days |
| CVE-2026-20700 | Apple (dyld) | ~Mar 5 | ~13 days |
| CVE-2026-1731 | BeyondTrust RS/PRA | ~Mar 6 | ~14 days |
| CVE-2025-49113 | RoundCube Webmail | TBD | **NEW - Patch Now** |
| CVE-2025-68461 | RoundCube Webmail | TBD | **NEW - Patch Now** |
| CVE-2026-22769 | Dell RecoverPoint | TBD | **ACTIVELY EXPLOITED** |

---

## Recommended Actions

### Priority 1 - Patch Within 24 Hours
1. **RoundCube Webmail**: Patch CVE-2025-49113 (deserialization RCE) and CVE-2025-68461 (XSS) - CISA KEV added today
2. **Dell RecoverPoint**: Apply vendor patch for CVE-2026-22769 (CVSS 10.0 hardcoded credentials) - actively exploited by China-nexus UNC6201
3. **Windows Admin Center**: Verify December 2025 patch deployed for CVE-2026-26119

### Priority 2 - This Week
4. **CISA KEV Deadlines in 4 Days**: FreePBX CVE-2019-19006, Sangoma CVE-2025-64328, GitLab CVE-2021-39935 - February 24 deadline
5. **Hunt for BeyondTrust Implants**: Even if patched, scan for VShell and SparkRAT artifacts; WebSocket C2 channels; new accounts/scheduled tasks
6. **Hunt for UNC6201 Persistence**: On any Dell RecoverPoint systems, assume compromise and hunt for root-level backdoors

### Priority 3 - Process & Awareness
7. **Supply Chain Monitoring**: Monitor Advantest breach updates if your organization relies on their chip testing services
8. **Ransomware Preparedness**: With Qilin now targeting critical national infrastructure (energy pipelines), review OT/ICS network segmentation
9. **Insider Threat Review**: The US cybersecurity professional guilty pleas signal a need to review privileged access and employee vetting processes
10. **Winter Olympics Hacktivist Risk**: If operating in Italy or as an Olympics sponsor/partner, elevate DDoS protections through February 22

---

## Sources

- [CISA KEV - February 20, 2026 Addition](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Palo Alto Unit 42 - BeyondTrust CVE-2026-1731 VShell SparkRAT](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [SOC Prime - Dell RecoverPoint CVE-2026-22769](https://socprime.com/blog/cve-2026-22769-vulnerability/)
- [Help Net Security - Windows Admin Center CVE-2026-26119](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)
- [SecurityWeek - Advantest Ransomware](https://www.securityweek.com/chip-testing-giant-advantest-hit-by-ransomware/)
- [SecurityWeek - US Cybersecurity Pros Ransomware Guilty](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [CYFIRMA Weekly Intelligence Report - February 20, 2026](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [HIPAA Journal - MedRevenu & EyeCare Partners Breaches](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [Rescana - February 2026 Security Patch Report](https://www.rescana.com/post/february-2026-security-patch-report-microsoft-sap-intel-adobe-and-60-vendors-address-critical)
- [WEF - 2026 Cyberthreats](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [BlackFog - State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [CISA - CISA Adds Six Microsoft 0-Day Vulnerabilities KEV](https://cybersecuritynews.com/microsoft-0-day-vulnerabilities/)
- [The Hacker News - CISA Flags Four Security Flaws](https://thehackernews.com/2026/02/cisa-flags-four-security-flaws-under.html)
- [CVEBrief - February 20, 2026](https://cvebrief.com/)

---

*Report generated: 2026-02-20*
*Next report: 2026-02-21*
*Classification: TLP:CLEAR*
*Deduplication: Items from Feb 16 and Feb 18 reports not repeated unless marked [UPDATE]*
