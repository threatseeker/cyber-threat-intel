# Cyber Threat Intelligence Report
**Date:** March 4, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0304

---

## Executive Summary

- **CVE-2026-22719 (VMware Aria Operations)**: CISA added high-severity command injection flaw (CVSS 8.1) to KEV catalog — unauthenticated RCE possible during support migration; FCEB agencies must patch by March 24, 2026
- **LexisNexis Cloud Breach Confirmed** (March 4): FulcrumSec threat actor exfiltrated 2.04GB from AWS — 21,000 enterprise accounts, 400,000 user profiles including 118 federal .gov accounts (DOJ, SEC, federal judges) exposed via unpatched React2Shell vuln
- **Cloudflare 2026 Threat Report**: 230 billion daily threats blocked; DDoS attacks doubled to 47.1M in 2025; threat actors shift from "breaking in" to "logging in" — 94% of login attempts are bots; North Korea uses AI deepfake profiles to infiltrate Western employers
- **SloppyLemming (India-Nexus APT)**: Espionage campaign targeting government agencies and critical infrastructure across Pakistan, Bangladesh, and Sri Lanka — newly disclosed
- **[UPDATE] Iran "Great Epic" Campaign**: Palo Alto Unit 42 publishes formal Threat Brief on March 4 escalation — proxy actors outside Iran sustaining attacks on ICS/SCADA, Israeli and Gulf infrastructure
- **[UPDATE] CVE-2026-21385 (Qualcomm)**: CISA added to KEV catalog March 3 — FCEB remediation deadline March 24, 2026 (previously reported in Android update; KEV addition is new requirement)
- **Android KVM/Hypervisor VM Escape Risk**: Two newly highlighted CVEs (CVE-2026-0037/0038, CVSS 9.0) enable virtual machine isolation breaks and host control — not previously itemized

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2026-22719 | VMware Aria Operations | 8.1 | Command Injection RCE | **CISA KEV** — Patch by March 24 |
| CVE-2026-22720 | VMware Aria Operations | Medium | Stored XSS | Patched VMSA-2026-0001 |
| CVE-2026-22721 | VMware Aria Operations | High | Privilege Escalation | Patched VMSA-2026-0001 |
| CVE-2026-21385 | Qualcomm Multiple Chipsets | High | Memory Corruption Zero-Day | **CISA KEV** — Patch by March 24 |
| CVE-2026-0037 | Android KVM (Kernel) | 9.0 | VM Isolation Break / EoP | Patched March 2026 Android update |
| CVE-2026-0038 | Android Hypervisor | 9.0 | VM Escape to Host | Patched March 2026 Android update |

### CVE-2026-22719 — VMware Aria Operations Command Injection

**CVSS: 8.1 | CISA KEV Added: March 3, 2026 | Patch Deadline: March 24, 2026**

An unauthenticated attacker with network access can exploit a command injection vulnerability in VMware Aria Operations while support-assisted product migration is in progress, achieving arbitrary command execution and potential RCE. Disclosed and patched February 24, 2026 via VMSA-2026-0001. Active exploitation confirmed — CISA added to KEV catalog with mandatory FCEB remediation deadline.

**Related vulnerabilities patched in same advisory:**
- **CVE-2026-22720** — Stored XSS enabling persistent cross-site scripting attacks
- **CVE-2026-22721** — Privilege escalation to administrative access

**Remediation:** Apply Broadcom VMware Aria Operations patches from VMSA-2026-0001. Restrict network access to Aria Operations management interfaces. Do not initiate support-assisted migrations until patched.

### [UPDATE] CVE-2026-21385 — Qualcomm CISA KEV Addition

Previously reported in the Android March 2026 Security Bulletin as an actively exploited zero-day affecting 234 Qualcomm chipsets. CISA formally added to KEV catalog on March 3, 2026, mandating Federal Civilian Executive Branch agencies remediate by **March 24, 2026**.

**Remediation:** Apply March 2026 Android security patches immediately. Federal agencies must comply by March 24, 2026 deadline.

### CVE-2026-0037/0038 — Android KVM Virtual Machine Escape

Two critical-severity vulnerabilities (CVSS 9.0) in Android's kernel-based virtual machine (KVM) subsystem and hypervisor component — patched in the March 2026 Android Security Bulletin but not previously itemized:

- **CVE-2026-0037**: Critical KVM Elevation of Privilege — breaks virtual machine isolation, grants System privileges
- **CVE-2026-0038**: Critical Hypervisor Elevation of Privilege — potential VM escape to host control

**Remediation:** Apply March 2026 Android security patches. Particularly critical for enterprise Android deployments running containerized workloads.

---

## Exploits & Zero-Days

### LexisNexis React2Shell Exploitation — FulcrumSec

LexisNexis was breached via a known vulnerability dubbed "React2Shell" in an unpatched React frontend application. Initial access occurred **February 24, 2026**; FulcrumSec posted claims on **March 3**; LexisNexis confirmed the breach on **March 4, 2026**.

**Attack chain:**
1. React2Shell exploit against unpatched frontend application (months unaddressed)
2. Lateral movement enabled by overly permissive IAM role
3. Database access via hardcoded weak credential (`Lexis1234`)
4. Exfiltration of 2.04GB structured data from AWS

**Takeaway:** This is a textbook cloud breach combining unpatched known vulnerability + IAM misconfiguration + hardcoded credentials. No novel exploitation required.

---

## Malware & Ransomware

### Fake IT Support Ransomware Precursor — Multi-Sector Campaign

Security researchers identified an evolving intrusion pattern targeting multiple organizations:
- **Initial lure:** Email spam followed by unsolicited phone calls from fake IT support personnel
- **Delivery:** Malware delivered under guise of remote assistance tools
- **Outcome:** Ransomware deployment as second-stage payload
- **Sectors targeted:** Broad, not sector-specific

**Remediation:** Train employees to verify IT support calls through internal channels before accepting remote access. Block unsolicited MSRA (Microsoft Remote Assistance), AnyDesk, and TeamViewer connections from external sources.

### Active Ransomware Groups — March 3-4, 2026 Activity

Multiple groups claimed victims in the March 3-4 window per breach tracking sources:

| Group | Notable Activity |
|-------|----------------|
| Akira | New industrial sector victims listed |
| Medusa | Healthcare and education sector activity |
| Qilin | Malaysia Airlines (unconfirmed — see prior reports) |
| TheGentlemen | New group — retail and logistics targeting |

**[UPDATE] USHA International Breach:** Employee data, CRM systems, and SAP database contents confirmed exfiltrated — attributed to ransomware actor; investigation ongoing.

---

## Threat Actors

### SloppyLemming (India-Nexus) — Regional Espionage Campaign

A suspected India-linked advanced persistent threat actor, tracked as **SloppyLemming**, has been conducting espionage operations targeting government agencies and critical infrastructure in:
- **Pakistan** — government agencies
- **Bangladesh** — critical infrastructure
- **Sri Lanka** — government entities

**TTPs:** Zero-day perimeter bypass, extended dwell time, targeting aligned with Indian regional intelligence interests.

**Assessment:** First public disclosure of this campaign. Expect further TTPs to emerge as investigations deepen. Organizations in South Asian government and critical infrastructure sectors should review for indicators.

### [UPDATE] Iran — Unit 42 Formal Threat Brief Published

Palo Alto Networks Unit 42 released a formal Threat Brief on March 4, 2026 analyzing the escalating cyber activity following Operation Epic Fury (Feb 28). Key updates:

- Proxy and diaspora actors outside Iran have sustained "Great Epic" campaign operations despite Iran's internal internet degradation (1-4% connectivity)
- **Handala Hacker Group** ICS/SCADA attacks against Jordan fuel infrastructure confirmed operational impact
- **Attribution caution:** Unit 42 notes significant false-flag activity — some "Iranian" operations may be conducted by proxies or aligned actors, not direct IRGC/MOIS operators
- Assessment: Campaign will likely persist 2-4 weeks minimum regardless of internal Iranian connectivity

**Remediation:** See March 2 report for full action items. Organizations in energy, water, government, and financial sectors in Israel, Jordan, Saudi Arabia, UAE should maintain heightened alert posture.

### Cloudflare 2026 Threat Intelligence Report — Key Threat Actor Findings

Published March 3, 2026. Headline: **Nation-state actors and cybercriminals shift from "breaking in" to "logging in."**

Key findings relevant to threat actor operations:
- **North Korea** — Using AI-generated deepfake profiles and U.S.-based laptop farms to obtain employment at Western tech and finance companies; insider threat vector now confirmed at scale
- **Credential attacks dominant** — 94% of all login attempts on Cloudflare's network are bots; 46% of human login attempts use previously compromised credentials
- **Living-off-the-Cloud (LoTC)** — Threat actors routing attacks through AWS, Azure, GCP, and SaaS platforms to blend with legitimate traffic; traditional IP-based blocking increasingly ineffective
- **AI weaponization** — LLMs used for real-time network mapping, exploit development, and hyper-realistic deepfakes; no single attributed group, broad adoption across state and criminal actors
- **DDoS scale** — 47.1 million DDoS attacks in 2025 (2x prior year); largest: 31.4 Tbps UDP flood (Aisuru botnet, November 2025)

---

## Data Breaches

### LexisNexis — Cloud Breach Confirmed (March 4, 2026)

**Threat Actor:** FulcrumSec
**Data Exfiltrated:** 2.04 GB structured data
**Initial Access:** February 24, 2026 (via React2Shell exploit)
**Confirmation:** March 4, 2026

**Exposed data:**
- 21,000+ enterprise customer accounts
- ~400,000 user profiles with contact information
- Complete VPC infrastructure map (significant for follow-on attacks)
- 118 profiles with .gov emails — federal judges, DOJ attorneys, court clerks, SEC staff

**Security failures:** Unpatched React application (months overdue), overly permissive AWS IAM role, hardcoded weak password (`Lexis1234`)

**Impact assessment:** HIGH — VPC infrastructure map enables targeted follow-on attacks; government email exposure creates spear-phishing and surveillance risks; legal/intelligence data represents high-value espionage target.

**Response:** LexisNexis notified law enforcement; contracted external cybersecurity firm; notified current and previous customers.

---

## Vendor Advisories

### Broadcom — VMSA-2026-0001 (VMware Aria Operations)

- **CVE-2026-22719** (CVSS 8.1): Command injection RCE — CISA KEV, actively exploited
- **CVE-2026-22720**: Stored XSS
- **CVE-2026-22721**: Privilege escalation
- **Action:** Apply patches immediately; FCEB deadline March 24, 2026
- **Source:** VMSA-2026-0001 advisory

### Google — Android March 2026 Security Bulletin (Ongoing)

Previously reported. New focus: CVE-2026-0037/0038 (KVM/Hypervisor VM escape, CVSS 9.0) deserve priority for enterprise Android deployments.

### CISA — New KEV Additions (March 3, 2026)

Two new entries in CISA's Known Exploited Vulnerabilities catalog:
1. **CVE-2026-22719** — VMware Aria Operations command injection (FCEB deadline: March 24)
2. **CVE-2026-21385** — Qualcomm chipset memory corruption (FCEB deadline: March 24)

---

## Recommended Actions

1. **[CRITICAL] Patch VMware Aria Operations immediately** — CVE-2026-22719 is in active exploitation; apply VMSA-2026-0001 patches before enabling any support-assisted migrations. FCEB deadline March 24 but exploit is live now.

2. **[CRITICAL] Apply Android March 2026 patches** — CVE-2026-21385 is now CISA KEV; CVE-2026-0037/0038 enable VM escape. Federal agencies have until March 24; enterprise should patch now.

3. **[HIGH] Audit AWS IAM roles and credentials** — LexisNexis breach exploited overly permissive IAM + hardcoded credential. Run immediate review: identify wildcard IAM policies, rotate all database passwords, scan code repositories for hardcoded credentials.

4. **[HIGH] Hunt for VMware Aria Operations indicators** — Review logs for unauthorized support-migration activity, unusual API calls to Aria Operations management interfaces, and lateral movement from management plane.

5. **[HIGH] Deploy phishing-resistant MFA** — Cloudflare report confirms 94% of login attempts are bots; 46% of human attempts use compromised creds. Roll out FIDO2/WebAuthn across all internet-facing services.

6. **[MEDIUM] Monitor for SloppyLemming IOCs** — South Asian government and infrastructure organizations should check for indicators from India-nexus espionage campaign targeting Pakistan, Bangladesh, Sri Lanka.

7. **[MEDIUM] Implement insider threat controls for North Korea IT worker risk** — Vet remote contractors through video interviews, device verification, and background checks. Flag U.S.-based laptop farms routing to overseas workers.

8. **[MEDIUM] Maintain elevated ICS/SCADA monitoring** — Iran proxy campaign "Great Epic" remains active. Unit 42 Threat Brief confirms sustained operations despite internal connectivity degradation.

---

## Sources

- [CISA Adds Two Known Exploited Vulnerabilities to Catalog (March 3, 2026)](https://www.cisa.gov/news-events/alerts/2026/03/03/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Adds Actively Exploited VMware Aria Operations Flaw CVE-2026-22719 to KEV Catalog — The Hacker News](https://thehackernews.com/2026/03/cisa-adds-actively-exploited-vmware.html)
- [CISA flags VMware Aria Operations RCE flaw as exploited in attacks — BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-flags-vmware-aria-operations-rce-flaw-as-exploited-in-attacks/)
- [VMware Aria Operations Vulnerability Exploited in the Wild — SecurityWeek](https://www.securityweek.com/vmware-aria-operations-vulnerability-exploited-in-the-wild/)
- [CVE-2026-22719 — Tenable](https://www.tenable.com/cve/CVE-2026-22719)
- [LexisNexis Confirms Major Cloud Breach — CyberNewscentre](https://www.cybernewscentre.com/4march-2026-cyber-update-lexisnexis-confirms-major-cloud-breach-exposing-legal-and-government-client-data/)
- [Hackers claim LexisNexis cloud breach exposing 400K user profiles — CyberNews](https://cybernews.com/security/lexisnexis-breach-400k-users-gov-accounts-aws/)
- [LexisNexis confirms data breach as hackers leak stolen files — BleepingComputer](https://www.bleepingcomputer.com/news/security/lexisnexis-confirms-data-breach-as-hackers-leak-stolen-files/)
- [LexisNexis Data Breach — Threat Actor Allegedly Claims 2.04 GB Stolen — CyberSecurityNews](https://cybersecuritynews.com/lexisnexis-data-breach/)
- [Cloudflare tracked 230 billion daily threats and here is what it found — Help Net Security](https://www.helpnetsecurity.com/2026/03/03/cloudflare-cyber-threat-report-2026/)
- [Introducing the 2026 Cloudflare Threat Report — Cloudflare Blog](https://blog.cloudflare.com/2026-threat-report/)
- [Cloudflare 2026 Threat Intelligence Report — Cloudflare Press Release](https://www.cloudflare.com/press/press-releases/2026/cloudflare-2026-threat-intelligence-report-nation-state-actors-and/)
- [Threat Brief: March 2026 Escalation of Cyber Risk Related to Iran — Palo Alto Unit 42](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/)
- [Alleged India-linked espionage campaign targeted Pakistan, Bangladesh, Sri Lanka — The Record](https://therecord.media/india-pakistan-cyber-campaign-apt)
- [Google Confirms CVE-2026-21385 in Qualcomm Android Component Exploited — The Hacker News](https://thehackernews.com/2026/03/google-confirms-cve-2026-21385-in.html)
- [Ransomware Without Encryption: Why Pure Exfiltration Attacks Are Surging — Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [Top data breaches of March 2026 — SharkStriker](https://sharkstriker.com/blog/march-data-breaches-today-2026/)
- [Data breaches in March 2026 — BreachSense](https://www.breachsense.com/breaches/2026/march/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
