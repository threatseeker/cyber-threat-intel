# Cyber Threat Intelligence Report
**Date:** 2026-02-23
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0223

---

## Executive Summary

- **NEW - CRITICAL**: CVE-2026-1731 BeyondTrust RCE (CVSS 9.9) weaponized with VShell/SparkRAT implants - confirmed active exploitation since Feb 10; CISA KEV listed
- **NEW - CRITICAL**: CVE-2026-26119 Windows Admin Center privilege escalation patched; under specific conditions enables full domain compromise from standard user
- **NEW - CRITICAL**: CVE-2026-2441 Chrome zero-day (first of 2026) - use-after-free in CSS engine, actively exploited in-the-wild before patch; update Chrome now
- **NEW**: Hellcat ransomware breached Ascom - 44GB exfiltrated including source code via Jira credential theft (Infostealer initial access)
- **NEW**: Odido (Dutch telecom) breach exposes 6 million customer records including names, phone numbers, email addresses, bank account numbers, and passport numbers
- **NEW**: IRS improperly disclosed confidential tax data of ~1.28 million individuals to DHS/ICE - significant government data misuse incident
- **NEW - TREND**: Ransomware-without-encryption ("pure exfiltration") attacks surging - harder to detect, lower risk for attackers
- **[UPDATE] URGENT**: SmarterMail CVE-2026-24423 CISA KEV deadline is **TOMORROW Feb 26** - patch immediately if not done
- **[UPDATE]**: FreePBX (CVE-2019-19006, CVE-2025-64328) and GitLab (CVE-2021-39935) KEV deadlines **PASSED yesterday Feb 24** - non-compliance status; escalate remediation

---

## Critical Vulnerabilities

| CVE | Product | CVSS | Type | Status |
|-----|---------|------|------|--------|
| CVE-2026-1731 | BeyondTrust Remote Support / PRA | **9.9** | OS Command Injection RCE | **CISA KEV - actively exploited; VShell/SparkRAT deployed** |
| CVE-2026-26030 | Microsoft Semantic Kernel Python SDK | **9.9** | Unspecified RCE | Critical - patch immediately |
| CVE-2026-2441 | Google Chrome (CSS) | High | Use-After-Free | **Zero-day - actively exploited; patch released** |
| CVE-2026-26119 | Windows Admin Center | High | Privilege Escalation | Critical - can lead to domain compromise |
| CVE-2026-20805 | Windows Desktop Window Manager | High | Type Confusion EoP | Actively exploited (Patch Tuesday Feb 10) |
| CVE-2025-49113 | RoundCube Webmail | High | Deserialization | CISA KEV added Feb 20 |
| CVE-2025-68461 | RoundCube Webmail | Medium | Stored XSS | CISA KEV added Feb 20 |
| CVE-2026-24423 | SmarterTools SmarterMail | **9.3** | Unauthenticated RCE | **CISA KEV deadline TOMORROW Feb 26** |

---

### NEW: CVE-2026-1731 - BeyondTrust RCE with VShell/SparkRAT Deployment

**Product:** BeyondTrust Remote Support and Privileged Remote Access
**CVSS:** 9.9
**Type:** OS Command Injection in thin-scc-wrapper component
**First Exploitation Observed:** February 10, 2026 (same day PoC published)

Palo Alto Unit42 has confirmed active exploitation of this critical RCE vulnerability, with attackers deploying VShell (a macOS/Linux backdoor) and SparkRAT (a cross-platform remote access tool). The thin-scc-wrapper component fails to sanitize user-supplied input before passing it to OS-level command execution. With CVSS 9.9, exploitation is straightforward with no authentication required on vulnerable external-facing instances.

CISA added CVE-2026-1731 to the KEV catalog on February 13, 2026.

**Affected Versions:** BeyondTrust Remote Support < 24.3.2 / PRA < 24.3.2

**Action:** Patch BeyondTrust immediately. Audit logs for C2 activity, VShell/SparkRAT indicators. Review all privileged remote access sessions from Feb 10 onward.

**Sources:**
- [Unit42 - VShell and SparkRAT in CVE-2026-1731 Exploitation](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [Orca Security - CVE-2026-1731 BeyondTrust](https://orca.security/resources/blog/cve-2026-1731-beyondtrust-vulnerability/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

### NEW: CVE-2026-26119 - Windows Admin Center Domain Compromise Path

**Product:** Windows Admin Center
**Type:** Privilege Escalation
**Disclosed:** February 19, 2026

Microsoft disclosed a critical privilege escalation in Windows Admin Center (WAC). An attacker who exploits this vulnerability gains the rights of the user running the affected application - and under specific conditions where WAC is used to manage domain-joined systems, a standard user could achieve full domain compromise. This is a particularly dangerous vector for organizations using WAC for enterprise infrastructure management.

**Action:** Apply the patch released in December 2025. Audit WAC access permissions. Restrict WAC to privileged admin accounts only.

**Sources:**
- [Help Net Security - CVE-2026-26119 Windows Admin Center](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)

---

### NEW: CVE-2026-26030 - Microsoft Semantic Kernel Python SDK (CVSS 9.9)

**Product:** Microsoft Semantic Kernel Python SDK
**CVSS:** 9.9
**Type:** Remote Code Execution

A maximum-severity RCE flaw in Microsoft's Semantic Kernel Python SDK has been disclosed alongside a similar CVSS 10.0 flaw in Linux Cyber Protect. AI/ML development pipelines using Semantic Kernel are at risk. Given the widespread adoption of Semantic Kernel in enterprise AI applications, exposure may be broad.

**Action:** Update Semantic Kernel Python SDK immediately. Audit AI/ML infrastructure for vulnerable versions.

---

### [UPDATE] CISA KEV Deadline Status

| CVE | Product | Deadline | Status |
|-----|---------|----------|--------|
| CVE-2026-24423 | SmarterMail RCE | **Feb 26 (TOMORROW)** | URGENT |
| CVE-2019-19006 | Sangoma FreePBX | Feb 24 | **PAST DUE** |
| CVE-2025-64328 | Sangoma FreePBX | Feb 24 | **PAST DUE** |
| CVE-2021-39935 | GitLab SSRF | Feb 24 | **PAST DUE** |
| CVE-2026-23760 | SmarterMail Auth Bypass | Feb 16 | **PAST DUE** |

---

## Exploits & Zero-Days

### CVE-2026-2441 - Chrome Zero-Day (First of 2026)

Google issued an emergency patch for CVE-2026-2441, a use-after-free vulnerability in Chrome's CSS engine (CSSFontFeatureValuesMap implementation). Google acknowledged active exploitation in-the-wild prior to patch availability. This is the first Chrome zero-day of 2026 and was treated as severe enough to warrant an out-of-cycle stable channel update rather than waiting for the next major release.

**Action:** Update Chrome immediately. All versions before the emergency patch are vulnerable.

**Sources:**
- [SecPod - CVE-2026-2441 Chrome Actively Exploited](https://www.secpod.com/blog/google-addresses-actively-exploited-chrome-vulnerability-cve-2026-2441/)
- [Malwarebytes - Chrome Zero-Day Code Execution](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)

### RoundCube Webmail - CISA KEV (Added Feb 20)

CISA added two RoundCube Webmail vulnerabilities to the KEV catalog on February 20:
- **CVE-2025-49113** - Deserialization vulnerability enabling RCE
- **CVE-2025-68461** - Stored XSS enabling session hijacking

RoundCube is widely deployed in government and enterprise environments. These vulnerabilities were previously exploited by APT groups targeting government email systems.

**Sources:**
- [CISA - Adds Two Known Exploited Vulnerabilities Feb 20](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)

---

## Malware & Ransomware

### Hellcat Ransomware - Ascom Infrastructure Breach

Hellcat ransomware group breached Swiss technology company Ascom, exfiltrating 44GB of sensitive data including source code, project details, invoices, and confidential documents. Initial access was achieved via Jira credentials harvested by Infostealer malware - a growing attack pattern combining credential theft with targeted ransomware deployment. No encryption was deployed; pure data exfiltration/extortion model.

**Sources:**
- [CYFIRMA Weekly Intelligence Report Feb 20](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [Cybersecurity News Weekly](https://cybersecuritynews.com/cybersecurity-news-weekly/)

### Space Bears Ransomware - Phobos Affiliate Activity

Space Bears ransomware continues aggressive double-extortion campaigns, operating as an affiliate of the Phobos ransomware ecosystem. Active targeting across multiple sectors with a focus on mid-market enterprises lacking mature detection capabilities.

**Sources:**
- [Morphisec - Ransomware Without Encryption Surging](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-hard-to-catch/)

### Trend Alert: Ransomware Without Encryption

A significant shift in ransomware tactics is underway - pure exfiltration attacks (no encryption deployed) are surging. Attackers quietly steal data over weeks or months, then extort victims. This model is:
- Lower risk for attackers (no noisy encryption event)
- Harder for defenders to detect (no endpoint alerts on encryption)
- Harder to investigate (logs often aged out before discovery)

Organizations relying solely on ransomware detection via encryption detection are blind to this threat class.

**Sources:**
- [Morphisec - Ransomware Without Encryption](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [The Hacker News - From Ransomware to Residency](https://thehackernews.com/2026/02/from-ransomware-to-residency-inside.html)

---

## Threat Actors

### UNC3886 (China-nexus) - Singapore Telecom Operations (Ongoing)

Singapore's Operation CYBER GUARDIAN continues to remediate the UNC3886 intrusion across all four major Singapore telecom operators (M1, SIMBA, Singtel, StarHub). The threat actor used zero-day exploits to bypass perimeter firewalls and deployed rootkits for persistent, undetected access. No customer data confirmed exfiltrated; no service disruption confirmed. The operation represents one of the most significant state-sponsored telecom intrusions in APAC history.

First flagged July 2025; publicly disclosed February 9, 2026.

**Sources:**
- [Computer Weekly - Singapore Cyber Operation Against UNC3886](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [CSA Singapore Press Release](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)

### Pro-Russian Hacktivists - Post-Olympics Activity

Following the close of the 2026 Milan/Cortina Winter Olympics (Feb 22), pro-Russian hacktivist activity that spiked during the Games is expected to taper. Monitor for residual DDoS and defacement activity targeting Italian and Western European infrastructure over the next 48-72 hours.

**Sources:**
- [WEF - Cyber Threats to Watch in 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)

---

## Data Breaches

### Odido (Dutch Telecom) - 6 Million Customer Records Exposed

Dutch telecommunications company Odido confirmed a cyberattack affecting more than 6 million customer accounts. Stolen data includes names, telephone numbers, email addresses, bank account numbers, and passport numbers. Investigation commenced February 7, 2026. Full scope still being assessed.

**Sources:**
- [Privacy Guides - Data Breach Roundup](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)

### IRS Tax Data Disclosure - 1.28 Million Individuals

The IRS improperly disclosed confidential tax information of approximately 1.28 million individuals to the Department of Homeland Security (ICE) as part of immigration enforcement operations. The IRS Chief Risk and Control Officer confirmed the disclosure in a court filing on February 12, 2026. This represents a significant government privacy violation with legal challenges ongoing.

**Sources:**
- [Evrimagaci - IRS Data Breach Immigration Deal](https://evrimagaci.org/gpt/irs-data-breach-sparks-outcry-over-immigration-deal-528626)

### Conduent Govtech Breach - Expanding Impact

The Conduent government technology platform breach, initially disclosed in early February, has expanded with millions more Americans confirmed affected. Conduent processes benefits, child support, and other government services for multiple US states.

**Sources:**
- [TechCrunch - Conduent Breach Expands](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)

### Healthcare: EyeCare Partners & Cottage Hospital

- **EyeCare Partners**: Unauthorized access to managed email accounts between December 2024 - January 2025 disclosed to state AGs in February 2026. Patient PII at risk.
- **Cottage Hospital**: Data breach exposed PII of 1,600+ individuals including SSNs, driver's license numbers, and bank account information. Notification letters mailed February 6, 2026.

**Sources:**
- [HIPAA Journal - MedRevenu & EyeCare Partners](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [Valley News - Cottage Hospital Breach](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)

---

## Vendor Advisories

| Vendor | Updates | Notes |
|--------|---------|-------|
| **Microsoft** | 58 CVEs (Feb 10 Patch Tuesday) | 6 zero-days, 5 critical; apply immediately |
| **Google** | Chrome emergency update | CVE-2026-2441 zero-day; update now |
| **BeyondTrust** | Remote Support / PRA patch | CVE-2026-1731 CVSS 9.9; CISA KEV |
| **Adobe** | Audition, After Effects, InDesign, Substance 3D, Lightroom Classic | Multiple security updates |
| **Cisco** | Secure Web Appliance, Meeting Management | Security patches released |
| **Fortinet** | FortiOS, FortiSandbox | Security updates released |
| **Microsoft** | Semantic Kernel Python SDK | CVE-2026-26030 CVSS 9.9; update immediately |

CISA has urged organizations to patch all February Patch Tuesday vulnerabilities by March 3, 2026.

**Sources:**
- [Bleeping Computer - February 2026 Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [Qualys - Microsoft and Adobe Patch Tuesday Review](https://blog.qualys.com/vulnerabilities-threat-research/2026/02/10/microsoft-patch-tuesday-february-2026-security-update-review)
- [Krebs on Security - Patch Tuesday Feb 2026](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)

---

## Recommended Actions

1. **IMMEDIATE (Today)**: Patch Chrome across all endpoints - CVE-2026-2441 is an in-the-wild zero-day
2. **IMMEDIATE**: Patch BeyondTrust Remote Support/PRA (CVE-2026-1731, CVSS 9.9) - hunt for VShell/SparkRAT indicators
3. **TOMORROW (Feb 26)**: SmarterMail CVE-2026-24423 CISA KEV deadline - patch or escalate to leadership
4. **This Week**: Patch Windows Admin Center (CVE-2026-26119) - prevent domain compromise path
5. **This Week**: Update Microsoft Semantic Kernel Python SDK (CVE-2026-26030, CVSS 9.9)
6. **This Week**: Patch RoundCube Webmail (CVE-2025-49113, CVE-2025-68461) - new CISA KEV
7. **This Week**: Apply all February 2026 Patch Tuesday updates before CISA deadline of March 3
8. **Verify Compliance**: FreePBX and GitLab KEV deadlines passed Feb 24 - confirm patching complete
9. **Detection**: Implement detection for pure exfiltration ransomware patterns (unusual data staging, DLP alerts, large egress); do not rely solely on encryption-based detection
10. **Telecom/ISP**: If operating in APAC telecom sector, review for UNC3886 IOCs (rootkits, firewall bypass evidence)

---

## Sources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds Two Known Exploited Vulnerabilities Feb 20](https://www.cisa.gov/news-events/alerts/2026/02/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Adds One Known Exploited Vulnerability Feb 13](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog)
- [Unit42 - VShell and SparkRAT in CVE-2026-1731](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [Orca Security - CVE-2026-1731 BeyondTrust](https://orca.security/resources/blog/cve-2026-1731-beyondtrust-vulnerability/)
- [Help Net Security - Windows Admin Center CVE-2026-26119](https://www.helpnetsecurity.com/2026/02/19/windows-admin-center-cve-2026-26119/)
- [SecPod - CVE-2026-2441 Chrome Actively Exploited](https://www.secpod.com/blog/google-addresses-actively-exploited-chrome-vulnerability-cve-2026-2441/)
- [Malwarebytes - Chrome Zero-Day](https://www.malwarebytes.com/blog/news/2026/02/update-chrome-now-zero-day-bug-allows-code-execution-via-malicious-webpages)
- [The Hacker News - Critical n8n CVE-2026-25049](https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html)
- [Bleeping Computer - February 2026 Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-february-2026-patch-tuesday-fixes-6-zero-days-58-flaws/)
- [Krebs on Security - Patch Tuesday Feb 2026](https://krebsonsecurity.com/2026/02/patch-tuesday-february-2026-edition/)
- [Qualys - Microsoft and Adobe Patch Tuesday Review](https://blog.qualys.com/vulnerabilities-threat-research/2026/02/10/microsoft-patch-tuesday-february-2026-security-update-review)
- [SecurityWeek - 6 Zero-Days February 2026](https://www.securityweek.com/6-actively-exploited-zero-days-patched-by-microsoft-with-february-2026-updates/)
- [Malwarebytes - February 2026 Patch Tuesday Zero-Days](https://www.malwarebytes.com/blog/news/2026/02/february-2026-patch-tuesday-includes-six-actively-exploited-zero-days)
- [CYFIRMA Weekly Intelligence Report Feb 20](https://www.cyfirma.com/news/weekly-intelligence-report-20-february-2026/)
- [Computer Weekly - Singapore UNC3886 Operation](https://www.computerweekly.com/news/366638973/Singapore-mounts-largest-ever-cyber-operation-to-oust-APT-actor)
- [CSA Singapore Press Release - Operation CYBER GUARDIAN](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)
- [TechCrunch - Conduent Breach Expands](https://techcrunch.com/2026/02/05/data-breach-at-govtech-giant-conduent-balloons-affecting-millions-more-americans/)
- [HIPAA Journal - EyeCare Partners Breach](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [Valley News - Cottage Hospital Breach](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [Evrimagaci - IRS Data Disclosure](https://evrimagaci.org/gpt/irs-data-breach-sparks-outcry-over-immigration-deal-528626)
- [Privacy Guides - Data Breach Roundup](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [Morphisec - Ransomware Without Encryption](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [The Hacker News - Ransomware to Residency](https://thehackernews.com/2026/02/from-ransomware-to-residency-inside.html)
- [WEF - Cyber Threats 2026](https://www.weforum.org/stories/2026/02/2026-cyberthreats-to-watch-and-other-cybersecurity-news/)
- [Cybersecurity News Weekly](https://cybersecuritynews.com/cybersecurity-news-weekly/)
- [Zero Day Initiative - February 2026 Review](https://www.zerodayinitiative.com/blog/2026/2/10/the-february-2026-security-update-review)
