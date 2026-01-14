# Cyber Threat Intelligence Report
## Date: January 14, 2026

---

## Executive Summary

Today marks Microsoft's first Patch Tuesday of 2026, delivering fixes for **114 vulnerabilities** including one **actively exploited zero-day** (CVE-2026-20805) that CISA has immediately added to its Known Exploited Vulnerabilities catalog. The security community is also responding to critical vulnerabilities in n8n workflow automation (CVSS 10.0), SAP enterprise applications, Veeam Backup, and Fortinet products.

Key developments for January 14, 2026:
- **Microsoft Patch Tuesday**: 114 CVEs fixed, including 8 Critical and 1 actively exploited zero-day
- **CISA KEV Update**: CVE-2026-20805 added to KEV catalog with February 3 remediation deadline
- **VoidLink Malware**: New cloud-native Linux malware framework disclosed by Check Point Research
- **Everest Ransomware**: Claims 900GB data theft from Nissan Motor Corporation
- **Chinese APT Activity**: VMware ESXi exploitation toolkit traced back to February 2024 development
- **Firefox Zero-Days**: Mozilla patches 34 CVEs including two suspected exploited vulnerabilities

---

## Critical Vulnerabilities (NEW)

### Microsoft January 2026 Patch Tuesday

| CVE ID | CVSS | Product | Description | Status |
|--------|------|---------|-------------|--------|
| **CVE-2026-20805** | 5.5 | Windows DWM | Information disclosure zero-day (actively exploited) | **CISA KEV Added** |
| CVE-2026-20822 | Critical | Windows Graphics | Elevation of Privilege | Patch Available |
| CVE-2026-20952 | 7.7 | Microsoft Office | Remote Code Execution (use-after-free) | Patch Available |
| CVE-2026-20953 | 7.4 | Microsoft Office | Remote Code Execution (use-after-free) | Patch Available |
| CVE-2026-20957 | Critical | Microsoft Excel | Remote Code Execution | Patch Available |
| CVE-2026-20955 | Critical | Microsoft Excel | Remote Code Execution | Patch Available |
| CVE-2026-20848 | High | Windows SMB Server | Elevation of Privilege | Patch Available |
| CVE-2026-21265 | 6.4 | Secure Boot | Certificate expiration bypass (publicly known) | Patch Available |

**Source**: [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-january-2026-patch-tuesday-fixes-3-zero-days-114-flaws/), [The Register](https://www.theregister.com/2026/01/14/patch_tuesday_january_2026/)

### n8n Workflow Automation Critical Vulnerabilities

| CVE ID | CVSS | Description |
|--------|------|-------------|
| **CVE-2026-21858** | **10.0** | "Ni8mare" - Unauthenticated RCE via Content-Type confusion |
| **CVE-2026-21877** | **10.0** | Unrestricted file upload with dangerous type |
| CVE-2025-68613 | 9.9 | Improper control of dynamically-managed code resources |

- **Affected**: n8n versions prior to 1.121.0 (~100,000 servers globally)
- **Impact**: Complete instance takeover without authentication
- **Remediation**: Upgrade to version 1.121.0 immediately

**Source**: [The Hacker News](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html), [CyberScoop](https://cyberscoop.com/n8n-critical-vulnerability-massive-risk/)

### AdonisJS Path Traversal (NEW)

| CVE ID | CVSS | Description |
|--------|------|-------------|
| **CVE-2026-21440** | **9.2** | Path traversal in multipart file handling enables arbitrary file write |

- **Affected**: @adonisjs/bodyparser through 10.1.1 and 11.x pre-releases
- **Impact**: Remote arbitrary file write, potential RCE
- **Remediation**: Upgrade to version 10.1.2 or 11.0.0-next.6

**Source**: [The Hacker News](https://thehackernews.com/2026/01/critical-adonisjs-bodyparser-flaw-cvss.html)

### Fortinet Critical Vulnerabilities (NEW Advisory - January 14, 2026)

| CVE ID | CVSS | Product | Description |
|--------|------|---------|-------------|
| CVE-2025-25249 | High | FortiOS/FortiSwitchManager | Unauthenticated RCE via CAPWAP daemon |
| CVE-2025-64155 | Critical | FortiSIEM | Unauthenticated RCE as root |

- **MS-ISAC Advisory 2026-003** issued January 13, 2026
- **Affected products**: FortiOS, FortiSIEM, FortiSwitchManager, FortiSandbox, FortiWeb, FortiVoice, FortiClientEMS

**Source**: [Secure-ISS SOC Advisory](https://secure-iss.com/soc-advisory-fortinet-fortisiem-fortios-critical-vulnerabilities-14-jan-2026/)

---

## Exploits & Zero-Days

### Microsoft Zero-Day Under Active Exploitation

**CVE-2026-20805** - Windows Desktop Window Manager Information Disclosure
- **Status**: Actively exploited in the wild
- **CISA KEV**: Added January 14, 2026; remediation deadline February 3, 2026
- **Discovery**: Microsoft Threat Intelligence Center
- **Impact**: Memory address leakage enabling follow-on exploitation

### Firefox Suspected Zero-Days

| CVE ID | Description | Status |
|--------|-------------|--------|
| CVE-2026-0891 | Suspected exploitation in the wild | Patched in Firefox 147 / ESR 140.7 |
| CVE-2026-0892 | Suspected exploitation in the wild | Patched in Firefox 147 |

- **Total CVEs Fixed**: 34 vulnerabilities across Firefox and Firefox ESR
- Mozilla addressed sandbox escape vulnerabilities rated CVSS 10.0

**Source**: [Ivanti Blog](https://www.ivanti.com/blog/january-2026-patch-tuesday), [Secure-ISS](https://secure-iss.com/soc-advisory-mozilla-firefox-critical-vulnerabilities-14-jan-2026/)

### VMware ESXi Zero-Day Exploitation (UPDATE - New Attribution Details)

[UPDATE] New research from Huntress reveals the VMware ESXi exploitation toolkit was developed as early as **February 2024** - over a year before Broadcom's public disclosure in March 2025.

- **Toolkit Name**: MAESTRO
- **Attribution**: Chinese-speaking threat actors (simplified Chinese strings in code paths)
- **Initial Access**: SonicWall VPN compromise
- **Exposure**: 30,000+ internet-facing ESXi instances vulnerable

**Source**: [Huntress](https://www.huntress.com/blog/esxi-vm-escape-exploit), [The Hacker News](https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html)

---

## Malware & Ransomware

### VoidLink: New Cloud-Native Linux Malware Framework (NEW)

Check Point Research disclosed a sophisticated new malware framework targeting Linux cloud infrastructure:

**Key Characteristics:**
- Written in Zig, Go, and C
- Cloud provider detection: AWS, GCP, Azure, Alibaba, Tencent
- Kubernetes/Docker environment awareness
- Self-deletion and runtime code encryption
- User-mode and kernel-level rootkit capabilities
- Adaptive behavior based on security monitoring level

**Attribution**: Chinese-affiliated developers (exact affiliation unclear)
**Status**: No active infections confirmed; appears to be a commercial offering

**Source**: [Check Point Research](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-voidlink-malware-framework-targets-linux-cloud-servers/)

### Ransomware Activity

#### Everest Ransomware - Nissan Motor Corporation (NEW)

- **Date**: January 10, 2026
- **Claimed Data**: 900GB exfiltrated
- **Evidence**: Screenshots of directory structures, dealer information
- **Status**: Pending verification; Nissan has not confirmed

**Source**: [Hackread](https://hackread.com/everest-ransomware-nissan-data-breach/), [Cybernews](https://cybernews.com/security/nissan-900gb-data-leak-ransomware/)

#### BlackCat/Alphv - Insider Threat Case Resolution

Two US cybersecurity professionals pleaded guilty to conspiracy charges for their roles in BlackCat ransomware operations:
- Kevin Martin (36, Texas) - Former DigitalMint negotiator
- Ryan Goldberg (40, Georgia) - Former Sygnia incident response manager
- **Sentencing**: March 12, 2026
- **Maximum Penalty**: 20 years

**Source**: [SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)

---

## Threat Actors

### Chinese-Linked APT Activity

#### VMware ESXi Exploitation Campaign
- Custom toolkit "MAESTRO" with VSOCKpuppet backdoor
- Development artifacts suggest "XLab" involvement
- Timestamps indicate November 2023 infrastructure preparation

#### VoidLink Framework Development
- Commercial-grade malware targeting cloud infrastructure
- Extensive documentation suggesting product offering
- Chinese-affiliated development team

### Scattered Spider
Federal authorities continue targeting teenage hacking groups including Scattered Spider, which has targeted an estimated $1 trillion worth of Fortune 500 companies since 2022.

**Source**: [Fortune](https://fortune.com/2026/01/01/feds-hunt-teenagers-hacking-crypto-gaming/)

---

## Vendor Security Advisories (January 14, 2026)

### Microsoft
- **114 CVEs** fixed (8 Critical, 105 Important)
- 1 actively exploited zero-day
- Removal of vulnerable Agere Soft Modem drivers

### SAP Security Patch Day

| CVE ID | CVSS | Product | Description |
|--------|------|---------|-------------|
| CVE-2026-0501 | 9.9 | S/4HANA | Critical SQL injection (RFC/ADBC) |
| CVE-2026-0500 | 9.6 | Wily Introscope | Unauthenticated RCE via JNLP |
| CVE-2026-0498 | 9.1 | S/4HANA | Code injection (OS command) |
| CVE-2026-0491 | 9.1 | Landscape Transformation | Code injection |

**Total**: 19 vulnerabilities addressed

**Source**: [SecurityWeek](https://www.securityweek.com/saps-january-2026-security-updates-patch-critical-vulnerabilities/)

### Cisco
- **CVE-2026-20029** (CVSS 4.9): ISE/ISE-PIC XML External Entity vulnerability
- Public PoC exploit available
- Additional Snort 3 DCE/RPC fixes (CVE-2026-20026, CVE-2026-20027)

**Source**: [The Hacker News](https://thehackernews.com/2026/01/cisco-patches-ise-security.html)

### Veeam Backup & Replication
- **CVE-2025-59470** (CVSS 9.0): PostgreSQL RCE
- Affects version 13.0.1.180 and earlier v13 builds
- Fixed in version 13.0.1.1071

**Source**: [The Hacker News](https://thehackernews.com/2026/01/veeam-patches-critical-rce.html)

### Mozilla Firefox
- 34 CVEs addressed across Firefox 147 and Firefox ESR
- Two suspected exploited vulnerabilities patched

### Adobe
Security updates for: InDesign, Illustrator, InCopy, Bridge, Substance 3D (Modeler, Stager, Painter, Sampler, Designer), ColdFusion

### Google Android
January 2026 security bulletin with fix for critical "DD+ Codec" flaw affecting Dolby components

---

## Industry News & Data Breaches

### Gulshan Management Services Breach (NEW Disclosure)
- **Discovered**: September 27, 2025 (disclosed January 2026)
- **Root Cause**: Phishing attack on September 17, 2025
- **Records Affected**: 377,082
- **Data Exposed**: Names, SSNs, contact information, driver's license numbers

**Source**: [GlobeNewswire](https://www.globenewswire.com/news-release/2026/01/12/3217014/6819/en/Gulshan-Management-Services-Inc-Data-Breach-Alert-Issued-By-Wolf-Haldenstein.html)

### 700Credit Breach Notification
- **Affected Individuals**: 5.6 million nationwide
- **South Carolina Residents**: 108,000+
- **Data Type**: Consumer credit and identity verification data

### European Space Agency Breach
- Collaborative engineering servers compromised
- Claims of 200GB+ stolen data including API tokens and source code
- Investigation ongoing

### Instagram Password Reset Issue
- Meta confirmed unauthorized password reset emails were sent
- Denied any data breach of systems
- Accounts remain secure per Meta statement

---

## CISA Known Exploited Vulnerabilities (KEV) Updates

### Added January 14, 2026
| CVE ID | Product | Due Date |
|--------|---------|----------|
| CVE-2026-20805 | Microsoft Windows DWM | February 3, 2026 |

### Recent Additions (Past 7 Days)
| CVE ID | Product | Due Date |
|--------|---------|----------|
| CISA KEV Jan 12 | 1 vulnerability added | TBD |
| CISA KEV Jan 7 | 2 vulnerabilities added | TBD |

---

## Recommended Actions

### Immediate (Within 24-48 Hours)

1. **Apply Microsoft January 2026 Patch Tuesday updates** - Prioritize CVE-2026-20805 (actively exploited)
2. **Update Firefox** to version 147 or ESR 140.7/115.32
3. **Patch n8n instances** to version 1.121.0 if exposed to internet
4. **Update Veeam Backup & Replication** to version 13.0.1.1071
5. **Apply SAP Security Notes** for critical SQL injection and RCE vulnerabilities
6. **Patch Cisco ISE** if using affected versions

### Short-Term (Within 1 Week)

1. **Audit VMware ESXi environments** - Apply latest patches; ESXi 6.x is EOL and unpatched
2. **Review Fortinet deployments** - Apply FortiOS and FortiSIEM updates
3. **Update AdonisJS applications** using @adonisjs/bodyparser
4. **Implement network segmentation** for backup infrastructure
5. **Scan for VoidLink IOCs** in Linux cloud environments

### Ongoing

1. **Monitor CISA KEV catalog** for new additions
2. **Review SonicWall VPN access logs** for signs of compromise
3. **Implement MFA** on all administrative interfaces
4. **Conduct phishing awareness training** (reference Gulshan Management breach)

---

## Indicators of Compromise (IOCs)

### VoidLink Malware
- Detection of Zig/Go/C hybrid binaries on Linux systems
- Unusual cloud metadata API queries
- Kernel module loading without legitimate purpose
- Self-deleting binaries upon detection

### VMware ESXi Exploitation (MAESTRO Toolkit)
- exploit.exe / MyDriver.sys artifacts
- VSOCKpuppet ELF backdoor
- VSOCK-based command and control traffic
- Disabled VMware VMCI devices

---

## Sources

- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News](https://thehackernews.com/)
- [BleepingComputer](https://www.bleepingcomputer.com/)
- [SecurityWeek](https://www.securityweek.com/)
- [The Register](https://www.theregister.com/)
- [Check Point Research](https://research.checkpoint.com/)
- [Huntress](https://www.huntress.com/blog/)
- [CyberScoop](https://cyberscoop.com/)

---

*Report generated: January 14, 2026*
*Classification: TLP:WHITE - Unlimited distribution*
