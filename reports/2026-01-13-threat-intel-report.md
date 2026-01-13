# Threat Intelligence Report - January 13, 2026

## Executive Summary
Brief overview of the threat landscape for this reporting period:
- **Critical Items**: 8 requiring immediate attention
- **New CVEs**: 15+ critical/high severity (CVSS >= 9.0)
- **Active Campaigns**: VMware ESXi exploitation, Scattered Spider, TridentLocker ransomware
- **Key Trend**: Ransomware groups shifting to pure data exfiltration without encryption, making attacks harder to detect

---

## Critical Vulnerabilities

### Actively Exploited (CISA KEV)
| CVE ID | Product | CVSS | Added | Description |
|--------|---------|------|-------|-------------|
| CVE-2025-8110 | Gogs | - | Jan 12 | Path Traversal Vulnerability |
| CVE-2009-0556 | Microsoft Office PowerPoint | 8.8 | Jan 7 | Code injection via memory corruption allowing RCE |
| CVE-2025-37164 | HPE OneView | 10.0 | Jan 7 | Code injection allowing unauthenticated RCE |
| CVE-2025-14847 | MongoDB Server (MongoBleed) | - | Dec 29 | Actively exploited, 87,000+ vulnerable instances |

### Critical Severity (CVSS >= 9.0)
| CVE ID | Product | CVSS | Description |
|--------|---------|------|-------------|
| CVE-2026-21858 | n8n Workflow Platform | 10.0 | "Ni8mare" - Content-Type confusion flaw, ~100K servers affected |
| CVE-2026-21877 | n8n Workflow Platform | 10.0 | Unrestricted file upload leading to full instance compromise |
| CVE-2025-68668 | n8n Python Code Node | 9.9 | Sandbox bypass via Pyodide |
| CVE-2026-0501 | SAP S/4HANA General Ledger | 9.9 | SQL injection allowing arbitrary query execution |
| CVE-2026-0498 | SAP S/4HANA | 9.1 | Code injection leading to OS command injection |
| CVE-2026-0491 | SAP Landscape Transformation | 9.1 | Code injection vulnerability |
| CVE-2026-0625 | D-Link DSL Routers (EOL) | 9.3 | Command injection in dnscfg.cgi - NO PATCH AVAILABLE |
| CVE-2026-21440 | AdonisJS Bodyparser | 9.2 | Path traversal enabling arbitrary file write |
| CVE-2025-59470 | Veeam Backup & Replication | 9.0 | RCE as postgres user via malicious parameters |

### Microsoft Patch Tuesday (January 2026)
| CVE ID | Product | CVSS | Description |
|--------|---------|------|-------------|
| CVE-2026-20805 | Windows | - | **Actively Exploited** - Important severity |
| CVE-2026-20854 | Windows LSASS | 7.5 | Critical RCE over network |
| CVE-2026-20876 | Windows VBS Enclave | - | Critical EoP - heap-based buffer overflow |
| CVE-2026-20944 | Microsoft Word | - | Critical RCE via malicious file |

---

## Exploits & Zero-Days

### New Exploits Released
- **CVE-2026-0625** (D-Link DSL): Command injection in discontinued routers
  - Affected: Multiple D-Link DSL gateway models (EOL)
  - Status: Actively exploited since Nov 2025 / **NO PATCH - Replace devices**

- **CVE-2026-21858** (n8n "Ni8mare"): Content-Type confusion exploit
  - Affected: ~100,000 n8n servers globally
  - Status: PoC available / Patch released

### Zero-Day Activity

**VMware ESXi Exploit Toolkit (MAESTRO)**
Security researchers at Huntress uncovered a sophisticated attack campaign targeting VMware ESXi instances through the "MAESTRO" zero-day exploit toolkit. The toolkit chains multiple critical vulnerabilities to achieve VM escape:
- CVE-2025-22224 (CVSS 9.3)
- CVE-2025-22225 (CVSS 8.2)
- CVE-2025-22226 (CVSS 7.1)

The exploit was developed as early as February 2024, over a year before VMware's public disclosure.

**Apple WebKit Zero-Days**
Apple released emergency security updates for two zero-days (CVE-2025-43529, CVE-2025-14174) exploited in "extremely sophisticated" targeted attacks. Google TAG credited with discovery - indicates likely nation-state/commercial spyware involvement.

**Chrome Zero-Day**
CVE-2025-14174 patched in Chrome - tied to same Apple zero-days, actively exploited in the wild.

---

## Malware & Ransomware

### Active Campaigns

- **TridentLocker Ransomware**
  - Type: Ransomware/Extortion
  - Targets: Government contractors (Sedgwick Government Solutions)
  - Vector: Unknown
  - Notable: Claimed 3.4 GB from federal contractor serving DHS, ICE, CBP, CISA

- **Gentlemen Ransomware**
  - Type: Ransomware
  - Targets: Energy sector (Romania's Oltenia Energy Complex)
  - Vector: Unknown
  - Notable: ERP systems, email, website disrupted; power supply unaffected

- **INC Ransomware**
  - Type: Data exfiltration/extortion
  - Targets: Architecture/engineering (Omrania - Saudi Arabia)
  - Notable: 4,000 GB exposed including NDAs, financial records, project drawings

### Ransomware Activity
- TridentLocker claimed Sedgwick Government Solutions (federal contractor) - 3.4 GB stolen
- INC Ransomware published 4 TB from Omrania architecture firm
- Quilin ransomware targeted CSV group (Italy)
- Clop claimed Dartmouth College breach - 40,000+ affected

### Trends
- **Pure Exfiltration Attacks Surging**: Attackers stealing data without encryption, extorting victims weeks/months later
- **47% increase** in publicly reported attacks in 2025 vs 2024
- **57 new ransomware groups** and 27 new extortion groups observed in 2025
- 2026 predicted to be first year new ransomware actors outside Russia outnumber those within

---

## Threat Actors

### APT/Nation-State Activity

- **Phantom Taurus** (NEW - China)
  - Attribution: China (PRC)
  - Targets: Government agencies, embassies, military operations in Africa, Middle East, Asia
  - TTPs: Direct targeting of high-value systems (not typical social engineering), custom-built toolkit, resurfaces within hours/days of detection
  - Reference: [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)

- **APT40** (China)
  - Attribution: China (PRC)
  - Targets: Pacific Island nations, government, critical infrastructure
  - TTPs: Fileless malware, registry-based loading, modified commodity tools
  - Reference: Government of Samoa advisory

- **Scattered Spider**
  - Attribution: US-based teenagers
  - Targets: Fortune 500 companies ($1 trillion worth targeted since 2022)
  - TTPs: Social engineering, SIM swapping, cryptocurrency theft
  - Reference: [Fortune](https://fortune.com/2026/01/01/feds-hunt-teenagers-hacking-crypto-gaming/)

### Criminal Groups
- TridentLocker - Active against US federal contractors
- INC Ransomware - Middle East operations
- Quilin - European targets
- Clop - Educational institutions

---

## Vendor Advisories

### Microsoft (January 2026 Patch Tuesday)
- **114 vulnerabilities** fixed including 3 zero-days
- **8 Critical** vulnerabilities (6 RCE, 2 EoP)
- **1 Actively Exploited**: CVE-2026-20805
- Key affected components: LSASS, Word, Excel, Office, VBS Enclave, Windows Graphics
- Removed vulnerable Agere modem drivers (agrsm64.sys, agrsm.sys)
- Updates: KB5073724 (Win10), KB5074109 (Win11 25H2)

### SAP (January 2026 Security Patch Day)
- Multiple critical vulnerabilities (CVSS 9.1-9.9)
- SQL injection in S/4HANA General Ledger
- Code injection in S/4HANA and Landscape Transformation

### Apple
- Emergency updates for 2 WebKit zero-days (CVE-2025-43529, CVE-2025-14174)
- Described as "extremely sophisticated" targeted attacks
- Likely nation-state or commercial spyware involvement

### Google
- Chrome zero-day (CVE-2025-14174) patched
- Tied to Apple WebKit vulnerabilities

### VMware/Broadcom
- ESXi vulnerabilities being exploited via MAESTRO toolkit
- Patches available for CVE-2025-22224, CVE-2025-22225, CVE-2025-22226

### D-Link
- **NO PATCH** for CVE-2026-0625 - devices are EOL
- Recommendation: Replace affected DSL gateway devices immediately

---

## Industry News

### Breaches & Incidents

- **700Credit**: 5.6 million individuals exposed (SSNs, DOB, addresses) - auto dealership credit checks
  - Impact: Full PII including Social Security numbers
  - Attribution: Unknown attacker

- **Instagram**: 17.5 million accounts allegedly exposed
  - Impact: Account data leaked on BreachForums
  - Attribution: Unknown

- **Dartmouth College**: 40,000+ affected
  - Impact: SSNs, bank account information
  - Attribution: Clop ransomware

- **Aflac Insurance**: 22.65 million individuals
  - Impact: Personal information theft
  - Attribution: Unknown

- **Manage My Health (NZ)**: 400,000 medical documents, 120,000 patients
  - Impact: Hospital discharge summaries, specialist referrals
  - Attribution: Unknown

### Regulatory/Compliance
- CISA KEV catalog now at 1,487 total vulnerabilities (20% growth in 2025)
- Federal agencies required to remediate January KEV additions by January 28, 2026

---

## Recommended Actions

### Immediate (Critical)
1. [ ] Patch n8n installations for CVE-2026-21858/21877/68668 (CVSS 10.0)
2. [ ] Apply Microsoft January 2026 Patch Tuesday updates, prioritize CVE-2026-20805
3. [ ] Replace EOL D-Link DSL routers affected by CVE-2026-0625 (no patch available)
4. [ ] Patch HPE OneView for CVE-2025-37164 (CVSS 10.0)
5. [ ] Update VMware ESXi to mitigate MAESTRO exploitation toolkit
6. [ ] Apply Apple emergency updates for WebKit zero-days
7. [ ] Update Chrome to latest version

### This Week (High)
1. [ ] Review SAP January 2026 security patches and plan deployment
2. [ ] Audit MongoDB instances for CVE-2025-14847 (MongoBleed)
3. [ ] Review Veeam Backup & Replication for CVE-2025-59470
4. [ ] Hunt for MAESTRO toolkit IOCs in VMware environments
5. [ ] Assess exposure to AdonisJS bodyparser vulnerability

### Awareness
- Pure data exfiltration ransomware attacks are increasing - may not trigger encryption-based detections
- Federal contractors remain high-value targets for ransomware groups
- New China APT "Phantom Taurus" shows unprecedented persistence - resurfaces within hours of detection
- Scattered Spider teenage hackers continue targeting Fortune 500

---

## Sources
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://nvd.nist.gov/
- [CISA Adds Two KEV Vulnerabilities (Jan 7)](https://www.cisa.gov/news-events/alerts/2026/01/07/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CISA Adds One KEV Vulnerability (Jan 12)](https://www.cisa.gov/news-events/alerts/2026/01/12/cisa-adds-one-known-exploited-vulnerability-catalog)
- [Microsoft January 2026 Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-january-2026-patch-tuesday-fixes-3-zero-days-114-flaws/)
- [n8n Critical Vulnerability](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html)
- [VMware ESXi Exploitation](https://www.huntress.com/blog/esxi-vm-escape-exploit)
- [SAP January 2026 Security Patches](https://www.securityweek.com/saps-january-2026-security-updates-patch-critical-vulnerabilities/amp/)
- [Phantom Taurus APT](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)
- [Apple WebKit Zero-Days](https://www.foxnews.com/tech/apple-patches-two-zero-day-flaws-used-targeted-attacks)
- [Ransomware Trends 2026](https://www.recordedfuture.com/blog/ransomware-tactics-2026)
- [Data Breaches January 2026](https://sharkstriker.com/blog/data-breaches-in-january-2026/)

---
*Report generated by Cyber Threat Intel Agent on January 13, 2026 08:00 EST*
