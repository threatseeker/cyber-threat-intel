# Cyber Threat Intelligence Report
## January 15, 2026

---

## Executive Summary

Today's threat landscape shows significant APT activity with newly disclosed China-nexus threat actors targeting critical infrastructure, critical vulnerabilities in workflow automation platforms, and ongoing exploitation of Microsoft Windows zero-days. Key highlights include:

- **NEW APT Discovery**: UAT-8837 China-nexus APT targeting North American critical infrastructure (disclosed today)
- **Critical RCE**: CVE-2026-21858 (CVSS 10.0) in n8n workflow automation platform
- **[UPDATE] Active Exploitation**: CVE-2026-20805 Windows zero-day added to CISA KEV catalog today
- **Major Data Breaches**: SoundCloud breach affects tens of millions, Instagram leak exposes 17.5M accounts
- **New Malware Campaigns**: SHADOW#REACTOR and PLUGGYAPE targeting enterprise and military systems
- **[UPDATE]** VMware ESXi zero-days (CVE-2025-22224, CVE-2025-22225, CVE-2025-22226) actively exploited by Chinese-linked actors

**Risk Level**: HIGH - Multiple zero-day exploitations, critical infrastructure targeting, and widespread data breaches

---

## Critical Vulnerabilities

### NEW Critical CVEs Disclosed

#### CVE-2026-21858 - n8n Workflow Automation Platform RCE
- **CVSS Score**: 10.0 (Critical)
- **Vendor**: n8n
- **Impact**: Remote code execution without authentication, complete system takeover
- **Description**: Attackers can remotely execute code and fully take over vulnerable n8n workflow automation instances without any authentication
- **Status**: Patch available
- **Recommendation**: Immediate patching required for all n8n deployments
- **Source**: [The Hacker News](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html), [Orca Security](https://orca.security/resources/blog/cve-2026-21858-n8n-rce-vulnerability/)

#### CVE-2025-68428 - jsPDF Path Traversal
- **CVSS Score**: 9.2 (Critical)
- **Vendor**: jsPDF
- **Affected Versions**: Prior to version 4.0.0 (server-side Node.js deployments)
- **Impact**: Path traversal allowing arbitrary file read from local filesystem
- **Description**: Server-side Node.js deployments vulnerable to arbitrary file access
- **Status**: Fixed in version 4.0.0
- **Recommendation**: Upgrade to jsPDF 4.0.0 or later
- **Source**: [Security Boulevard](https://securityboulevard.com/2026/01/critical-jspdf-vulnerability-enables-arbitrary-file-read-in-node-js-cve-2025-68428/)

### [UPDATE] Previously Reported CVEs - Significant Updates

#### CVE-2026-20805 - Windows Desktop Window Manager Zero-Day
- **CVSS Score**: 5.5 (Medium)
- **Status**: **ACTIVELY EXPLOITED IN THE WILD**
- **Update**: Added to CISA KEV catalog on January 15, 2026
- **Federal Deadline**: February 3, 2026
- **Impact**: Memory information disclosure enabling bypass of security protections
- **Description**: Allows attackers to leak memory address information that can help bypass security protections and enable more serious exploits
- **Recommendation**: Apply Microsoft's January 2026 Patch Tuesday updates immediately
- **Source**: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [SC Media](https://www.scworld.com/brief/cisa-adds-microsoft-windows-vulnerability-cve-2026-20805-to-kev-catalog), [The Register](https://www.theregister.com/2026/01/14/patch_tuesday_january_2026/)

#### CVE-2026-20952 & CVE-2026-20953 - Microsoft Office RCE
- **CVSS Score**: 8.4 (High) - Both vulnerabilities
- **Status**: Patched in January 2026 Patch Tuesday
- **Impact**: Critical remote code execution vulnerabilities in Microsoft Office
- **Recommendation**: Apply January 2026 Office security updates
- **Source**: [Tenable](https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805), [CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/)

#### CVE-2026-20944 - Microsoft Word RCE
- **CVSS Score**: 8.4 (High)
- **Impact**: Unauthenticated attackers can execute arbitrary code via out-of-bounds read weakness
- **Status**: Patched in January 2026 Patch Tuesday
- **Recommendation**: Apply January 2026 security updates
- **Source**: [CrowdStrike](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/)

#### [UPDATE] CVE-2025-22224, CVE-2025-22225, CVE-2025-22226 - VMware ESXi
- **CVSS Scores**: 9.3, 8.2, 7.1 respectively
- **Update**: Chinese-linked attackers actively exploiting these zero-days to escape VMs and gain hypervisor control
- **Attack Vector**: SonicWall VPN access combined with VMware ESXi exploitation
- **Status**: Originally disclosed March 2025, active exploitation confirmed January 2026
- **Recommendation**: Apply VMware patches immediately, review VPN access logs
- **Source**: [The Hacker News](https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html)

---

## Exploits & Zero-Day Vulnerabilities

### Active Zero-Day Exploitation

#### CVE-2026-20805 - Windows Desktop Window Manager
- **Status**: Actively exploited in the wild
- **Added to CISA KEV**: January 15, 2026
- **Details**: See Critical Vulnerabilities section above

#### [UPDATE] CVE-2026-0625 - D-Link DSL Router Zero-Day
- **CVSS Score**: 9.3 (Critical)
- **Status**: Active exploitation of end-of-life devices
- **Impact**: Command injection in "dnscfg.cgi" endpoint
- **Discovery**: VulnCheck informed D-Link on December 16, 2025
- **Affected Devices**: Legacy D-Link DSL routers (end-of-life)
- **Recommendation**: Replace affected devices; no patch available for EOL products
- **Source**: [The Hacker News](https://thehackernews.com/2026/01/active-exploitation-hits-legacy-d-link.html), [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)

### Other Publicly Disclosed Zero-Days

#### CVE-2026-21265 - Windows Secure Boot Bypass
- **CVSS Score**: 6.4 (Medium)
- **Status**: Publicly disclosed (not exploited)
- **Impact**: Authenticated local attackers with high privileges can bypass Secure Boot
- **Weakness**: Certificate update mechanism vulnerability
- **Status**: Patched in January 2026 Patch Tuesday
- **Source**: [Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-january-2026-patch-tuesday-fixes-3-zero-days-114-flaws/), [Dark Reading](https://www.darkreading.com/application-security/microsofts-starts-2026-bang-zero-day)

---

## Advanced Persistent Threats (APTs)

### NEW APT Discovery - UAT-8837 (China-nexus)
- **First Observed**: 2025
- **Attribution**: Medium confidence China-nexus APT
- **Target Sectors**: Critical infrastructure in North America
- **TTPs**:
  - Initial access via vulnerable server exploitation or compromised credentials
  - Deploys open-source tools for credential harvesting
  - Overlaps with known China-nexus threat actor tactics
- **Severity**: High - Critical infrastructure targeting
- **Published**: January 15, 2026
- **Source**: [Cisco Talos](https://blog.talosintelligence.com/uat-8837/)

### UAT-7290 (China-nexus) - Telecommunications Targeting
- **Attribution**: High confidence China-nexus APT
- **Target Region**: South Asia telecommunications providers
- **Malware Arsenal**: RushDrop, DriveSwitch, SilentRaid
- **Sophistication**: Advanced persistent threat with custom tooling
- **Published**: January 8, 2026
- **Source**: [Cisco Talos](https://blog.talosintelligence.com/uat-7290/)

### [UPDATE] APT28/Fancy Bear (Russian GRU)
- **Recent Activity**: Credential harvesting campaigns
- **Target Regions**: Balkans, Middle East, Central Asia
- **Attribution**: Russian Federation GRU
- **Tactics**: Targeted credential theft operations
- **Source**: [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-credentials-global-targets)

---

## Malware & Ransomware Activity

### NEW Malware Campaigns

#### SHADOW#REACTOR Campaign
- **Payload**: Remcos RAT (Remote Administration Tool)
- **Technique**: Multi-stage evasive attack chain
- **Attack Chain**:
  1. Obfuscated VBS launcher via wscript.exe
  2. PowerShell downloader invocation
  3. Persistent remote access establishment
- **Sophistication**: Tightly orchestrated execution path with obfuscation
- **Target**: General enterprise environments
- **Source**: [The Hacker News](https://thehackernews.com/2026/01/new-malware-campaign-delivers-remcos.html)

#### PLUGGYAPE - Targeting Ukrainian Defense Forces
- **Attribution**: Medium confidence to Russian group "Void Blizzard"
- **Active Period**: October - December 2025 (disclosed January 2026)
- **Attack Vector**: Signal and WhatsApp instant messaging
- **Social Engineering**: Masquerading as charity organizations
- **Delivery**: Password-protected archives via messaging apps
- **Target**: Ukrainian military and defense forces
- **Reporting Agency**: CERT-UA (Computer Emergency Response Team of Ukraine)
- **Source**: [The Hacker News](https://thehackernews.com/2026/01/pluggyape-malware-uses-signal-and.html)

#### Black Cat SEO Poisoning Campaign
- **Threat Actor**: Black Cat cybercrime gang
- **Technique**: Search engine optimization (SEO) poisoning
- **Target Software**: Google Chrome, Notepad++, QQ International, iTools
- **Method**: Fraudulent sites advertising popular software
- **Payload**: Backdoor malware
- **Impact**: Users searching for legitimate software downloads
- **Source**: [The Hacker News](https://thehackernews.com/2026/01/black-cat-behind-seo-poisoning-malware.html)

### Ransomware Activity

#### NEW Ransomware Incidents (January 2026)

**HealthBridge Chiropractic**
- **Attacker**: Qilin ransomware group
- **Date**: January 6, 2026
- **Impact**: Systems and data compromised

**Apex Spine and Neurosurgery**
- **Attacker**: Interlock ransomware group
- **Impact**: Over 12 GB of sensitive data compromised

**Eros Elevators**
- **Attacker**: LockBit5 ransomware group
- **Impact**: Serious disruption to data and operations

**Sedgwick Government Solutions**
- **Attacker**: TridentLocker ransomware gang
- **Date**: December 31, 2025 (claimed)
- **Data Stolen**: 3.4 GB
- **Victims Affected**: ~30,000 employees (names, bank account numbers)
- **Significance**: Subsidiary provides services to DHS, ICE, and CISA
- **Source**: [The Record](https://therecord.media/sedgwick-cyber-incident-ransomware)

#### NEW Legal Development - BlackCat/Alphv Ransomware Case
- **Date**: Announced January 2026
- **Incident**: Two US cybersecurity professionals plead guilty to conspiracy to commit extortion
- **Charges**: Both individuals face up to 20 years in prison
- **Sentencing**: Scheduled for March 12, 2026
- **Significance**: Rare case of cybersecurity professionals involved in ransomware operations; highlights insider threat risks
- **Source**: [SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)

#### Ransomware Trends
- **North Carolina**: 50% increase in ransomware attacks (843 to 1,215 incidents)
- **2025 Statistics**: Nearly 6,500 ransomware incidents, 57 new ransomware groups, 27 new extortion groups
- **Emerging Trends**: AI-assisted attacks, supply-chain infiltration, data-leak extortion without encryption
- **Source**: [WRAL](https://www.wral.com/news/investigates/ransomeware-attacks-surge-nc-hacker-negotiator-shares-why-jan-2026/)

---

## Vendor Security Advisories

### Microsoft January 2026 Patch Tuesday (Released January 14, 2026)

**Overall**: 114 vulnerabilities patched
- **Critical**: 8 vulnerabilities
- **Important**: 106 vulnerabilities
- **Zero-Days**: 3 (1 actively exploited, 2 publicly disclosed)

**Key Patches**:
- CVE-2026-20805 (actively exploited zero-day)
- CVE-2026-21265 (Secure Boot bypass)
- CVE-2026-20952, CVE-2026-20953 (Office RCE)
- CVE-2026-20944 (Word RCE)
- CVE-2023-31096 (Agere Soft Modem drivers removed)

**Recommendation**: Deploy January 2026 Patch Tuesday updates immediately, prioritize CVE-2026-20805

**Source**: [Bleeping Computer](https://www.bleepingcomputer.com/news/microsoft/microsoft-january-2026-patch-tuesday-fixes-3-zero-days-114-flaws/), [The Hacker News](https://thehackernews.com/2026/01/microsoft-fixes-114-windows-flaws-in.html), [Krebs on Security](https://krebsonsecurity.com/2026/01/patch-tuesday-january-2026-edition/)

### SAP January 2026 Security Updates

**Overall**: 19 vulnerabilities patched
- **Critical**: 3 vulnerabilities

**Critical Vulnerabilities**:
- **CVE-2026-0501** (CVSS 9.9): SQL injection in S/4HANA
- **CVE-2026-0500** (CVSS 9.6): Remote code execution in Wily Introscope Enterprise Manager
- **CVE-2026-0498** (CVSS 9.1): Code injection in S/4HANA leading to OS command injection

**Recommendation**: Apply SAP security updates immediately for all affected systems

**Source**: [SecurityWeek](https://www.securityweek.com/saps-january-2026-security-updates-patch-critical-vulnerabilities/)

### Adobe January 2026 Updates

**Overall**: 11 security advisories, 25 vulnerabilities
- **Critical**: 17 vulnerabilities

**Affected Products**:
- Adobe DreamWeaver
- Adobe InDesign
- Adobe Illustrator
- Adobe InCopy
- Adobe Bridge
- Adobe Substance 3D Modeler
- Adobe Substance 3D Painter
- Adobe Substance 3D Sampler
- Adobe Coldfusion
- Adobe Substance 3D Designer

**Recommendation**: Update all Adobe products to latest versions

**Source**: [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review)

### Other Vendor Updates

**Cisco**: Identity Services Engine (ISE) vulnerability with public PoC exploit (CVE-2026-20029)
**Fortinet**: Multiple products including 2 RCE fixes
**Google**: Android January security bulletin with critical DD+ Codec flaw (Dolby components)

---

## Data Breaches & Industry Incidents

### NEW Major Data Breaches

#### SoundCloud Data Breach
- **Discovery**: January 2026
- **Cause**: Unauthorized access to ancillary service dashboard
- **Data Exposed**: Email addresses and public profile information
- **Affected Users**: ~20% of user base (~28 million based on 140M total users)
- **Data NOT Compromised**: Passwords, financial data, private content
- **Status**: Under investigation
- **Source**: [SharkStriker](https://sharkstriker.com/blog/data-breaches-in-january-2026/)

#### Instagram Data Leak
- **Discovery**: January 9-10, 2026
- **Affected Users**: 17.5 million accounts
- **Data Exposed**: Personal information circulating on dark web forums
- **Indicators**: Password reset email spike beginning January 9, 2026
- **Source**: BreachForums post
- **Severity**: High - Large-scale breach with dark web distribution
- **Source**: [Cyberpress](https://cyberpress.org/instagram-data-leak/)

#### Gulshan Management Services (GMS)
- **Initial Detection**: September 27, 2025
- **Disclosure**: January 2026
- **Attack Method**: Phishing attack on September 17, 2025
- **Impact**: Unauthorized network access, potential exposure of personal information including SSNs
- **Investigation**: Completed in January 2026
- **Source**: [Class Action](https://www.classaction.org/data-breach-lawsuits/gulshan-management-services-january-2026)

#### Dartmouth College
- **Affected Individuals**: 40,000+
- **Disclosure**: January 2026
- **Type**: Data breach affecting students, faculty, or staff
- **Source**: [The Dartmouth](https://www.thedartmouth.com/article/2026/01/more-than-40000-hit-by-dartmouth-data-breach)

#### Monroe University
- **Affected Individuals**: 320,000
- **Disclosure**: January 2026
- **Status**: Under investigation by attorneys
- **Source**: [Class Action](https://www.classaction.org/data-breach-lawsuits/monroe-university-january-2026)

#### Ledger (via Global-e)
- **Date**: January 5, 2026
- **Cause**: Supply chain breach at e-commerce partner Global-e
- **Data Exposed**: Customer order data
- **Type**: Third-party/supply chain incident
- **Source**: [Ledger Support](https://support.ledger.com/article/Global-e-Incident-to-Order-Data---January-2026)

### Emerging Threat: AI Security Vulnerabilities

#### "Reprompt" Attack on Microsoft Copilot
- **Technique**: Single-click data exfiltration from AI chatbots
- **Target**: Microsoft Copilot
- **Method**: Legitimate Microsoft link compromises victims
- **Impact**: Bypass of enterprise security controls
- **Severity**: High - Minimal user interaction required

#### Malicious Chrome Extensions
- **Victims**: 900,000+ users
- **Disguise**: AI helpers
- **Data Stolen**: ChatGPT and DeepSeek chat data
- **Discovery**: January 2026

---

## CISA Known Exploited Vulnerabilities (KEV) Updates

### Added to KEV Catalog on January 15, 2026

**CVE-2026-20805** - Microsoft Windows Desktop Window Manager
- **Vulnerability**: Information Disclosure
- **CVSS**: 5.5
- **Status**: Actively exploited in the wild
- **Federal Deadline**: February 3, 2026
- **Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### Previously Added (January 7, 2026)

**CVE-2009-0556** - Microsoft Office PowerPoint
**CVE-2025-37164** - HPE OneView
- **Federal Deadline**: January 28, 2026
- **Status**: Evidence of active exploitation
- **Source**: [The Hacker News](https://thehackernews.com/2026/01/cisa-flags-microsoft-office-and-hpe.html)

### KEV Catalog Statistics
- **Total Vulnerabilities**: 1,484 (as of January 2026)
- **2025 Additions**: 245 security defects
- **Ransomware-Related**: 24 bugs exploited in ransomware attacks
- **Growth**: 20% expansion in 2025
- **Source**: [SecurityWeek](https://www.securityweek.com/cisa-kev-catalog-expanded-20-in-2025-topping-1480-entries/)

---

## Recommended Actions

### Immediate (24-48 hours)

1. **Apply Critical Patches**:
   - Microsoft January 2026 Patch Tuesday (prioritize CVE-2026-20805)
   - SAP January 2026 updates (CVE-2026-0501, CVE-2026-0500, CVE-2026-0498)
   - Adobe January 2026 security updates
   - n8n workflow automation platform (CVE-2026-21858)
   - jsPDF to version 4.0.0+ (CVE-2025-68428)

2. **Verify Exposure**:
   - Check for n8n workflow automation deployments
   - Identify legacy D-Link DSL routers (CVE-2026-0625)
   - Review VMware ESXi instances for compromise indicators
   - Audit Chrome extensions for malicious AI helper tools

3. **Monitor for Exploitation**:
   - Windows Desktop Window Manager exploitation attempts (CVE-2026-20805)
   - VMware ESXi unusual hypervisor activity
   - SonicWall VPN access logs for suspicious activity

### Short-term (1 week)

4. **Infrastructure Review**:
   - Replace end-of-life D-Link devices
   - Review critical infrastructure access controls (UAT-8837 threat)
   - Audit credential management systems
   - Assess exposure to China-nexus APT TTPs

5. **User Awareness**:
   - Warn users about SEO poisoning campaigns targeting popular software
   - Alert to phishing campaigns via Signal/WhatsApp (PLUGGYAPE)
   - Educate on "Reprompt" attacks targeting AI chatbot users
   - Brief on charity organization impersonation tactics

6. **Data Breach Response**:
   - If using SoundCloud, Instagram, or affected services, review account security
   - Implement additional monitoring for affected user bases
   - Review third-party/supply chain security (e-commerce partners)

### Medium-term (1 month)

7. **Strategic Initiatives**:
   - Review and harden Secure Boot configurations (CVE-2026-21265)
   - Assess ransomware preparedness (50% increase in some regions)
   - Implement AI chatbot security controls
   - Enhance supply chain security assessments
   - Review telecommunications infrastructure security (UAT-7290 targeting)

8. **Threat Hunting**:
   - Search for indicators of UAT-8837 and UAT-7290 activity
   - Review logs for SHADOW#REACTOR campaign indicators
   - Audit for Remcos RAT presence
   - Check for Black Cat SEO poisoning compromise indicators

9. **Compliance**:
   - CISA KEV remediation deadlines:
     - CVE-2026-20805: February 3, 2026
     - CVE-2009-0556, CVE-2025-37164: January 28, 2026

---

## Threat Intelligence Sources

### Vulnerability & Exploit Intelligence
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [SC Media - CISA KEV Updates](https://www.scworld.com/brief/cisa-adds-microsoft-windows-vulnerability-cve-2026-20805-to-kev-catalog)
- [The Hacker News - Critical n8n Vulnerability](https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html)
- [Orca Security - n8n RCE Analysis](https://orca.security/resources/blog/cve-2026-21858-n8n-rce-vulnerability/)
- [Security Boulevard - jsPDF Vulnerability](https://securityboulevard.com/2026/01/critical-jspdf-vulnerability-enables-arbitrary-file-read-in-node-js-cve-2025-68428/)
- [The Hacker News - D-Link Routers](https://thehackernews.com/2026/01/active-exploitation-hits-legacy-d-link.html)
- [Dark Reading - D-Link Zero-Day](https://www.darkreading.com/cyberattacks-data-breaches/attackers-exploit-zero-day-end-of-life-d-link-routers)

### Vendor Security Advisories
- [Bleeping Computer - Microsoft Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-january-2026-patch-tuesday-fixes-3-zero-days-114-flaws/)
- [The Hacker News - Microsoft Patch Tuesday](https://thehackernews.com/2026/01/microsoft-fixes-114-windows-flaws-in.html)
- [Krebs on Security - Patch Tuesday Analysis](https://krebsonsecurity.com/2026/01/patch-tuesday-january-2026-edition/)
- [Tenable - Microsoft January 2026](https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805)
- [CrowdStrike - Patch Tuesday Analysis](https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/)
- [Dark Reading - Microsoft Zero-Day](https://www.darkreading.com/application-security/microsofts-starts-2026-bang-zero-day)
- [The Register - Windows Zero-Day](https://www.theregister.com/2026/01/14/patch_tuesday_january_2026/)
- [SecurityWeek - SAP Updates](https://www.securityweek.com/saps-january-2026-security-updates-patch-critical-vulnerabilities/)
- [Qualys - Patch Tuesday Review](https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review)

### APT & Threat Actor Intelligence
- [Cisco Talos - UAT-8837](https://blog.talosintelligence.com/uat-8837/)
- [Cisco Talos - UAT-7290](https://blog.talosintelligence.com/uat-7290/)
- [Dark Reading - APT28/Fancy Bear](https://www.darkreading.com/cyberattacks-data-breaches/russian-apt-credentials-global-targets)
- [The Hacker News - VMware ESXi Exploitation](https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html)

### Malware & Ransomware
- [The Hacker News - SHADOW#REACTOR](https://thehackernews.com/2026/01/new-malware-campaign-delivers-remcos.html)
- [The Hacker News - PLUGGYAPE](https://thehackernews.com/2026/01/pluggyape-malware-uses-signal-and.html)
- [The Hacker News - Black Cat SEO Poisoning](https://thehackernews.com/2026/01/black-cat-behind-seo-poisoning-malware.html)
- [The Record - Sedgwick Ransomware](https://therecord.media/sedgwick-cyber-incident-ransomware)
- [SecurityWeek - BlackCat/Alphv Case](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [WRAL - Ransomware Statistics](https://www.wral.com/news/investigates/ransomeware-attacks-surge-nc-hacker-negotiator-shares-why-jan-2026/)

### Data Breaches
- [SharkStriker - January 2026 Breaches](https://sharkstriker.com/blog/data-breaches-in-january-2026/)
- [Cyberpress - Instagram Data Leak](https://cyberpress.org/instagram-data-leak/)
- [Class Action - Gulshan Management Services](https://www.classaction.org/data-breach-lawsuits/gulshan-management-services-january-2026)
- [The Dartmouth - Dartmouth Breach](https://www.thedartmouth.com/article/2026/01/more-than-40000-hit-by-dartmouth-data-breach)
- [Class Action - Monroe University](https://www.classaction.org/data-breach-lawsuits/monroe-university-january-2026)
- [Ledger Support - Global-e Incident](https://support.ledger.com/article/Global-e-Incident-to-Order-Data---January-2026)

### Industry News & Statistics
- [SecurityWeek - CISA KEV Catalog Growth](https://www.securityweek.com/cisa-kev-catalog-expanded-20-in-2025-topping-1480-entries/)
- [The Hacker News - CISA KEV Additions](https://thehackernews.com/2026/01/cisa-flags-microsoft-office-and-hpe.html)

---

## Summary Statistics

- **NEW CVEs**: 2 critical (CVE-2026-21858, CVE-2025-68428)
- **Active Zero-Days**: 1 (CVE-2026-20805)
- **CISA KEV Additions Today**: 1 (CVE-2026-20805)
- **NEW APTs Disclosed**: 1 (UAT-8837)
- **NEW Malware Campaigns**: 3 (SHADOW#REACTOR, PLUGGYAPE, Black Cat SEO)
- **Ransomware Incidents**: 4+ in early January 2026
- **Major Data Breaches**: 6 disclosed this month
- **Microsoft Patches**: 114 vulnerabilities
- **SAP Patches**: 19 vulnerabilities
- **Adobe Patches**: 25 vulnerabilities

---

**Report Generated**: 2026-01-15
**Next Update**: 2026-01-16
**Classification**: TLP:WHITE - Unrestricted distribution

---

*This report aggregates open-source intelligence from trusted cybersecurity sources. Organizations should validate findings against their specific environments and threat models.*
