# Cyber Threat Intelligence Report

**Date:** 2026-03-19
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0319

---

## Executive Summary

- **CRITICAL:** CVE-2026-20963 (Microsoft SharePoint deserialization RCE) added to CISA KEV on March 18; actively exploited in the wild; FCEB patch deadline March 21, only two days away
- **CRITICAL:** Interlock ransomware campaign exploiting Cisco FMC zero-day CVE-2026-20131 (CVSS 10.0) since January 26; Amazon threat intelligence published detailed analysis on March 18; targets healthcare, manufacturing, government
- **HIGH:** CVE-2026-26144 (Microsoft Excel XSS + Copilot Agent zero-click data exfiltration); novel attack vector combining traditional XSS with indirect prompt injection to weaponize AI assistants; patched March 10
- **HIGH:** TELUS Digital confirms ShinyHunters breach of nearly 1 petabyte of data including source code, FBI background checks, financial data, and voice recordings; company rejected $65M ransom demand
- **HIGH:** Veeam patches seven critical RCE flaws (CVSS up to 9.9) in Backup & Replication; high-value ransomware target; no active exploitation yet but domain-authenticated users can achieve full server compromise
- **HIGH:** Seedworm/MuddyWater (MOIS) confirmed on networks of U.S. bank, airport, software company, and Canadian NGO using novel Dindoor and Fakeset backdoors; pre-positioned before Iran conflict escalation
- **MEDIUM:** AkzoNobel confirms Anubis ransomware breach at U.S. site; 170GB exfiltrated including passport scans, confidential agreements, employee records
- **MEDIUM:** LexisNexis confirms breach by FulcrumSec via React2Shell exploit; 2GB exfiltrated from AWS including 3.9M database records, 21K customer accounts, 118 .gov user profiles

---

## Critical Vulnerabilities

### CISA KEV Additions Since March 16

| Date | CVE | Product | Type | CVSS | Status |
|------|-----|---------|------|------|--------|
| Mar 18 | CVE-2026-20963 | Microsoft SharePoint | Deserialization RCE | Critical | **Actively exploited**; FCEB deadline Mar 21 |

### New / Previously Unreported Critical CVEs

| CVE | Product | Type | CVSS | Status |
|-----|---------|------|------|--------|
| CVE-2026-20079 | Cisco Secure FMC | Authentication Bypass (root) | 10.0 | Patched Mar 4; no workaround available |
| CVE-2026-20131 | Cisco Secure FMC | Insecure Deserialization (root) | 10.0 | **Exploited as zero-day since Jan 26** by Interlock ransomware |
| CVE-2026-26144 | Microsoft Excel | XSS + Copilot Exfiltration | 7.5 | Patched Mar 10; zero-click via Copilot Agent mode |
| CVE-2026-21666 | Veeam Backup & Replication | Authenticated RCE | 9.9 | Patched Mar 12; domain user to full server compromise |
| CVE-2026-21708 | Veeam Backup & Replication | RCE as postgres | 9.9 | Patched Mar 12; Backup Viewer role exploitable |
| CVE-2026-23813 | HPE AOS-CX Switches | Authentication Bypass | 9.8 | Patched; web interface auth bypass on enterprise switches |
| CVE-2026-2991 | KiviCare WordPress Plugin | Authentication Bypass | 9.8 | Disclosed Mar 18; unauth access to patient medical records |
| CVE-2026-3891 | Pix for WooCommerce Plugin | Arbitrary File Upload | 9.8 | Disclosed; unauth file upload to server |

### [UPDATE] Previously Reported, New Developments

| CVE | Update |
|-----|--------|
| CVE-2026-20963 (SharePoint) | Originally patched January 2026; now confirmed actively exploited and added to CISA KEV March 18 with 3-day remediation deadline |
| CVE-2026-1731 (BeyondTrust RS/PRA) | CISA updated KEV entry to confirm use in active ransomware campaigns targeting defense contractors, local governments, healthcare, and financial services |

---

## Exploits & Zero-Days

### CVE-2026-20131, Cisco FMC Zero-Day Exploited by Interlock Ransomware

Amazon Threat Intelligence published a detailed analysis on March 18 documenting the Interlock ransomware group's exploitation of CVE-2026-20131 (CVSS 10.0) in Cisco Secure Firewall Management Center. The vulnerability allows unauthenticated remote code execution as root via insecure deserialization of Java byte streams.

**Key details:**
- Exploitation began January 26, 2026, 36 days before Cisco's March 4 public disclosure
- Attack chain: crafted HTTP requests to FMC > arbitrary Java code execution as root > HTTP PUT callback to C2 confirming compromise > ELF binary payload fetch
- Interlock targets: healthcare, manufacturing, education, engineering, construction, government
- No workarounds available; patching is the only remediation path
- Second Cisco FMC flaw (CVE-2026-20079, also CVSS 10.0) disclosed simultaneously enables authentication bypass to root

**Recommended action:** Patch Cisco FMC immediately. Hunt for anomalous HTTP PUT requests from FMC systems. Audit FMC access logs for exploitation indicators dating back to late January.

### CVE-2026-26144, Microsoft Excel + Copilot Agent Zero-Click Exfiltration

This novel vulnerability combines cross-site scripting (XSS) with indirect prompt injection to weaponize Microsoft's Copilot Agent integrated into Office applications. User-controlled content in a workbook triggers Copilot Agent to perform unintended network egress, exfiltrating data without any user interaction.

**Why this matters:** This represents a new class of vulnerability where traditional web security flaws (XSS) interact with agentic AI capabilities to create zero-click data exfiltration paths. Organizations deploying Copilot Agent mode in Office environments should treat this as a signal that agentic AI surfaces are becoming a first-class attack vector.

**Recommended action:** Apply March 10 Patch Tuesday updates. Review Copilot Agent deployment policies; consider restricting Agent mode on workbooks from untrusted sources.

### CVE-2026-20963, Microsoft SharePoint Actively Exploited

CISA confirmed active exploitation of CVE-2026-20963 on March 18, adding it to the KEV catalog with an aggressive March 21 remediation deadline (3 days). The flaw stems from improper deserialization of untrusted data in SharePoint Enterprise Server 2016, Server 2019, and Server Subscription Edition. Exploitation enables unauthenticated remote code execution in low-complexity attacks. Originally patched in the January 2026 Patch Tuesday.

**Recommended action:** Patch all on-premises SharePoint servers immediately. This is not a "patch window" situation; exploitation is confirmed in the wild.

---

## Malware & Ransomware

### Interlock Ransomware, Cisco FMC Zero-Day Campaign

See Exploits section above for technical details. Interlock has historically targeted education, healthcare, manufacturing, and government entities. The 36-day exploitation window before disclosure underscores the accelerating zero-day-to-ransomware pipeline. Organizations running Cisco FMC should assume potential compromise if unpatched during the January 26 to March 4 window.

### [UPDATE] BeyondTrust CVE-2026-1731, Confirmed in Ransomware Campaigns

CISA has activated the "Known To Be Used in Ransomware Campaigns" flag in its KEV catalog entry for CVE-2026-1731 (BeyondTrust Remote Support/Privileged Remote Access pre-auth RCE). Multiple ransomware crews are targeting defense contractors, local governments, healthcare, financial services, and higher education organizations. Palo Alto Unit 42 documented deployment of VShell and SparkRAT via this vulnerability. The speed from disclosure (Feb 6) to PoC (Feb 10) to active ransomware use (under two weeks) confirms that patch windows continue shrinking.

### Tycoon 2FA Phishing Platform Takedown

A coordinated law enforcement operation involving Proofpoint, Microsoft, Europol, and Cloudflare disrupted the Tycoon 2FA phishing-as-a-service platform on March 4, resulting in seizure of 330 control panel domains. In February 2026 alone, Proofpoint observed over 3 million messages tied to Tycoon 2FA campaigns, with Microsoft reporting the platform provided access to nearly 100,000 organizations. This is a significant disruption to the adversary-in-the-middle (AiTM) phishing ecosystem, though operators will likely migrate infrastructure.

### Anubis Ransomware, AkzoNobel Breach

The Anubis ransomware-as-a-service operation (active since December 2024) claimed a breach of AkzoNobel, the Dutch paint and coatings multinational. AkzoNobel confirmed a security incident at one U.S. site. Anubis exfiltrated 170GB (170,000 files) including confidential client agreements, employee contact information, private emails, passport scans, and technical specifications. Anubis is notable for incorporating a data wiper capability, adding a destructive dimension beyond traditional ransomware extortion.

---

## Threat Actors

### Seedworm / MuddyWater (MOIS), U.S. Critical Infrastructure Pre-Positioning

Security researchers confirmed that Seedworm (MuddyWater, Temp Zagros, Static Kitten), a subordinate element of the Iranian Ministry of Intelligence and Security (MOIS), has been active on U.S. networks since early February 2026. Confirmed victims include a U.S. bank, a U.S. airport, a U.S. software company's Israeli operations (a defense/aerospace supplier), and a Canadian non-governmental organization.

**New malware:** Two previously unknown backdoors were identified:
- **Dindoor**: Found on the Israeli software company, the U.S. bank, and the Canadian NGO
- **Fakeset**: A Python-based backdoor found on the airport and NGO networks

**Strategic significance:** Seedworm established its network presence before the February 28 U.S.-Israeli strikes on Iran. This pre-positioning means the group was already inside critical U.S. infrastructure when hostilities escalated, putting them in a position to conduct destructive operations at a moment's notice.

### [UPDATE] APT42 (IRGC), SpearSpecter Campaign

APT42 has launched the SpearSpecter campaign, targeting senior government and defense officials through a multi-stage attack chain. Initial contact begins via personalized WhatsApp outreach before delivering sophisticated payloads. This represents an evolution from APT42's traditional credential harvesting approach to include custom lightweight backdoors for persistent access.

### [UPDATE] Handala / Void Manticore, Iran Leadership Transition

Mojtaba Khamenei was elected on March 8 to succeed his father as Iran's Supreme Leader following the February 28 airstrike. Senior Iranian leadership pledged allegiance. This leadership transition may accelerate coordinated state-directed cyber operations as the new regime consolidates authority. Handala continues operating via Starlink satellite connectivity (as reported in CTI-2026-0316), maintaining full operational capability despite Iran's national internet restrictions.

### ShinyHunters, TELUS Digital Mega-Breach

ShinyHunters, active since 2020 and responsible for breaches at PowerSchool, LVMH, Qantas, and Jaguar Land Rover, claimed the TELUS Digital attack. The group gained initial access using Google Cloud Platform credentials found in data stolen from Salesloft in 2025, then used trufflehog to discover additional credentials for lateral movement. This supply chain attack vector (credentials from one breach enabling access to another) represents an increasingly common pattern.

---

## Data Breaches

### TELUS Digital, ShinyHunters (~1 Petabyte)

TELUS Digital, a Canadian BPO giant, confirmed on March 12 that attackers accessed internal systems. ShinyHunters claims nearly 1 petabyte of exfiltrated data including customer support recordings, proprietary source code, employee records, FBI background checks, Salesforce data for client companies, and financial information. TELUS Digital rejected a $65 million ransom demand. Business operations remain fully operational with no service disruption.

**Recommended action:** If your organization uses TELUS Digital for BPO services, assess whether your data was in scope. Reset credentials for any systems with TELUS Digital integration.

### LexisNexis, FulcrumSec (2GB Structured Data)

LexisNexis Legal & Professional confirmed on March 3 that the threat actor FulcrumSec exploited a React2Shell vulnerability in an unpatched React frontend to access AWS infrastructure. Exfiltrated data includes 536 Redshift tables, 430+ VPC database tables, 53 plaintext AWS Secrets Manager secrets, 3.9 million database records, 21,042 customer accounts, 5,582 attorney survey respondents with IP addresses, 45 employee password hashes, and a complete VPC infrastructure map. Notably, 118 .gov user profiles were exposed, belonging to federal judges, DOJ attorneys, and SEC staff. LexisNexis stated the data was primarily legacy (pre-2020) and no SSNs, financial data, or active passwords were compromised.

### AkzoNobel, Anubis Ransomware (170GB)

See Ransomware section above. 170,000 files exfiltrated from U.S. site including passport scans, confidential agreements, and employee records.

### Cloud Imperium Games (Star Citizen)

The developer behind Star Citizen and Squadron 42 confirmed a January breach was disclosed in March, exposing basic account information (metadata, contact details, usernames, dates of birth) for an undisclosed number of users.

---

## Vendor Advisories

| Vendor | Advisory | Key Items |
|--------|----------|-----------|
| CISA | KEV update Mar 18 | CVE-2026-20963 (SharePoint RCE); **FCEB deadline March 21** |
| Cisco | Security Advisory Mar 4 | CVE-2026-20079 and CVE-2026-20131 (FMC, both CVSS 10.0); no workarounds; CVE-2026-20131 exploited as zero-day by Interlock ransomware |
| Microsoft | March Patch Tuesday (updated) | CVE-2026-26144 (Excel/Copilot zero-click exfil); CVE-2026-26113/26110 (Office RCE via preview pane); 82 total vulnerabilities |
| Veeam | Security Bulletin Mar 12 | 7 critical RCE flaws in Backup & Replication; CVE-2026-21666 and CVE-2026-21708 (both CVSS 9.9); patch to 13.0.1.2067 or 12.3.2.4465 |
| HPE | AOS-CX Advisory | CVE-2026-23813 (CVSS 9.8 auth bypass on enterprise switches) |
| Apple | Background Security Improvement | CVE-2026-20643 (WebKit zero-day, silently patched) |
| Mozilla | Firefox 148.0.2 | 3 high-severity CVEs resolved |
| Adobe | March 2026 updates | 80 vulnerabilities across Acrobat, Commerce, and other products |

---

## Recommended Actions

1. **IMMEDIATE (24h):** Patch all on-premises Microsoft SharePoint servers for CVE-2026-20963. CISA KEV deadline is March 21. Exploitation is confirmed in the wild.

2. **IMMEDIATE (24h):** Patch Cisco Secure Firewall Management Center for CVE-2026-20079 and CVE-2026-20131. No workarounds exist. If unpatched between January 26 and March 4, conduct forensic investigation for Interlock ransomware indicators.

3. **URGENT (48h):** Patch Veeam Backup & Replication to version 13.0.1.2067 or 12.3.2.4465. Seven critical RCE flaws; domain-authenticated users can achieve full backup infrastructure compromise.

4. **URGENT (48h):** If using BeyondTrust Remote Support or Privileged Remote Access, verify CVE-2026-1731 is patched. CISA confirms active ransomware exploitation targeting defense, healthcare, financial services, and government.

5. **URGENT (48h):** Apply March 10 Patch Tuesday; prioritize CVE-2026-26144 (Excel/Copilot zero-click exfil) for organizations deploying Copilot Agent mode.

6. **HIGH (7 days):** Hunt for Seedworm/MuddyWater IOCs (Dindoor and Fakeset backdoors) on banking, aviation, defense supply chain, and NGO networks. Assume Iranian APT operational capability is fully intact despite national internet disruption.

7. **HIGH (7 days):** Patch HPE AOS-CX switches for CVE-2026-23813 (CVSS 9.8 authentication bypass). Enterprise network switches are high-value pivot points.

8. **HIGH (7 days):** If using TELUS Digital for BPO services, assess data exposure scope and rotate credentials for integrated systems.

9. **MEDIUM (14 days):** Review WordPress sites for KiviCare (CVE-2026-2991) and Pix for WooCommerce (CVE-2026-3891) plugins; both CVSS 9.8 with unauthenticated exploitation.

10. **MEDIUM (30 days):** Assess organizational exposure to Copilot Agent-class vulnerabilities. CVE-2026-26144 signals that agentic AI integrated into productivity suites is a new attack surface requiring policy controls.

---

## Sources

- [CISA Adds One Known Exploited Vulnerability to Catalog (Mar 18)](https://www.cisa.gov/news-events/alerts/2026/03/18/cisa-adds-one-known-exploited-vulnerability-catalog-0)
- [Critical Microsoft SharePoint Flaw Now Exploited in Attacks | BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/critical-microsoft-sharepoint-flaw-now-exploited-in-attacks/)
- [CISA Warns of Zimbra, SharePoint Flaw Exploits; Cisco Zero-Day Hit in Ransomware Attacks | The Hacker News](https://thehackernews.com/2026/03/cisa-warns-of-zimbra-sharepoint-flaw.html)
- [Interlock Ransomware Exploits Cisco FMC Zero-Day CVE-2026-20131 for Root Access | The Hacker News](https://thehackernews.com/2026/03/interlock-ransomware-exploits-cisco-fmc.html)
- [Amazon Threat Intelligence Identifies Interlock Ransomware Campaign | AWS](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-teams-identify-interlock-ransomware-campaign-targeting-enterprise-firewalls/)
- [Ransomware Crims Abused Cisco 0-Day Weeks Before Disclosure | The Register](https://www.theregister.com/2026/03/18/amazon_cisco_firewall_0_day_ransomware/)
- [Critical Cisco FMC Vulnerabilities CVE-2026-20079 and CVE-2026-20131 | Abstract Security](https://www.abstract.security/blog/critical-cisco-vulnerabilities-cve-2026-20079-and-cve-2026-20131)
- [Excel CVE-2026-26144 XSS and Copilot Exfiltration | WindowsForum](https://windowsforum.com/threads/excel-cve-2026-26144-xss-and-copilot-exfiltration-zero-click-disclosure.404596/)
- [Critical Microsoft Excel Bug Weaponizes Copilot Agent | The Register](https://www.theregister.com/2026/03/10/zeroclick_microsoft_info_disclosure_bug/)
- [Microsoft Patches 84 Flaws in March Patch Tuesday | The Hacker News](https://thehackernews.com/2026/03/microsoft-patches-84-flaws-in-march.html)
- [March 2026 Patch Tuesday Edition | Krebs on Security](https://krebsonsecurity.com/2026/03/microsoft-patch-tuesday-march-2026-edition/)
- [Veeam Patches 7 Critical Backup & Replication Flaws | The Hacker News](https://thehackernews.com/2026/03/veeam-patches-7-critical-backup.html)
- [Veeam Warns of Critical Flaws Exposing Backup Servers to RCE | BleepingComputer](https://www.bleepingcomputer.com/news/security/veeam-warns-of-critical-flaws-exposing-backup-servers-to-rce-attacks/)
- [BeyondTrust Vulnerability Exploited in Ransomware Attacks | SecurityWeek](https://www.securityweek.com/beyondtrust-vulnerability-exploited-in-ransomware-attacks/)
- [VShell and SparkRAT in Exploitation of BeyondTrust CVE-2026-1731 | Unit 42](https://unit42.paloaltonetworks.com/beyondtrust-cve-2026-1731/)
- [Iran-Linked MuddyWater Hackers Target U.S. Networks With New Dindoor Backdoor | The Hacker News](https://thehackernews.com/2026/03/iran-linked-muddywater-hackers-target.html)
- [Seedworm: Iranian APT on Networks of U.S. Bank, Airport, Software Company | Security.com](https://www.security.com/threat-intelligence/iran-cyber-threat-activity-us)
- [Iranian APT Hacked US Airport, Bank, Software Company | SecurityWeek](https://www.securityweek.com/iranian-apt-hacks-us-airport-bank-software-company/)
- [Telus Digital Confirms Breach After Hacker Claims 1 Petabyte Data Theft | BleepingComputer](https://www.bleepingcomputer.com/news/security/telus-digital-confirms-breach-after-hacker-claims-1-petabyte-data-theft/)
- [Telus Digital Confirms Breach; ShinyHunters Claims Credit | Cybersecurity Dive](https://www.cybersecuritydive.com/news/telus-digital-cyberattack-shinyhunters/814817/)
- [LexisNexis Says Hackers Accessed Legacy Data | The Record](https://therecord.media/lexisnexis-says-hackers-accessed-legacy-data)
- [LexisNexis Data Breach Confirmed After Hackers Leak Files | SecurityWeek](https://www.securityweek.com/new-lexisnexis-data-breach-confirmed-after-hackers-leak-files/)
- [AkzoNobel Confirms Cyberattack at U.S. Site Following Anubis Ransomware | BleepingComputer](https://www.bleepingcomputer.com/news/security/paint-maker-giant-akzonobel-confirms-cyberattack-on-us-site/)
- [Tycoon 2FA Phishing Platform Takedown | Hornetsecurity Monthly Threat Report](https://www.hornetsecurity.com/en/blog/monthly-threat-report/)
- [Iran-Israel/US Cyber War 2026 Dashboard | SOCRadar](https://socradar.io/iran-israel-cyber-conflict-dashboard/)
- [The Iranian Cyber Capability 2026 | Trellix](https://www.trellix.com/blogs/research/the-iranian-cyber-capability-2026/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
