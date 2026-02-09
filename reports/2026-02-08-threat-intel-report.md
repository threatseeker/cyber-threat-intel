# Cyber Threat Intelligence Report
**Date:** February 8, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0208

---

## Executive Summary

- **NEW**: BeyondTrust CVE-2026-1731 (CVSS 9.9) - Pre-auth RCE in Remote Support and PRA; ~8,500 on-prem instances exposed; SaaS patched Feb 2
- **NEW**: TGR-STA-1030 "Shadow Campaigns" - Asia-based state-aligned espionage group compromised 70+ organizations across 37 countries including parliaments, law enforcement, and telecom providers
- **NEW**: Signal account hijacking campaign - Germany's BfV/BSI warns of state-backed phishing targeting politicians, military, diplomats, and journalists across Europe
- **NEW**: CISA BOD 26-02 - Federal agencies ordered to identify and remove end-of-life edge devices within 18 months
- **NEW**: Two US cybersecurity professionals (DigitalMint negotiator, Sygnia IR manager) plead guilty as ALPHV/BlackCat ransomware affiliates - face up to 20 years
- **NEW**: AT&T breach data resurfaces with enriched, more actionable profiles circulating since Feb 2
- **UPCOMING**: Microsoft Patch Tuesday - February 10, 2026 - cumulative security update KB5074105 expected

---

## Critical Vulnerabilities

### NEW: BeyondTrust CVE-2026-1731 - Pre-Auth RCE (CVSS 9.9)

**CVE:** CVE-2026-1731
**CVSS:** 9.9 (Critical)
**Type:** OS Command Injection (pre-authentication)
**Products:** BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA)
**Discovered:** January 31, 2026
**Advisory:** BT26-02

**Details:**
By sending specially crafted requests, an unauthenticated remote attacker can execute OS commands in the context of the site user. No authentication or user interaction required.

**Affected:**
- Remote Support versions 25.3.1 and prior
- Privileged Remote Access versions 24.3.4 and prior

**Exposure:**
- ~11,000 instances exposed to the internet
- ~8,500 are on-premises deployments (potentially still vulnerable)
- SaaS instances patched automatically as of February 2, 2026

**Why Critical:** BeyondTrust tools are widely used by IT teams and MSPs for privileged remote access. Compromise provides direct access to managed endpoints and credentials. This follows BeyondTrust's previous critical vulnerability (CVE-2024-12356) which was exploited in the US Treasury breach.

**Action:** Self-hosted customers must manually apply patches if not subscribed to automatic updates.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/beyondtrust-fixes-critical-pre-auth-rce.html), [BeyondTrust Advisory BT26-02](https://www.beyondtrust.com/trust-center/security-advisories/bt26-02), [Help Net Security](https://www.helpnetsecurity.com/2026/02/09/beyondtrust-remote-access-vulnerability-cve-2026-1731/)

---

### NEW: Fortinet FortiCloud SSO CVE-2026-24858 - Authentication Bypass

**CVE:** CVE-2026-24858
**CVSS:** 9.4 (Critical)
**Type:** Authentication Bypass (CWE-288)
**Status:** Actively exploited zero-day; added to CISA KEV January 27, 2026

**Details:**
Allows attackers with any FortiCloud account and registered device to log into devices registered to other users when FortiCloud SSO is enabled. Affects FortiOS, FortiManager, FortiWeb, FortiProxy, and FortiAnalyzer.

**Timeline:**
- January 20: Customers report unauthorized admin accounts on FortiGate firewalls
- January 22: Two malicious FortiCloud accounts locked out
- January 26: Fortinet disables all FortiCloud SSO authentication globally
- January 27: Service reinstated with exploitation prevention; CISA adds to KEV
- January 28: CISA releases advisory

**Post-Exploitation Activity:**
- Config file exfiltration for reconnaissance
- Creation of persistent local admin accounts
- Firewall configuration alterations

**Fixed:** FortiOS 7.4.11; patches for FortiManager and FortiAnalyzer forthcoming

**Sources:** [CISA Advisory](https://www.cisa.gov/news-events/alerts/2026/01/28/fortinet-releases-guidance-address-ongoing-exploitation-authentication-bypass-vulnerability-cve-2026), [The Hacker News](https://thehackernews.com/2026/01/fortinet-patches-cve-2026-24858-after.html), [Help Net Security](https://www.helpnetsecurity.com/2026/01/28/fortinet-forticloud-sso-zero-day-vulnerability-cve-2026-24858/), [Security Affairs](https://securityaffairs.com/187426/security/fortinet-patches-actively-exploited-fortios-sso-auth-bypass-cve-2026-24858.html)

---

### Upcoming: Microsoft Patch Tuesday - February 10, 2026

**Scheduled:** February 10, 2026 at 10:00 AM PST / 1:00 PM EST / 6:00 PM UTC
**Key Update:** Windows 11 KB5074105 cumulative security update

**Expected Content:**
- All out-of-band fixes from January (including CVE-2026-21509 Office zero-day patches)
- Windows 11 25H2/24H2 and Windows 10 ESU security updates
- Potential .NET framework updates
- Office security updates (including legacy 2016 versions)

**Context:** January Patch Tuesday addressed 112-114 vulnerabilities including the actively exploited CVE-2026-20805 DWM information-disclosure flaw.

**Sources:** [Help Net Security - Forecast](https://www.helpnetsecurity.com/2026/02/06/february-2026-patch-tuesday-forecast/), [MSFTNewsNow](https://msftnewsnow.com/microsoft-patch-tuesday-february-10-2026-windows/), [Zecurit](https://zecurit.com/endpoint-management/patch-tuesday/)

---

### Upcoming CISA KEV Deadlines

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20045 | Cisco Unified CM/Webex | **February 11, 2026** |
| CVE-2025-31125 | Vite Vitejs | February 12, 2026 |
| CVE-2025-34026 | Versa Concerto | February 12, 2026 |
| CVE-2025-68645 | Zimbra ZCS | February 12, 2026 |
| CVE-2026-21509 | Microsoft Office | February 16, 2026 |
| CVE-2019-19006/CVE-2025-64328 | FreePBX/Sangoma | February 24, 2026 |
| CVE-2021-39935 | GitLab CE/EE | February 24, 2026 |
| CVE-2026-24423 | SmarterTools SmarterMail | February 26, 2026 |
| CVE-2025-11953 | React Native CLI | February 26, 2026 |

---

## APT & Threat Actor Activity

### NEW: TGR-STA-1030 "Shadow Campaigns" - Asia-Based State Espionage

**Threat Actor:** TGR-STA-1030
**Attribution:** State-aligned, operating out of Asia (high confidence, per Unit 42)
**Discovered by:** Palo Alto Networks Unit 42
**Scale:** 70+ organizations compromised across 37 countries
**Active:** Throughout 2025 and into 2026

**Targets Compromised:**
- Five national-level law enforcement and border control entities
- Three ministries of finance plus other government ministries
- One nation's parliament
- A senior elected official of another nation
- National-level telecommunications companies
- National police and counter-terrorism organizations

**Reconnaissance Scope:**
- November-December 2025: Active reconnaissance against government infrastructure in 155 countries
- Following the January 3, 2026 US Operation Absolute Resolve (capture of Venezuelan president), TGR-STA-1030 conducted extensive reconnaissance targeting 140+ government-owned IP addresses

**Persistence:** Maintained access to several compromised entities for months

**Significance:** The scope and target selection (parliaments, elected officials, law enforcement, telecom) indicate a highly capable nation-state operation with strategic intelligence objectives.

**Sources:** [Unit 42 - Shadow Campaigns](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/), [The Register](https://www.theregister.com/2026/02/05/asia_government_spies_hacked_37_critical_networks), [The Record](https://therecord.media/research-cyber-espionage-targeting-dozens-worldwide), [Axios](https://www.axios.com/2026/02/05/cyberespionage-government-hacking-campaign-palo-alto-networks)

---

### NEW: State-Backed Signal Account Hijacking Campaign

**Advisory by:** German BfV (Federal Office for the Protection of the Constitution) and BSI (Federal Office for Information Security)
**Attribution:** Likely state-sponsored (suspected Russian-linked)
**Target Region:** Germany and Europe

**Targets:**
- Politicians and senior government figures
- Military officers
- Diplomats
- Investigative journalists

**Attack Method:**
- No malware used; no technical vulnerabilities exploited
- Attackers contact targets directly via Signal
- Impersonate Signal support team or support chatbot
- Steal PINs or trick targets into linking attacker-controlled devices
- Enables real-time message interception and impersonation

**Why Effective:**
- Exploits trust in Signal as a "secure" platform
- Social engineering bypasses all technical security controls
- Linked devices receive all future messages in real time

**Mitigation:**
- Signal never contacts users directly - block and report such accounts
- Review linked devices regularly in Signal settings
- Enable Registration Lock in Signal

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/germany-warns-of-signal-account-hijacking-targeting-senior-figures/), [The Hacker News](https://thehackernews.com/2026/02/german-agencies-warn-of-signal-phishing.html), [Help Net Security](https://www.helpnetsecurity.com/2026/02/06/state-linked-phishing-europe-journalists-signal/)

---

## Ransomware & Law Enforcement

### NEW: Two US Cybersecurity Professionals Plead Guilty as BlackCat Affiliates

**Defendants:**
- **Kevin Martin**, 36, Texas - Ransomware negotiator at DigitalMint (threat intelligence/incident response firm)
- **Ryan Goldberg**, 40, Georgia - Incident response manager at Sygnia (cybersecurity company)

**Charges:** Conspiracy to commit extortion as ALPHV/BlackCat ransomware affiliates

**Details:**
- Operated between April 2023 and December 2023
- Paid ALPHV/BlackCat administrators 20% of ransoms for platform access
- Successfully extorted one victim for ~$1.2 million in Bitcoin
- Split their 80% share three ways and laundered funds
- A third co-conspirator was also involved

**Sentencing:** March 12, 2026; face up to 20 years in prison

**Significance:** This case is extraordinary because both defendants worked professionally in cybersecurity - one as a ransomware negotiator and the other in incident response. They had insider knowledge of victim organizations' willingness and ability to pay, creating a severe conflict of interest.

**Sources:** [DOJ Press Release](https://www.justice.gov/opa/pr/two-americans-plead-guilty-targeting-multiple-us-victims-using-alphv-blackcat-ransomware), [SecurityWeek](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/), [The Record](https://therecord.media/ransomware-responders-guilty-plea-using-alphv-blackcat-us-attacks), [CSO Online](https://www.csoonline.com/article/4112400/two-cybersecurity-experts-plead-guilty-to-running-ransomware-operation.html)

---

### FTC Issues Second Ransomware Report to Congress

The Federal Trade Commission released its second report to Congress under the RANSOMWARE Act on February 6, 2026, detailing the agency's efforts to combat ransomware and cyberattacks from China, Russia, North Korea, and Iran.

**Source:** [FTC Press Release](https://www.ftc.gov/news-events/news/press-releases/2026/02/ftc-issues-second-report-congress-its-work-fight-ransomware-other-cyberattacks)

---

### 2025 Ransomware Statistics

Emsisoft's "State of Ransomware in the US" report for 2025:
- **8,000+ organizations targeted** (up from ~6,000 in 2024)
- Active ransomware groups increased ~30% compared to 2024
- Trend toward pure data-exfiltration extortion (no encryption) is accelerating

**Sources:** [SecurityWeek](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/), [Morphisec](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)

---

## Data Breaches

### NEW: AT&T Breach Data Resurfaces with Enhanced Profiles

**Status:** Previously breached data (March/July 2024) repackaged and circulating since February 2, 2026
**Risk Level:** Elevated

**What Changed:**
- The resurfaced dataset contains more complete profiles per person
- More email addresses and SSNs per record than original leaks
- Data has been enriched through cross-referencing with other breaches
- More searchable and actionable for criminals

**Context:** AT&T's original breach affected 73 million customers. A $177M class action settlement was already reached. The data's re-emergence in enriched form creates new risks from old breaches.

**Recommendations:**
- Monitor for phishing using AT&T-related lures
- Enable MFA on all accounts
- Lock mobile accounts with extra passcodes
- Consider credit monitoring/freeze

**Sources:** [Malwarebytes](https://www.malwarebytes.com/blog/news/2026/02/att-breach-data-resurfaces-with-new-risks-for-customers), [JDSupra/HaystackID](https://www.jdsupra.com/legalnews/at-t-customer-data-resurfaces-on-dark-9253832/)

---

## Policy & Directives

### NEW: CISA Binding Operational Directive 26-02 - Edge Device Lifecycle Management

**Issued:** February 5, 2026
**Title:** "Mitigating Risk From End-of-Support Edge Devices"
**Scope:** US Federal Civilian Executive Branch (FCEB) agencies

**Timeline:**
| Phase | Deadline | Requirement |
|-------|----------|-------------|
| Inventory | 3 months | Identify all unsupported edge devices |
| Removal begins | 12 months | Begin removing/replacing EOL devices |
| Full compliance | 18 months | Eliminate all unsupported edge devices |
| Ongoing | Continuous | Monitor to prevent reintroduction |

**Affected Device Types:**
- Load balancers, firewalls, routers, switches
- Wireless access points, network security appliances
- IoT edge devices, SDN devices
- Physical or virtual networking devices

**Justification:** CISA is aware of widespread exploitation campaigns by advanced threat actors (some nation-state) targeting end-of-service edge devices.

**Sources:** [CISA](https://www.cisa.gov/news-events/news/cisa-orders-federal-agencies-strengthen-edge-device-security-amid-rising-cyber-threats), [The Hacker News](https://thehackernews.com/2026/02/cisa-orders-removal-of-unsupported-edge.html), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisa-orders-federal-agencies-to-replace-end-of-life-edge-devices/), [CyberScoop](https://cyberscoop.com/cisa-bod-directive-unsupported-edge-devices-firewalls-routers/)

---

## Vendor Advisories

### BeyondTrust
- Remote Support and PRA patched for CVE-2026-1731 (CVSS 9.9)
- SaaS auto-patched Feb 2; on-prem requires manual update

### Fortinet
- FortiOS 7.4.11 patches CVE-2026-24858 (FortiCloud SSO auth bypass)
- Additional product patches (FortiManager, FortiAnalyzer) forthcoming

### Microsoft
- Patch Tuesday February 10 expected; includes all January OOB fixes
- KB5074105 for Windows 11

### CISA
- BOD 26-02 issued for edge device lifecycle management
- KEV deadlines: Cisco UCM/Webex (Feb 11), Vite/Versa/Zimbra (Feb 12)

---

## Recommended Actions

### Immediate Priority (Next 48 Hours)

1. **BeyondTrust RS/PRA** - On-prem customers: patch CVE-2026-1731 immediately; ~8,500 instances exposed (CVSS 9.9)
2. **Fortinet** - Upgrade FortiOS to 7.4.11 for CVE-2026-24858; check for unauthorized admin accounts and config changes
3. **Cisco UCM/Webex** - Patch CVE-2026-20045 before **February 11** CISA deadline
4. **Microsoft Patch Tuesday** - Prepare for February 10 release; pre-stage deployment

### High Priority (This Week)

5. **Signal security** - Brief high-value personnel on Signal phishing; review linked devices; enable Registration Lock
6. **Vite/Versa/Zimbra** - Patch before **February 12** CISA deadlines
7. **AT&T customers** - Alert users about enriched breach data; reinforce phishing awareness

### Threat Hunting

8. **FortiGate devices** - Audit for unauthorized local admin accounts created since January 20
9. **BeyondTrust logs** - Review for pre-auth exploitation attempts against RS/PRA
10. **Edge device inventory** - Begin asset discovery per CISA BOD 26-02 guidance
11. **Signal accounts** - Check for unauthorized linked devices across executive/VIP accounts

### Organizational

12. **Insider threat** - BlackCat/ALPHV case highlights risk of cybersecurity professionals acting as threat actors; review access controls and conflict-of-interest policies for IR/negotiation staff
13. **Edge device lifecycle** - Even non-federal organizations should adopt CISA BOD 26-02 principles

---

## Sources

- [BeyondTrust Advisory BT26-02](https://www.beyondtrust.com/trust-center/security-advisories/bt26-02)
- [The Hacker News - BeyondTrust RCE](https://thehackernews.com/2026/02/beyondtrust-fixes-critical-pre-auth-rce.html)
- [Help Net Security - BeyondTrust CVE-2026-1731](https://www.helpnetsecurity.com/2026/02/09/beyondtrust-remote-access-vulnerability-cve-2026-1731/)
- [CISA - Fortinet CVE-2026-24858](https://www.cisa.gov/news-events/alerts/2026/01/28/fortinet-releases-guidance-address-ongoing-exploitation-authentication-bypass-vulnerability-cve-2026)
- [The Hacker News - Fortinet CVE-2026-24858](https://thehackernews.com/2026/01/fortinet-patches-cve-2026-24858-after.html)
- [Help Net Security - Fortinet FortiCloud SSO](https://www.helpnetsecurity.com/2026/01/28/fortinet-forticloud-sso-zero-day-vulnerability-cve-2026-24858/)
- [Security Affairs - Fortinet SSO Bypass](https://securityaffairs.com/187426/security/fortinet-patches-actively-exploited-fortios-sso-auth-bypass-cve-2026-24858.html)
- [Unit 42 - Shadow Campaigns](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [The Register - TGR-STA-1030](https://www.theregister.com/2026/02/05/asia_government_spies_hacked_37_critical_networks)
- [Axios - Cyberespionage 37 Countries](https://www.axios.com/2026/02/05/cyberespionage-government-hacking-campaign-palo-alto-networks)
- [The Record - Global Espionage](https://therecord.media/research-cyber-espionage-targeting-dozens-worldwide)
- [BleepingComputer - Signal Hijacking](https://www.bleepingcomputer.com/news/security/germany-warns-of-signal-account-hijacking-targeting-senior-figures/)
- [The Hacker News - Signal Phishing](https://thehackernews.com/2026/02/german-agencies-warn-of-signal-phishing.html)
- [Help Net Security - Signal Phishing Europe](https://www.helpnetsecurity.com/2026/02/06/state-linked-phishing-europe-journalists-signal/)
- [DOJ - BlackCat Guilty Pleas](https://www.justice.gov/opa/pr/two-americans-plead-guilty-targeting-multiple-us-victims-using-alphv-blackcat-ransomware)
- [SecurityWeek - Cybersecurity Pros Guilty](https://www.securityweek.com/two-us-cybersecurity-pros-plead-guilty-over-ransomware-attacks/)
- [The Record - ALPHV Guilty Pleas](https://therecord.media/ransomware-responders-guilty-plea-using-alphv-blackcat-us-attacks)
- [CSO Online - Ransomware Operation](https://www.csoonline.com/article/4112400/two-cybersecurity-experts-plead-guilty-to-running-ransomware-operation.html)
- [Malwarebytes - AT&T Data Resurfaces](https://www.malwarebytes.com/blog/news/2026/02/att-breach-data-resurfaces-with-new-risks-for-customers)
- [CISA - BOD 26-02](https://www.cisa.gov/news-events/news/cisa-orders-federal-agencies-strengthen-edge-device-security-amid-rising-cyber-threats)
- [The Hacker News - CISA Edge Devices](https://thehackernews.com/2026/02/cisa-orders-removal-of-unsupported-edge.html)
- [BleepingComputer - CISA EOL Devices](https://www.bleepingcomputer.com/news/security/cisa-orders-federal-agencies-to-replace-end-of-life-edge-devices/)
- [CyberScoop - CISA BOD](https://cyberscoop.com/cisa-bod-directive-unsupported-edge-devices-firewalls-routers/)
- [FTC - Ransomware Report](https://www.ftc.gov/news-events/news/press-releases/2026/02/ftc-issues-second-report-congress-its-work-fight-ransomware-other-cyberattacks)
- [SecurityWeek - 8000 Ransomware Attacks](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)
- [Help Net Security - Patch Tuesday Forecast](https://www.helpnetsecurity.com/2026/02/06/february-2026-patch-tuesday-forecast/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 2-6, 2026 reports:

- CVE-2025-40551 SolarWinds WHD (deadline passed Feb 6)
- CVE-2026-24423 SmarterMail RCE (ransomware exploitation)
- CVE-2025-11953 React Native CLI command injection
- CVE-2026-22778 vLLM RCE via video URL
- CVE-2026-25049 n8n sandbox escape (fourth critical flaw)
- CVE-2025-22224/22225/22226 VMware ESXi chain (ransomware confirmed)
- CVE-2026-21509 Microsoft Office zero-day / APT28 Operation Neusploit
- CVE-2026-20045 Cisco UCM/Webex zero-day
- CVE-2026-20805 Microsoft DWM zero-day (deadline passed Feb 3)
- CVE-2025-40602 SonicWall SMA1000 chained zero-day
- CVE-2026-24061 GNU InetUtils telnetd
- CVE-2026-0625 D-Link DSL routers (no patch)
- CVE-2026-1862/1861 Chrome V8 type confusion and heap corruption
- Apple iOS 26.2 WebKit zero-days (CVE-2025-43529, CVE-2025-14174)
- React2Shell NGINX hijacking campaign (CVE-2025-55182)
- Amaranth-Dragon (APT-41 linked) SE Asia espionage
- APT28 Operation Neusploit details
- Iranian APT Infy (Prince of Persia) - Telegram C2
- Phantom Taurus NET-STAR malware suite
- Conduent breach (25.9M+ Americans, Safepay ransomware)
- Harvard/UPenn breach (ShinyHunters, 2.2M+ records)
- Under Armour breach (72.7M accounts)
- Nike/WorldLeaks (1.4TB)
- Crunchbase breach (2M+ records)
- Target source code theft (860 GB)
- Substack data breach (Feb 5)
- Reddit data breach (Feb 5)
- Hawk Law Group - INC ransomware
- Energy/utilities sector 60%+ ransomware surge
- Oleg Nefedov - EU Most Wanted ransomware leader

---

*Report generated: 2026-02-08*
*Next report: 2026-02-09*
*Classification: TLP:CLEAR*
