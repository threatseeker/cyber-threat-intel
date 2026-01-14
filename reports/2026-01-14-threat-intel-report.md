# Cyber Threat Intelligence Report
## Date: January 14, 2026

---

## Executive Summary

Today's threat landscape features significant developments in APT activity, new malware discoveries, and major data breach disclosures:

- **Salt Typhoon Congressional Breach**: Chinese state-sponsored hackers compromised email systems of US congressional committee staff members on powerful defense, intelligence, and foreign affairs committees
- **VoidLink Malware Framework**: Check Point Research publicly disclosed a sophisticated cloud-native Linux malware framework designed for long-term stealth access
- **AI Infrastructure Under Attack**: GreyNoise detected over 91,000 attack sessions targeting AI tools like Ollama and OpenAI between October 2025 and January 2026
- **Everest Ransomware Claims Nissan Breach**: 900GB of data allegedly exfiltrated from the automotive giant
- **Fortinet Security Advisory (January 14)**: Critical vulnerabilities in FortiSIEM and FortiOS requiring immediate patching
- **Major Data Breaches**: Illinois DHS exposed 700K residents' data; SoundCloud breach affects tens of millions

---

## Critical Vulnerabilities

### [UPDATE] Fortinet Critical Vulnerabilities - Advisory Released January 14, 2026

**CVE-2025-64155** - FortiSIEM OS Command Injection
- **CVSS Score**: 9.4 (Critical)
- **Impact**: Remote code execution with root privileges, no authentication required
- **Affected Versions**: 7.4.0, 7.3.0-7.3.4, 7.1.0-7.1.8, 7.0.0-7.0.4, 6.7.0-6.7.10
- **Status**: Patch available - upgrade immediately

**CVE-2025-25249** - FortiOS/FortiSwitchManager Heap Buffer Overflow
- **CVSS Score**: 7.4 (High)
- **Impact**: Arbitrary code execution via unauthenticated remote requests
- **Affected Versions**:
  - FortiOS: 7.6.0-7.6.3, 7.4.0-7.4.8, 7.2.0-7.2.11, 7.0.0-7.0.17, 6.4.0-6.4.16
  - FortiSwitchManager: 7.2.0-7.2.6, 7.0.0-7.0.5
- **Remediation**: Upgrade to FortiOS 7.6.4+, 7.4.9+, 7.2.12+, 7.0.18+, 6.4.17+
- **Workaround**: Restrict CAPWAP-CONTROL access to ports 5246-5249

**Source**: [Secure-ISS SOC Advisory](https://secure-iss.com/soc-advisory-fortinet-fortisiem-fortios-critical-vulnerabilities-14-jan-2026/)

### New Microsoft CVEs from January Patch Tuesday

**CVE-2026-20940** - Windows Cloud Files Mini Filter Driver Elevation of Privilege
- Published January 13, 2026 - Part of January Patch Tuesday
- Exploitation: More Likely

**CVE-2026-20936** - Windows NDIS Information Disclosure
- Published January 13, 2026

**CVE-2026-20811** - Win32k Elevation of Privilege
- Published January 13, 2026

**CVE-2026-20919** - Windows SMB Server Elevation of Privilege
- Published January 13, 2026

**CVE-2026-20922** - Windows NTFS Remote Code Execution
- **CVSS Score**: 7.8
- **Impact**: Heap-based buffer overflow enabling arbitrary code execution
- **Exploitation**: More Likely

**CVE-2026-20949** - Microsoft Excel Security Feature Bypass
- Part of January 2026 Patch Tuesday cycle

**CVE-2026-21219** - Inbox COM Objects Remote Code Execution
- Published January 13, 2026

**Source**: [Microsoft January 2026 Patch Tuesday](https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805)

---

## Exploits & Zero-Days

### No New Zero-Days Reported Today

Previous zero-days from January Patch Tuesday continue active exploitation:
- [UPDATE] **CVE-2026-20805** - Desktop Window Manager Information Disclosure remains actively exploited in the wild

---

## Malware & Ransomware

### NEW: VoidLink Cloud-Native Linux Malware Framework

Check Point Research has publicly disclosed a sophisticated malware framework discovered in December 2025:

**Technical Details**:
- **Target**: Linux-based cloud environments (AWS, GCP, Azure, Alibaba, Tencent)
- **Written in**: Zig, Go, and C
- **Architecture**: Modular plugin API with 30+ plugins (similar to Cobalt Strike BOFs)
- **Capabilities**:
  - Custom loaders, implants, rootkits
  - Runtime code encryption
  - Self-deletion upon tampering
  - Adaptive behavior based on detected environment
  - User-mode and kernel-level rootkit capabilities
  - Security product enumeration and risk scoring

**Attribution**: Chinese-affiliated developers (exact affiliation unclear)

**Current Status**: No real-world infections observed yet - appears to be a commercial product or framework developed for a customer

**Source**: [Check Point Research](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/)

### NEW: Everest Ransomware Claims Nissan Breach

**Date Disclosed**: January 10, 2026

**Details**:
- Everest ransomware group claims 900GB data exfiltration from Nissan Motor Corporation
- Evidence includes directory structures showing ZIP archives, text files, Excel sheets, and CSV documents
- Screenshots allegedly show dealer names, addresses, and dealership programs

**Verification Status**: Unconfirmed - Nissan has not publicly responded

**Threat Actor**: Everest (Russia-linked RaaS group active since July 2021, 330+ claimed victims since 2023)

**Previous Nissan Incident**: Mid-December 2025 - approximately 21,000 customer records accessed via Red Hat CMS vulnerability

**Source**: [Hackread](https://hackread.com/everest-ransomware-nissan-data-breach/)

### NEW: 91,000+ Attacks Targeting AI Infrastructure

**Period**: October 2025 - January 2026

**Discovery**: GreyNoise honeypot research

**Key Findings**:
- 91,403 attack sessions detected against AI tools (Ollama, OpenAI)
- Two separate active campaigns identified
- Attack spike of 1,688 sessions over 48 hours around Christmas 2025
- 62 source IPs across 27 countries involved

**Attack Methods**:
- Testing OpenAI-compatible and Google Gemini API formats
- SSRF vulnerabilities exploiting Ollama's model pull functionality
- Malicious registry URL injection
- Twilio SMS webhook integrations via MediaURL parameter

**Targeted Models**: GPT-4o, Claude, Llama, DeepSeek, Gemini, Mistral, Qwen, Grok

**Source**: [Hackread](https://hackread.com/hackers-attack-ai-systems-fake-ollama-servers/)

---

## Threat Actors

### NEW: Salt Typhoon Breaches US Congressional Email Systems

**Disclosed**: January 8, 2026

**Attribution**: Chinese Ministry of State Security (MSS)

**Targets**:
- House China Committee staff emails
- Foreign Affairs Committee staff
- Intelligence Committee staff
- Armed Services Committee staff

**Details**:
- Part of the ongoing Salt Typhoon espionage operation
- Intrusions detected in December 2025
- Campaign enables monitoring of US telecommunications and email
- Previously intercepted calls of senior US officials

**China Response**: Denied allegations, calling them "politically motivated disinformation"

**Previous Actions**: US sanctioned alleged hacker Yin Kecheng and Sichuan Juxinhe Network Technology earlier in 2025

**Source**: [IT Pro](https://www.itpro.com/security/cyber-attacks/salt-typhoon-us-congress-email-cyber-attack)

### Phantom Taurus (New APT Documented)

**Attribution**: Chinese nation-state actor

**Targets**: Government agencies, embassies, military operations across Africa, Middle East, Asia

**Notable TTPs**:
- Goes directly after high-value systems (not typical social engineering)
- Resurfaces within hours or days after discovery (atypical for APTs)
- Shows unusual persistence and speed in retooling

**Source**: [Dark Reading](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)

---

## Vendor Advisories

### Fortinet (January 14, 2026)
- Critical advisory for FortiSIEM, FortiOS, FortiSwitchManager
- CVE-2025-64155 (CVSS 9.4) and CVE-2025-25249 (CVSS 7.4)
- **Action**: Immediate patching required

**Source**: [Secure-ISS](https://secure-iss.com/soc-advisory-fortinet-fortisiem-fortios-critical-vulnerabilities-14-jan-2026/)

### Coordinated Attacks on Network Devices
- GreyNoise reports attacks on Cisco, Fortinet, and Palo Alto Networks devices originate from same infrastructure
- Three campaigns share TCP fingerprints and leverage same subnets
- **Recommendation**: Block IPs brute forcing Fortinet SSL VPNs; harden firewall/VPN defenses

**Source**: [SecurityWeek](https://www.securityweek.com/cisco-fortinet-palo-alto-networks-devices-targeted-in-coordinated-campaign/)

---

## Industry News & Data Breaches

### NEW: Illinois Department of Human Services Breach - 700K Affected

**Disclosed**: January 2026 (incident discovered September 22, 2025)

**Details**:
- Misconfigured privacy settings exposed internal resource allocation maps
- Two affected groups:
  - 672,616 Medicaid/Medicare recipients (addresses, case numbers, demographic details, medical plan names) - exposed Jan 2022 to Sept 2025
  - 32,401 Rehabilitation Services customers (names, addresses, case numbers, case status) - exposed April 2021 to Sept 2025

**Remediation**: New Secure Map Policy implemented; access restricted by role

**Concern**: Notification delayed 100+ days despite 60-day federal requirement

**Source**: [BleepingComputer](https://www.bleepingcomputer.com/news/security/illinois-department-of-human-services-data-breach-affects-700k-people/)

### NEW: SoundCloud Data Breach

**Details**:
- Unauthorized activity detected in ancillary service dashboard
- Email addresses and public profile information exfiltrated
- Estimated impact: ~20% of 140 million user base (tens of millions of accounts)

**Source**: [BreachSense](https://www.breachsense.com/breaches/2026/january/)

### NEW: PayPal Credentials Leak (Alleged)

**Date**: January 11, 2026

**Details**:
- Threat actor "Lud" posted 104,472 PayPal credentials (email:password format)
- Data allegedly from December 2025
- Researchers believe data from infostealer logs, not direct breach
- MFA protection makes exploitation more difficult

**Source**: [Cybernews](https://cybernews.com/security/paypal-credential-data-leak-claims/)

### UPDATE: Sedgwick Government Solutions - TridentLocker Ransomware

- TridentLocker claimed attack on New Year's Eve
- 3.4GB data allegedly stolen
- Affects federal contractor providing services to DHS, ICE, CBP, USCIS, DOL, and CISA

**Source**: [The Record](https://therecord.media/sedgwick-cyber-incident-ransomware)

---

## Recommended Actions

### Immediate (24-48 hours)

1. **Fortinet Devices**: Apply patches for CVE-2025-64155 and CVE-2025-25249 immediately or implement CAPWAP-CONTROL port restrictions
2. **AI Infrastructure**: Implement strict model pull restrictions, egress filtering, and rate-limiting for Ollama deployments
3. **Network Security**: Block IPs associated with coordinated attacks on Cisco/Fortinet/Palo Alto devices
4. **Email Security**: Enhanced monitoring for congressional and government-related communications

### Short-Term (1-2 weeks)

1. **Cloud Linux Systems**: Review for indicators of VoidLink framework; enhance monitoring of cloud-native workloads
2. **Credential Hygiene**: Force password resets for users who may reuse credentials across PayPal and other services
3. **Vendor Patch Assessment**: Complete January Microsoft Patch Tuesday deployment (114 CVEs)

### Ongoing

1. **APT Monitoring**: Track Salt Typhoon and Phantom Taurus indicators of compromise
2. **Ransomware Defense**: Review data exfiltration prevention controls given Everest group activity
3. **AI Security**: Audit AI/LLM deployments for public exposure and misconfigurations

---

## Sources

### CISA & Government
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA January 12, 2026 KEV Update](https://www.cisa.gov/news-events/alerts/2026/01/12/cisa-adds-one-known-exploited-vulnerability-catalog)

### Vendor Advisories
- [Fortinet FortiSIEM/FortiOS Advisory - January 14, 2026](https://secure-iss.com/soc-advisory-fortinet-fortisiem-fortios-critical-vulnerabilities-14-jan-2026/)
- [Microsoft January 2026 Patch Tuesday](https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805)

### Threat Intelligence
- [Check Point - VoidLink Malware Framework](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/)
- [GreyNoise - AI Infrastructure Attacks](https://hackread.com/hackers-attack-ai-systems-fake-ollama-servers/)
- [Dark Reading - Phantom Taurus APT](https://www.darkreading.com/cyberattacks-data-breaches/new-china-apt-strikes-precision-persistence)

### Ransomware & Breaches
- [Hackread - Everest Ransomware Nissan Claim](https://hackread.com/everest-ransomware-nissan-data-breach/)
- [BleepingComputer - Illinois DHS Breach](https://www.bleepingcomputer.com/news/security/illinois-department-of-human-services-data-breach-affects-700k-people/)
- [The Record - Sedgwick Government Solutions](https://therecord.media/sedgwick-cyber-incident-ransomware)

### APT Activity
- [IT Pro - Salt Typhoon Congressional Breach](https://www.itpro.com/security/cyber-attacks/salt-typhoon-us-congress-email-cyber-attack)
- [SecurityWeek - Coordinated Network Device Attacks](https://www.securityweek.com/cisco-fortinet-palo-alto-networks-devices-targeted-in-coordinated-campaign/)

### News Sources
- [The Hacker News](https://thehackernews.com/)
- [SecurityWeek](https://www.securityweek.com/)
- [Cybernews](https://cybernews.com/)
- [Dark Reading](https://www.darkreading.com/)

---

*Report generated: January 14, 2026*
*Classification: TLP:WHITE - Unrestricted distribution*
