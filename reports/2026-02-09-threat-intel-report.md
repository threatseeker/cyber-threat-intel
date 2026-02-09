# Cyber Threat Intelligence Report
**Date:** February 9, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0209

---

## Executive Summary

- **NEW**: Google disrupts IPIDEA residential proxy network - 550+ threat groups (China, DPRK, Iran, Russia) used it for password spraying, botnet C2, and SaaS access; millions of devices removed
- **NEW**: Chinese hackers breached US House of Representatives committee staff email systems - foreign affairs, intelligence, and armed services committees impacted
- **NEW**: Chat & Ask AI app exposed 300M messages from 25M+ users via Firebase misconfiguration - sensitive content including suicide inquiries and illegal activities
- **NEW**: Panera Bread breach confirmed at 5.1M records (ShinyHunters) - Microsoft Entra SSO compromised via vishing; 760GB archive leaked after extortion refused
- **NEW**: Spain's Ministry of Science shut down IT systems after "GordonFreeman" exploited IDOR vulnerability for full admin access; data offered for sale
- **NEW**: Illinois DHS breach affects 700K individuals - Medicaid/Medicare data exposed via publicly accessible mapping website
- **NEW**: AI-powered phishing campaign clones 150+ law firm websites behind Cloudflare for recovery scam re-victimization (Sygnia)
- **UPCOMING**: Microsoft Patch Tuesday - February 10, 2026

---

## Critical Vulnerabilities

### [UPDATE] n8n Vulnerability Count Expands - 16 Total, 6 Critical

Previous reports covered CVE-2026-21858 (CVSS 10.0), CVE-2026-1470 (9.9), CVE-2026-25049 (9.4), and CVE-2026-0863 (8.5). Additional critical flaws now disclosed:

| CVE | CVSS | Type | Fixed In |
|-----|------|------|----------|
| CVE-2026-21858 | 10.0 | Unauth RCE (Ni8mare) | 1.123.17 / 2.5.2 |
| CVE-2026-21877 | Critical | Authenticated RCE | 1.120.3 |
| CVE-2026-21893 | 9.4 | Command injection (admin) | 1.120.3 |
| CVE-2026-1470 | 9.9 | Security control bypass | 1.123.17 / 2.5.2 |
| CVE-2026-25049 | 9.4 | Sandbox escape | 1.123.17 / 2.5.2 |
| CVE-2026-25051 | 8.5 | XSS via webhook responses | 1.123.17 / 2.5.2 |

**Total:** 16 vulnerabilities disclosed, 6 rated critical. Public exploits available for Ni8mare (CVE-2026-21858). Canadian Cyber Centre (AL26-001) issued advisory.

**Assessment:** n8n's security posture represents systemic risk. Organizations should evaluate continued production use.

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-n8n-flaws-disclosed-along-with-public-exploits/), [Rapid7](https://www.rapid7.com/blog/post/etr-ni8mare-n8scape-flaws-multiple-critical-vulnerabilities-affecting-n8n/), [Canadian Cyber Centre AL26-001](https://www.cyber.gc.ca/en/alerts-advisories/al26-001-vulnerabilities-affecting-n8n-cve-2026-21858-cve-2026-21877-cve-2025-68613)

---

### Upcoming: Microsoft Patch Tuesday - February 10, 2026

**Scheduled:** Tomorrow, February 10, 2026 at 10:00 AM PST
**Key Update:** Windows 11 KB5074105 cumulative security update

Includes all January out-of-band fixes (CVE-2026-21509 Office zero-day). January cycle addressed 112-114 vulnerabilities.

**Source:** [Help Net Security](https://www.helpnetsecurity.com/2026/02/06/february-2026-patch-tuesday-forecast/)

---

### CISA KEV Deadlines This Week

| CVE | Product | Deadline |
|-----|---------|----------|
| CVE-2026-20045 | Cisco Unified CM/Webex | **February 11 (Tue)** |
| CVE-2025-31125 | Vite Vitejs | **February 12 (Wed)** |
| CVE-2025-34026 | Versa Concerto | **February 12 (Wed)** |
| CVE-2025-68645 | Zimbra ZCS | **February 12 (Wed)** |

---

## Exploits & Campaigns

### NEW: AI-Powered Law Firm Cloning Campaign (150+ Domains)

**Discovered by:** Sygnia
**Scale:** 150+ cloned law firm websites
**Infrastructure:** Multiple registrars, distinct SSL/TLS certificates per domain, Cloudflare-fronted

**How It Works:**
1. Criminals use AI to clone legitimate law firm websites at industrial scale
2. Sites are deployed behind Cloudflare with rotating IP ranges to evade takedowns
3. Targets are victims of previous fraud ("recovery scams")
4. Cloned legal sites offer to recover previously lost funds, requiring no upfront payment
5. Victims are defrauded a second time

**Why It Matters:** Demonstrates AI's role in scaling social engineering infrastructure. Each clone is distinct enough to avoid pattern-based detection.

**Sources:** [SecurityWeek](https://www.securityweek.com/researchers-expose-network-of-150-cloned-law-firm-websites-in-ai-powered-scam-campaign/), [Dark Reading](https://www.darkreading.com/cloud-security/phishing-empire-undetected-google-cloudflare)

---

## Threat Actors

### NEW: Google Disrupts IPIDEA - World's Largest Residential Proxy Network

**Actor:** IPIDEA (proxy-as-a-service provider)
**Disrupted by:** Google Threat Intelligence Group (GTIG)
**Date:** Late January 2026

**Scale of Abuse:**
- **550+ distinct threat groups** observed using IPIDEA exit nodes in a single 7-day period
- Actors from China, DPRK, Iran, and Russia all represented
- Network consisted of millions of hijacked consumer devices

**How IPIDEA Worked:**
- SDKs offered to mobile/desktop developers surreptitiously enrolled user devices into the proxy network
- Enrolled devices served as exit nodes, routing attacker traffic through residential IPs
- Made malicious traffic appear to originate from legitimate home internet connections

**Observed Malicious Activities:**
- Access to victim SaaS platforms
- Password spraying attacks
- Botnet command and control
- Infrastructure obfuscation for APT operations

**Google's Actions:**
- Legal action to take down control domains
- Google Play Protect automatically removes apps with IPIDEA SDKs
- Millions of devices removed from the proxy network

**Sources:** [Google GTIG Blog](https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/gtig-ipidea-disrupted/), [Google Cloud - Disruption Details](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network), [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-disrupts-ipidea-residential-proxy-networks-fueled-by-malware/), [The Register](https://www.theregister.com/2026/01/29/google_ipidea_crime_network)

---

### NEW: Chinese Hackers Breach US Congressional Staff Emails

**Attribution:** China (state-sponsored)
**Targets:** Staff email systems of US House of Representatives committees
**Committees Impacted:**
- House Foreign Affairs Committee
- House Intelligence Committee
- House Armed Services Committee

**Discovery:** Intrusions detected in December 2025; disclosed in late January/early February 2026

**Status:** It remains unclear whether lawmakers' personal email accounts were accessed in addition to staff systems.

**Significance:** Targeting of intelligence, foreign affairs, and armed services committees suggests strategic intelligence collection on US defense and foreign policy.

**Sources:** [Nextgov/FCW](https://www.nextgov.com/cybersecurity/2026/01/chinese-hackers-targeted-email-systems-us-congressional-staff-people-familiar-say/410544/), [Jerusalem Post](https://www.jpost.com/international/article-882703), [Cyber Press](https://cyberpress.org/china-reportedly-hacked-email-systems/)

---

## Malware & Ransomware

### NEW: Sedgwick Government Solutions - TridentLocker Ransomware

**Victim:** Sedgwick Government Solutions (subsidiary of Sedgwick, third-party claims administrator)
**Threat Actor:** TridentLocker (first surfaced November 2025; double extortion / data broker)
**Attack Date:** December 31, 2025 (New Year's Eve)
**Data Stolen:** ~3.4 GB leaked publicly

**Government Clients Served:**
- Department of Homeland Security (DHS)
- CISA
- Immigration and Customs Enforcement (ICE)
- Customs and Border Protection (CBP)
- Citizenship and Immigration Services (USCIS)
- Department of Labor

**Sedgwick Response:** Isolated file transfer system affected; no evidence of claims management server access; law enforcement notified.

**Significance:** TridentLocker is a new entrant (Nov 2025) that successfully breached a major government contractor serving DHS and CISA on New Year's Eve - timing likely chosen for reduced security monitoring.

**Sources:** [SecurityWeek](https://www.securityweek.com/sedgwick-confirms-cyberattack-on-government-subsidiary/), [The Record](https://therecord.media/sedgwick-cyber-incident-ransomware), [BleepingComputer](https://www.bleepingcomputer.com/news/security/sedgwick-confirms-breach-at-government-contractor-subsidiary/)

---

## Data Breaches

### NEW: Panera Bread - 5.1M Records (ShinyHunters)

**Victim:** Panera Bread
**Threat Actor:** ShinyHunters
**Records:** 5.1 million unique email addresses (confirmed by HIBP)
**Data Volume:** 760 GB archive leaked
**Disclosure:** January 2026

**Attack Vector:** Vishing campaign targeting employees to compromise Microsoft Entra Single Sign-On (SSO) code. Attackers impersonated IT staff to trick employees into entering credentials on a phishing page mimicking the SSO platform.

**Data Exposed:**
- Email addresses
- Names
- Physical addresses
- Phone numbers

**Context:** Data leaked after Panera refused extortion demands. ShinyHunters is the same group behind the Harvard/UPenn breaches (also via vishing).

**Sources:** [SecurityWeek](https://www.securityweek.com/hackers-leak-5-1-million-panera-bread-accounts/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/panera-bread-data-breach-impacts-51-million-accounts-not-14-million-customers/), [Security Affairs](https://securityaffairs.com/187556/data-breach/panera-bread-breach-affected-5-1-million-accounts-hibp-confirms.html), [Tom's Guide](https://www.tomsguide.com/computing/online-security/panera-data-breach-hits-over-5-million-customers-names-emails-phone-numbers-and-physical-addresses-exposed)

---

### NEW: Chat & Ask AI - 300M Messages / 25M Users Exposed

**App:** Chat & Ask AI (50M+ installs on Google Play + App Store)
**Discovered by:** Security researcher "Harry"
**Records:** ~300 million messages from 25+ million users
**Cause:** Misconfigured Google Firebase backend

**What Was Exposed:**
- Full chat messages (including sensitive/illegal content)
- Timestamps
- Model settings
- Chatbot names created by users

**Sensitive Content Found in Sample:**
- Suicide inquiries and notes
- Drug manufacturing instructions
- Hacking tutorials
- Other illegal activity requests

**App Details:** Chat & Ask AI is a wrapper app connecting to OpenAI's ChatGPT, Anthropic's Claude, and Google's Gemini. The exposure reveals what users thought were private AI conversations.

**Resolution:** Codeway (app developer) fixed the misconfiguration within hours of disclosure on January 20.

**Sources:** [404 Media](https://www.404media.co/massive-ai-chat-app-leaked-millions-of-users-private-conversations/), [Fox News](https://www.foxnews.com/tech/millions-ai-chat-messages-exposed-app-data-leak), [CyberGuy](https://cyberguy.com/security/millions-ai-chat-messages-exposed-app-data-leak/)

---

### NEW: Illinois DHS - 700K Individuals

**Agency:** Illinois Department of Human Services (IDHS)
**Affected:** ~700,000 individuals total
**Cause:** Publicly accessible mapping website (misconfiguration)

**Breakdown:**
- 32,000 Division of Rehabilitation Services (DRS) customers - names, addresses, case numbers, referral data
- ~672,000 Medicaid and Medicare Savings Program recipients - addresses, case numbers, demographics, medical assistance plans

**Sources:** [SecurityWeek](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)

---

### NEW: Spain Ministry of Science - IDOR Exploitation

**Victim:** Spain's Ministry of Science, Innovation and Universities
**Attack Date:** February 3, 2026
**Threat Actor:** "GordonFreeman"
**Vector:** Insecure Direct Object Reference (IDOR) vulnerability exploited for full admin access

**Impact:**
- Electronic services shut down
- Administrative procedures suspended
- Deadline extensions issued under Spanish administrative law
- Personal records, email addresses, enrollment applications leaked
- Data offered for sale on underground forums

**Sources:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/spains-ministry-of-science-shuts-down-systems-after-breach-claims/), [The Cyber Express](https://thecyberexpress.com/spain-ministry-of-science-cyberattack/)

---

## Vendor Advisories

### Microsoft
- **Patch Tuesday TOMORROW** (Feb 10) - KB5074105 for Windows 11; all January OOB fixes included
- Prepare deployment pipelines today

### n8n
- **16 total vulnerabilities** disclosed, 6 critical; public exploits available
- Canadian Cyber Centre advisory AL26-001 issued
- Minimum safe versions: 1.123.17 or 2.5.2

### Google
- IPIDEA residential proxy network disrupted; Play Protect blocking associated SDKs
- Monitor for residual proxy traffic from previously enrolled devices

---

## Recommended Actions

### Immediate Priority (Next 24 Hours)

1. **Prepare for Patch Tuesday** - Microsoft releases tomorrow (Feb 10); pre-stage KB5074105 deployment
2. **Patch Cisco UCM/Webex** - CISA deadline **February 11** for CVE-2026-20045
3. **n8n emergency assessment** - With 16 vulnerabilities (6 critical, public exploits), evaluate whether to take instances offline pending full patching to 1.123.17/2.5.2

### High Priority (This Week)

4. **Patch Vite/Versa/Zimbra** - Three CISA KEV deadlines on **February 12**
5. **IPIDEA indicator sweep** - Check network logs for known IPIDEA exit node IPs; review mobile device fleet for apps containing IPIDEA SDKs
6. **Firebase/cloud backend audit** - Chat & Ask AI incident highlights misconfigured backend risk; audit Firebase and similar BaaS configurations for public accessibility
7. **SSO security review** - Both Panera (Microsoft Entra) and Fortinet (FortiCloud) breaches exploited SSO mechanisms; review SSO configurations and add phishing-resistant MFA

### Threat Hunting

8. **Congressional staff indicators** - Government organizations should review for Chinese state-actor TTPs targeting email infrastructure
9. **Vishing campaign detection** - ShinyHunters using vishing across multiple targets (Harvard, UPenn, Panera); brief help desks and IT staff on impersonation tactics
10. **Law firm impersonation** - Legal industry should search for cloned versions of their websites; check Certificate Transparency logs for unauthorized SSL certs
11. **Residential proxy detection** - Monitor for anomalous traffic patterns from residential IP ranges that may indicate IPIDEA remnants

### Organizational

12. **AI chat privacy advisory** - Inform employees that AI chat app conversations may not be private; review organizational policies on AI tool usage
13. **Government contractor risk** - Sedgwick breach highlights supply chain risk for federal agencies; review third-party contractor security assessments

---

## Sources

- [Google GTIG - IPIDEA Disruption](https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/gtig-ipidea-disrupted/)
- [Google Cloud - Residential Proxy Disruption](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [BleepingComputer - IPIDEA](https://www.bleepingcomputer.com/news/security/google-disrupts-ipidea-residential-proxy-networks-fueled-by-malware/)
- [The Register - IPIDEA](https://www.theregister.com/2026/01/29/google_ipidea_crime_network)
- [Nextgov - Chinese Hackers Congressional Emails](https://www.nextgov.com/cybersecurity/2026/01/chinese-hackers-targeted-email-systems-us-congressional-staff-people-familiar-say/410544/)
- [Jerusalem Post - US House Breach](https://www.jpost.com/international/article-882703)
- [SecurityWeek - Panera Bread 5.1M](https://www.securityweek.com/hackers-leak-5-1-million-panera-bread-accounts/)
- [BleepingComputer - Panera Breach](https://www.bleepingcomputer.com/news/security/panera-bread-data-breach-impacts-51-million-accounts-not-14-million-customers/)
- [Security Affairs - Panera HIBP](https://securityaffairs.com/187556/data-breach/panera-bread-breach-affected-5-1-million-accounts-hibp-confirms.html)
- [404 Media - Chat & Ask AI](https://www.404media.co/massive-ai-chat-app-leaked-millions-of-users-private-conversations/)
- [Fox News - AI Chat Exposure](https://www.foxnews.com/tech/millions-ai-chat-messages-exposed-app-data-leak)
- [SecurityWeek - 8000 Ransomware / IDHS / China Emails](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)
- [SecurityWeek - Sedgwick](https://www.securityweek.com/sedgwick-confirms-cyberattack-on-government-subsidiary/)
- [The Record - Sedgwick Ransomware](https://therecord.media/sedgwick-cyber-incident-ransomware)
- [BleepingComputer - Sedgwick](https://www.bleepingcomputer.com/news/security/sedgwick-confirms-breach-at-government-contractor-subsidiary/)
- [BleepingComputer - Spain Ministry](https://www.bleepingcomputer.com/news/security/spains-ministry-of-science-shuts-down-systems-after-breach-claims/)
- [The Cyber Express - Spain Ministry](https://thecyberexpress.com/spain-ministry-of-science-cyberattack/)
- [SecurityWeek - AI Phishing Law Firms](https://www.securityweek.com/researchers-expose-network-of-150-cloned-law-firm-websites-in-ai-powered-scam-campaign/)
- [BleepingComputer - n8n Critical Flaws](https://www.bleepingcomputer.com/news/security/critical-n8n-flaws-disclosed-along-with-public-exploits/)
- [Rapid7 - n8n Ni8mare/N8scape](https://www.rapid7.com/blog/post/etr-ni8mare-n8scape-flaws-multiple-critical-vulnerabilities-affecting-n8n/)
- [Canadian Cyber Centre - AL26-001](https://www.cyber.gc.ca/en/alerts-advisories/al26-001-vulnerabilities-affecting-n8n-cve-2026-21858-cve-2026-21877-cve-2025-68613)
- [Help Net Security - Patch Tuesday Forecast](https://www.helpnetsecurity.com/2026/02/06/february-2026-patch-tuesday-forecast/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 5-8, 2026 reports:

- CVE-2026-1731 BeyondTrust RS/PRA (CVSS 9.9, pre-auth RCE)
- CVE-2026-24858 Fortinet FortiCloud SSO (auth bypass)
- CVE-2026-24423 SmarterMail (ransomware exploitation)
- CVE-2026-22778 vLLM (RCE via video URL)
- CVE-2026-25049 n8n (sandbox escape - now part of expanded disclosure above)
- CVE-2025-40551 SolarWinds WHD (deadline passed Feb 6)
- CVE-2025-22224/22225/22226 VMware ESXi chain
- CVE-2026-21509 Microsoft Office zero-day / APT28 Operation Neusploit
- CVE-2026-20045 Cisco UCM/Webex zero-day
- CVE-2025-40602 SonicWall SMA1000 chained zero-day
- CVE-2025-55182 React2Shell NGINX hijacking
- Apple iOS 26.2 WebKit zero-days
- Chrome 143 security update
- TGR-STA-1030 Shadow Campaigns (37 countries)
- Signal account hijacking campaign (Germany/Europe)
- CISA BOD 26-02 edge device directive
- Two US cybersecurity pros guilty as BlackCat affiliates
- Amaranth-Dragon SE Asia espionage
- Conduent breach (25.9M+)
- Harvard/UPenn breach (ShinyHunters)
- AT&T breach data resurface
- Substack/Reddit breaches
- Under Armour, Nike/WorldLeaks, Crunchbase, Target breaches
- Hawk Law Group (INC ransomware)
- FTC ransomware report to Congress
- Energy sector 60%+ ransomware surge

---

*Report generated: 2026-02-09*
*Next report: 2026-02-10*
*Classification: TLP:CLEAR*
