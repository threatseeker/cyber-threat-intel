# Cyber Threat Intelligence Report
**Date:** February 13, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0213

---

## Executive Summary

- **NEW**: Google Threat Intelligence Group reports nation-state actors from China, Iran, North Korea, and Russia actively using Gemini AI for reconnaissance, phishing, malware coding, and vulnerability research
- **NEW**: ChainedShark APT emerges as sophisticated China-nexus threat targeting international relations and marine technology research institutions
- **NEW**: MedRevenu healthcare billing breach exposes SSNs, medical records, and financial data; notifications began February 3
- **NEW**: EyeCare Partners breach compromises 55+ days of email access (Dec 2024-Jan 2025), exposing SSNs and clinical information
- **UPDATE**: Conduent breach expands to include nearly 17,000 Volvo Group North America employees
- **NEW**: BridgePay ransomware disrupts Bryan Texas Utilities payment processing, affecting 70,000 customers
- **NEW**: Flickr breach compromises usernames, IP addresses, location data via third-party provider attack

---

## Threat Actors

### NEW: Nation-State Actors Weaponize Google Gemini AI

**Disclosed:** February 12, 2026
**Source:** Google Threat Intelligence Group (GTIG) and Google DeepMind
**Threat Actors:** APT31 (China), APT42 (Iran), UNC2970 (North Korea), Russian state actors
**Reporting Period:** Q4 2025

**Attack Methods by Country:**

| Nation | APT Group | Gemini AI Use Cases |
|--------|-----------|---------------------|
| China | APT31 / Temp.HEX | Paired Gemini with Hexstrike tool for RCE analysis, web security bypass research, SQL injection targeting US entities |
| Iran | APT42 | Created official-seeming email addresses, conducted reconnaissance, established credible pretexts for social engineering |
| North Korea | UNC2970 | Synthesized OSINT, profiled high-value targets for campaign planning and reconnaissance |
| Russia | (Unnamed groups) | Target profiling, phishing lure generation, text translation, coding assistance |

**Model Extraction Attack:**
- Over 100,000 prompts deployed against Gemini in attempt to replicate the model's reasoning ability
- Focused on non-English language tasks
- Goal: steal intellectual property from the AI model itself

**Significance:** This marks the first comprehensive public disclosure of how nation-state APT groups are systematically integrating commercial AI tools across all stages of the cyber kill chain - from reconnaissance to payload development. The use of AI for social engineering (creating believable pretexts and official emails) represents a significant evolution in tradecraft sophistication.

**Sources:** [The Hacker News](https://thehackernews.com/2026/02/google-reports-state-backed-hackers.html), [The Record](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/nation-state-hackers-gemini-ai/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-says-hackers-are-abusing-gemini-ai-for-all-attacks-stages/), [CyberScoop](https://cyberscoop.com/state-hackers-using-gemini-google-ai/), [AI News](https://www.artificialintelligence-news.com/news/state-sponsored-hackers-ai-cyberattacks-google/)

---

### NEW: ChainedShark APT - Targeting Chinese Research Institutions

**Tracking Number:** Actor240820
**Disclosed:** NSFOCUS Fuying Lab (2025 retrospective, reported February 2026)
**Active Since:** May 2024
**Attribution:** State-sponsored attack team
**Targets:** Chinese universities and research institutions

**Target Profile:**
- Professionals in international relations and diplomacy
- Marine technology researchers
- Strategic research institutions
- Academic institutions with geopolitical research focus

**Technical Capabilities:**
- N-day vulnerability exploitation combined with custom trojans
- **LinkedShell** - custom trojan with high customization and advanced anti-forensic capabilities
- Meticulously designed attack chains with strong evasion and stealth
- Social engineering with fluent, natural Chinese-language lures

**First Wave - May 2024:**
The initial May 2024 campaign remains the most complex operation identified, deploying LinkedShell and demonstrating strategic coherence typical of nation-state operations.

**Motivation:** Intelligence collection targeting China's diplomatic and marine technology sectors, suggesting foreign intelligence service sponsorship.

**Sources:** [Security Boulevard](https://securityboulevard.com/2026/02/top-security-incidents-of-2025-the-emergence-of-the-chainedshark-apt-group/)

---

## Data Breaches

### NEW: MedRevenu Healthcare Billing Services Breach

**Victim:** MedRevenu, LLC (healthcare billing services provider)
**Incident Date:** Network disruption ~December 12, 2024
**Investigation Completion:** January 2025
**Notification Date:** February 3, 2026
**Impact:** Undisclosed number of patients and healthcare providers

**Data Exposed:**
- Names and birth dates
- Social Security numbers
- Driver's license and government ID numbers
- Health insurance and medical information
- Financial account and payment card numbers
- Account access credentials

**Timeline:**
- December 12, 2024: Network disruption detected
- January 2025: Investigation confirms unauthorized access to certain files
- February 3, 2026: Breach notification letters mailed to impacted individuals

**Remediation:** MedRevenu offering credit monitoring and identity theft protection services

**Sources:** [HIPAA Journal](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/), [ClassAction.org](https://www.classaction.org/data-breach-lawsuits/medrevenu-february-2026), [GlobeNewswire](https://www.globenewswire.com/news-release/2026/02/06/3234039/0/en/MedRevenu-Data-Breach-Claims-Investigated-by-Lynch-Carpenter.html)

---

### NEW: EyeCare Partners Email Security Incident

**Victim:** EyeCare Partners, LLC (St. Louis, MO - nationwide eye care provider)
**Incident Period:** December 3, 2024 - January 28, 2025 (55+ days)
**Discovery Date:** January 28, 2025
**Review Completion:** November 11, 2025
**Notification Date:** February 3, 2026
**Impact:** Undisclosed number of patients

**Attack Vector:** Unauthorized third-party accessed multiple managed email accounts for nearly two months before detection.

**Data Exposed:**
- Names and contact information
- Dates of birth
- Social Security numbers
- Driver's license numbers / state identification numbers
- Health plan information
- Limited clinical information

**Timeline Issues:**
- 55 days of unauthorized access before detection
- 9+ months between discovery and completion of account review
- Delayed notifications in February 2026

**Sources:** [HIPAA Journal](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/), [ClassAction.org](https://www.classaction.org/data-breach-lawsuits/eyecare-partners-february-2026), [Becker's ASC](https://www.beckersasc.com/ophthalmology/eyecare-partners-suffers-data-security-incident/)

---

### UPDATE: Conduent Breach Expands to Volvo Group North America

**Previous Coverage:** February 6, 9, 10, 12 reports (25.9M+ total victims)
**What's New:** Nearly **17,000 Volvo Group North America employees** confirmed as victims of the Conduent breach.

**Cumulative Impact:**
- 25M+ individuals affected across multiple states
- 15.4M in Texas alone
- 10+ federal class action lawsuits filed
- Credit monitoring deadline: **March 31, 2026**
- Attorney General Ken Paxton (Texas) issued Civil Investigative Demands to Conduent and Blue Cross Blue Shield of Texas

**Source:** [The Register](https://www.theregister.com/2026/02/10/conduent_volvo_breach/), [Texas AG Office](https://www.texasattorneygeneral.gov/news/releases/attorney-general-ken-paxton-demands-information-blue-cross-blue-shield-texas-and-conduent-part)

---

### NEW: Cottage Hospital Breach - 1,600 Affected

**Victim:** Cottage Hospital
**Incident Date:** October 2025
**Notification Date:** February 6, 2026
**Impact:** Over 1,600 individuals

**Data Exposed:** Personal information (details not specified in public disclosures)

**Source:** [Valley News](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)

---

### NEW: Flickr Data Breach via Third-Party Provider

**Victim:** Flickr (Yahoo-owned photo sharing service)
**Incident:** Cyber attack on third-party provider
**Notification Date:** February 2026

**Data Exposed:**
- Usernames
- IP addresses
- Location data
- Account activity metadata

**Attack Vector:** Compromise of a third-party service provider used by Flickr for infrastructure or data processing.

**Source:** [SharkStriker Data Breach Tracker](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)

---

## Malware & Ransomware

### NEW: BridgePay Ransomware Disrupts Bryan Texas Utilities

**Victim:** BridgePay (third-party payment processor)
**Incident Start:** February 6, 2026
**Downstream Impact:** Bryan Texas Utilities (BTU) - ~70,000 customers
**Services Affected:** Online payment processing
**Recovery Timeline:** 1-2 weeks estimated

**Impact:** BTU customers unable to make online payments for utility services. The attack targeted BridgePay's infrastructure, demonstrating the cascading effects of supply chain attacks on critical service providers.

**Sources:** [KBTX](https://www.kbtx.com/2026/02/11/cybersecurity-expert-explains-impact-ransomware-attack-halting-online-payments-btu-customers/)

---

### Ransomware Trend Analysis - 2025 Statistics

**Report:** BlackFog State of Ransomware Report (2025 data, published February 2026)

**Key Findings:**

| Metric | 2025 Data |
|--------|-----------|
| Year-over-year increase | **+49%** |
| Active ransomware groups increase | **+30%** vs 2024 |
| Most active groups | Qiling, Akira, Cl0p, Play, Safepay |

**Operational Shift:** Ransomware attacks increasingly **no longer involve encryption**. Instead, attackers:
- Quietly steal sensitive data over weeks or months
- Maintain silent residency
- Extort victims long after the breach using stolen data

This aligns with the Picus Red Report 2026 finding of a 38% drop in encryption-based ransomware (reported in February 12 report).

**Strategic Implication:** Detection strategies focused on encryption activity will miss the majority of modern ransomware operations. Organizations need behavioral analytics and data exfiltration detection.

**Sources:** [BlackFog](https://www.blackfog.com/the-state-of-ransomware-2026/), [SecurityWeek](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/), [Morphisec Blog](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)

---

## CISA KEV Updates

**No new additions since February 10, 2026.**

**Upcoming Deadlines:**

| CVE | Product | Deadline | Status |
|-----|---------|----------|--------|
| CVE-2026-21509 | Microsoft Office | Feb 16 | 3 days remaining |
| CVE-2019-19006 | FreePBX | Feb 24 | 11 days |
| CVE-2025-64328 | Sangoma | Feb 24 | 11 days |
| CVE-2021-39935 | GitLab CE/EE | Feb 24 | 11 days |
| CVE-2026-24423 | SmarterMail | Feb 26 | 13 days |
| CVE-2025-11953 | React Native CLI | Feb 26 | 13 days |
| CVE-2026-21510/21513/21514/21519/21525/21533 | Microsoft (6 zero-days) | **March 3** | 18 days |

**Deadlines Passed:**
- CVE-2026-20045 (Cisco Unified CM/Webex) - passed February 11
- CVE-2025-31125 (Vite Vitejs) - passed February 12
- CVE-2025-34026 (Versa Concerto) - passed February 12
- CVE-2025-68645 (Zimbra ZCS) - passed February 12

**Sources:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Recommended Actions

### Immediate Priority (Next 24 Hours)

1. **AI Security Governance** - Review AI tool usage (ChatGPT, Gemini, Claude, etc.) within your organization; nation-state actors are using commercial AI for reconnaissance and attack planning
2. **Microsoft Office zero-day** - CVE-2026-21509 deadline is **February 16** (3 days); ensure February Patch Tuesday deployed
3. **Conduent breach response** - If using Conduent services, verify breach notification received and enroll in credit monitoring before **March 31, 2026**

### High Priority (This Week)

4. **Healthcare sector** - If using MedRevenu billing services or EyeCare Partners, verify breach notification status and monitor for fraud
5. **Payment processor dependencies** - Audit third-party payment processors and supply chain vendors for ransomware risk (BridgePay incident demonstrates cascading impact)
6. **Email security** - Review email security posture; EyeCare Partners breach went undetected for 55 days

### Threat Hunting

7. **AI abuse indicators** - Monitor for unusual patterns in employee AI tool usage: mass OSINT queries, phishing template generation, vulnerability research on internal systems
8. **ChainedShark TTPs** - Organizations with research partnerships in China should hunt for LinkedShell indicators and sophisticated Chinese-language phishing lures
9. **Ransomware without encryption** - Shift detection focus from encryption events to data exfiltration, anomalous access patterns, and silent lateral movement
10. **Third-party email access** - Audit all third-party vendors with email system access; implement MFA and access logging

### Strategic

11. **AI Red Teaming** - Establish governance for employee use of commercial AI tools; consider how adversaries might use AI to profile your organization
12. **Supply chain payment security** - Evaluate single points of failure in payment processing infrastructure; establish backup processors
13. **Healthcare data protection** - Healthcare organizations should expect continued targeting; billing service providers represent high-value supply chain attack vectors
14. **Data exfiltration detection** - Per BlackFog report, 49% increase in ransomware with shift away from encryption; invest in DLP and behavioral analytics

---

## Vendor Advisories

### Microsoft
- CVE-2026-21509 (Office zero-day) - CISA deadline **February 16**
- Six zero-days from February Patch Tuesday - CISA deadline **March 3**

### CISA
- Four KEV deadlines passed (February 11-12); verify compliance
- Upcoming deadline: Microsoft Office CVE-2026-21509 (February 16)

### Google
- Gemini AI abuse disclosure; no product vulnerabilities, but awareness needed for how adversaries use AI

---

## Sources

- [The Hacker News - Google Gemini Nation-State Abuse](https://thehackernews.com/2026/02/google-reports-state-backed-hackers.html)
- [The Record - Gemini AI Nation-State Hackers](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns)
- [Infosecurity Magazine - Gemini AI](https://www.infosecurity-magazine.com/news/nation-state-hackers-gemini-ai/)
- [BleepingComputer - Google Hackers Gemini AI](https://www.bleepingcomputer.com/news/security/google-says-hackers-are-abusing-gemini-ai-for-all-attacks-stages/)
- [CyberScoop - State Hackers Gemini](https://cyberscoop.com/state-hackers-using-gemini-google-ai/)
- [AI News - State-Sponsored Hackers AI](https://www.artificialintelligence-news.com/news/state-sponsored-hackers-ai-cyberattacks-google/)
- [Security Boulevard - ChainedShark APT](https://securityboulevard.com/2026/02/top-security-incidents-of-2025-the-emergence-of-the-chainedshark-apt-group/)
- [HIPAA Journal - MedRevenu EyeCare Breaches](https://www.hipaajournal.com/data-breach-medrevenu-eyecare-partners/)
- [ClassAction.org - MedRevenu](https://www.classaction.org/data-breach-lawsuits/medrevenu-february-2026)
- [ClassAction.org - EyeCare Partners](https://www.classaction.org/data-breach-lawsuits/eyecare-partners-february-2026)
- [GlobeNewswire - MedRevenu Investigation](https://www.globenewswire.com/news-release/2026/02/06/3234039/0/en/MedRevenu-Data-Breach-Claims-Investigated-by-Lynch-Carpenter.html)
- [Becker's ASC - EyeCare Partners](https://www.beckersasc.com/ophthalmology/eyecare-partners-suffers-data-security-incident/)
- [The Register - Conduent Volvo](https://www.theregister.com/2026/02/10/conduent_volvo_breach/)
- [Texas AG Office - Conduent Investigation](https://www.texasattorneygeneral.gov/news/releases/attorney-general-ken-paxton-demands-information-blue-cross-blue-shield-texas-and-conduent-part)
- [Valley News - Cottage Hospital](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [SharkStriker - February 2026 Breaches](https://sharkstriker.com/blog/today-data-breaches-in-february-2026/)
- [KBTX - BTU Ransomware](https://www.kbtx.com/2026/02/11/cybersecurity-expert-explains-impact-ransomware-attack-halting-online-payments-btu-customers/)
- [BlackFog - State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [SecurityWeek - 8000 Ransomware Attacks](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)
- [Morphisec - Ransomware Without Encryption](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 10-12, 2026 reports:

- Microsoft February 2026 Patch Tuesday (59 CVEs, 6 zero-days, 5 critical)
- CVE-2026-21510/21513/21514/21519/21525/21533 Microsoft zero-days
- CVE-2026-21511 Outlook preview pane spoofing
- CVE-2026-24300 Azure Front Door EoP (CVSS 9.8)
- CVE-2026-0488 SAP CRM/S4HANA code injection (CVSS 9.9)
- CVE-2026-21643 FortiClientEMS SQLi (CVSS 9.1)
- UNC3886 Singapore telecoms Operation Cyber Guardian
- UNC1069 North Korea deepfake Zoom + ClickFix crypto campaign
- APT36/SideCopy three-pronged assault on Indian defense
- APT28 Operation Neusploit
- SSHStalker botnet (7,000 Linux systems, IRC C2)
- Kimwolf botnet I2P disruption
- Salt Typhoon Norway operations
- VoidLink multi-cloud Linux malware
- Picus Red Report 2026 (38% drop in encryption ransomware)
- Claude Desktop Extensions zero-click RCE (CVSS 10.0)
- DockerDash MCP injection
- Warlock ransomware vs SmarterTools
- Iron Mountain / Everest limited breach
- 0APT fake ransomware operation
- Evolve Mortgage Services 20TB breach
- Ivanti EPMM zero-days (~100 victims)
- BeyondTrust RS/PRA, Fortinet FortiCloud SSO, vLLM, n8n vulnerabilities
- Harvard/UPenn ShinyHunters, Substack, Panera Bread breaches

---

*Report generated: 2026-02-13*
*Next report: 2026-02-14*
*Classification: TLP:CLEAR*
