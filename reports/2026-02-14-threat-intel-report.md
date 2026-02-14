# Cyber Threat Intelligence Report
**Date:** February 14, 2026
**Classification:** TLP:CLEAR
**Report ID:** CTI-2026-0214

---

## Executive Summary

- **UPDATE**: CISA KEV added CVE-2026-1731 (BeyondTrust RS/PRA) on February 13; deadline approaching
- **UPDATE**: Japan Airlines breach disclosed - customer data from July 2024 onward compromised including names, phone numbers, emails
- **UPDATE**: Substack confirms unauthorized access on February 3 - user phone numbers, emails, and account data exposed
- **REMINDER**: Microsoft Office CVE-2026-21509 CISA deadline is **February 16** (2 days remaining)
- **REMINDER**: Six Microsoft zero-days from February 10 Patch Tuesday have March 3 CISA deadline (17 days)
- **REMINDER**: BridgePay ransomware continues to disrupt Bryan Texas Utilities payment processing (70,000 customers affected)

**No new critical zero-days or major breaches disclosed in the last 24 hours.** This report focuses on upcoming deadlines and recent developments from February 12-13.

---

## CISA KEV Updates

### February 13 Addition

**CVE-2026-1731** - BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA) OS Command Injection

- **CVSS:** 9.9 (Critical)
- **Type:** Pre-authentication remote code execution
- **Deadline:** TBD (typically 21 days from addition = ~March 6)
- **Status:** Previously covered in February 10 report; now officially added to KEV

### Upcoming Deadlines

| CVE | Product | Deadline | Days Remaining |
|-----|---------|----------|----------------|
| CVE-2026-21509 | Microsoft Office | **Feb 16** | **2 days** |
| CVE-2019-19006 | FreePBX | Feb 24 | 10 days |
| CVE-2025-64328 | Sangoma | Feb 24 | 10 days |
| CVE-2021-39935 | GitLab CE/EE | Feb 24 | 10 days |
| CVE-2026-24423 | SmarterMail | Feb 26 | 12 days |
| CVE-2025-11953 | React Native CLI | Feb 26 | 12 days |
| CVE-2026-21510/21513/21514/21519/21525/21533 | Microsoft (6 zero-days) | **March 3** | 17 days |
| CVE-2026-1731 | BeyondTrust RS/PRA | ~March 6 (estimate) | ~20 days |

**Deadlines Passed:**
- CVE-2026-20045 (Cisco Unified CM/Webex) - passed February 11
- CVE-2025-31125 (Vite Vitejs) - passed February 12
- CVE-2025-34026 (Versa Concerto) - passed February 12
- CVE-2025-68645 (Zimbra ZCS) - passed February 12

**Sources:** [CISA Adds One KEV - Feb 13](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog), [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Data Breaches

### NEW: Japan Airlines Breach - Customer Data Since July 2024

**Victim:** Japan Airlines (JAL)
**Discovery Date:** February 9, 2026
**Disclosure Date:** February 2026
**Impact:** Customers who used JAL services from July 2024 onward

**Data Exposed:**
- Names
- Phone numbers
- Email addresses
- Travel-related details (flight information, bookings)

**Timeline:**
- July 2024: Breach began (unauthorized access established)
- February 9, 2026: JAL discovered unauthorized access
- February 2026: Public disclosure

**Significance:** Seven months of customer data exposure before detection. The breach affects international travelers and demonstrates the extended dwell time of attackers in airline reservation systems.

**Sources:** [Data Breach Roundup Feb 2026](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)

---

### NEW: Substack Data Breach - User Account Information

**Victim:** Substack (newsletter publishing platform)
**Discovery Date:** February 3, 2026
**Disclosure Date:** February 2026
**Impact:** Undisclosed number of Substack users

**Data Exposed:**
- Email addresses
- Phone numbers
- User account data (likely includes usernames, subscription information)

**Attack Vector:** Unauthorized access to Substack's systems; specific entry point not disclosed.

**Significance:** Substack hosts thousands of independent writers and millions of subscribers. Compromised email addresses and phone numbers enable targeted phishing campaigns against newsletter subscribers, particularly those subscribed to high-value content (political analysis, financial newsletters, investigative journalism).

**Sources:** [Data Breach Roundup Feb 2026](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)

---

### UPDATE: Cottage Hospital Breach - Additional Details

**Previous Coverage:** February 13 report (1,600 affected)

**What's New:**
- Notification letters began mailing **February 6, 2026**
- Incident occurred **October 2025** (4-month delay in notifications)
- Affected residents primarily in "Twin States" region (likely Vermont/New Hampshire)

**Sources:** [Valley News - Cottage Hospital](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)

---

### UPDATE: Conduent Breach - Attorney General Investigation

**Previous Coverage:** February 10, 12, 13 reports (25M+ victims)

**What's New:**
- **Texas Attorney General Ken Paxton** issued Civil Investigative Demands (CIDs) to both Conduent and Blue Cross Blue Shield of Texas
- Investigating the breach as potentially "the largest data breach in U.S. history"
- Texas alone: **4 million victims** (later reports indicate 15.4M+ in Texas)
- Total victims across all states: **25 million+**
- Breach window: October 21, 2024 - January 13, 2025
- **10+ federal class action lawsuits** filed as of February 10
- Credit monitoring enrollment deadline: **March 31, 2026**

**Sources:** [Texas AG Paxton](https://www.texasattorneygeneral.gov/news/releases/attorney-general-ken-paxton-demands-information-blue-cross-blue-shield-texas-and-conduent-part), [Conduent Class Action Update](https://allaboutlawyer.com/conduent-data-breach-class-action-2026-10-feb-update-25m-victims-10-lawsuits-filed-free-credit-monitoring-deadline-march-31/)

---

## Threat Actor Activity

### No New APT Campaigns Disclosed (Last 24 Hours)

Recent reports (covered in previous days):
- Google Gemini AI abuse by APT31 (China), APT42 (Iran), UNC2970 (North Korea), Russian actors - **February 12 disclosure**
- ChainedShark APT targeting Chinese research institutions - **February 13 disclosure**
- UNC1069 deepfake Zoom + ClickFix targeting crypto/DeFi - **February 12 disclosure**
- UNC3886 Singapore telecoms - **February 10 disclosure**

**Sources:** [Nation-State Hackers Gemini AI](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/nation-state-hackers-gemini-ai/), [Singapore APT Operation](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)

---

## Malware & Ransomware

### UPDATE: BridgePay Ransomware - Bryan Texas Utilities Impact Continues

**Previous Coverage:** February 13 report (initial disclosure February 6)

**Status Update:**
- Online payment processing for **Bryan Texas Utilities** remains disrupted
- Estimated recovery timeline: **1-2 weeks** from February 6 attack
- Impact: ~**70,000 customers** unable to make online utility payments
- Attack targeted **BridgePay** (third-party payment processor), not BTU directly

**Lessons Learned:** Supply chain attacks on payment processors create cascading service disruptions for multiple downstream customers. Organizations should establish backup payment processing capabilities.

**Sources:** [KBTX - BTU Ransomware](https://www.kbtx.com/2026/02/11/cybersecurity-expert-explains-impact-ransomware-attack-halting-online-payments-btu-customers/)

---

### Ransomware Trend: Pure Exfiltration Attacks Surging

**Report:** BlackFog State of Ransomware 2026 (2025 data)

**Key Statistics:**
- **49% year-over-year increase** in ransomware attacks (2025 vs 2024)
- **38% drop in encryption-based ransomware** (per Picus Red Report)
- Attackers shifting to "silent residency" - maintaining invisible access for weeks/months before extortion

**Why This Matters:**
Traditional detection strategies focused on encryption activity will miss modern ransomware operations. Attackers are now:
1. Quietly stealing data over extended periods
2. Maintaining persistent access without disruption
3. Extorting victims using stolen data without ever deploying encryption

**Recommended Detection Strategy:** Shift focus to data exfiltration monitoring, anomalous access patterns, and behavioral analytics rather than relying on encryption event detection.

**Sources:** [BlackFog Ransomware Report 2026](https://www.blackfog.com/the-state-of-ransomware-2026/), [Morphisec - Ransomware Without Encryption](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/), [SecurityWeek - 8000 Ransomware Attacks](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)

---

## Recommended Actions

### Immediate Priority (Next 48 Hours)

1. **Microsoft Office CVE-2026-21509** - CISA deadline is **Sunday, February 16** (2 days); ensure February out-of-band patch deployed across all Office/M365 instances
2. **BeyondTrust RS/PRA** - CVE-2026-1731 now in CISA KEV; apply patches immediately if using Remote Support or Privileged Remote Access products
3. **Conduent breach response** - If using Conduent services, verify enrollment in credit monitoring before **March 31** deadline

### High Priority (This Week)

4. **FreePBX/Sangoma/GitLab** - Three CISA KEV deadlines on **February 24** (10 days); verify patches applied
5. **Japan Airlines customers** - If you flew JAL from July 2024 onward, monitor for phishing attempts using your travel details
6. **Substack users** - Watch for targeted phishing emails; attackers have email addresses and phone numbers of newsletter subscribers

### Threat Hunting

7. **Data exfiltration detection** - Per BlackFog/Picus reports, ransomware is shifting away from encryption; implement DLP monitoring and egress traffic analysis
8. **AI tool abuse** - Monitor for unusual patterns in commercial AI usage (Gemini, ChatGPT, Claude) that could indicate reconnaissance or attack planning
9. **Payment processor dependencies** - Audit third-party payment providers for ransomware preparedness (BridgePay incident demonstrates risk)

### Strategic

10. **Detection strategy modernization** - Encryption-based ransomware detection is increasingly ineffective; invest in behavioral analytics and silent exfiltration detection
11. **Supply chain risk assessment** - Both BridgePay and Conduent breaches demonstrate cascading impacts of third-party compromises
12. **Breach notification timelines** - Japan Airlines (7 months), Cottage Hospital (4 months) show extended dwell times; improve detection capabilities

---

## Vendor Advisories

### Microsoft
- CVE-2026-21509 Office zero-day - CISA deadline **February 16** (2 days)
- Six zero-days from February 10 Patch Tuesday - CISA deadline **March 3** (17 days)

### BeyondTrust
- CVE-2026-1731 RS/PRA pre-auth RCE - Added to CISA KEV February 13; patch immediately

### CISA
- CVE-2026-21509 deadline: **February 16** (Sunday)
- Four deadlines passed February 11-12 (Cisco, Vite, Versa, Zimbra)

---

## Sources

- [CISA Adds One KEV - February 13, 2026](https://www.cisa.gov/news-events/alerts/2026/02/13/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA Adds Six KEV - February 10, 2026](https://www.cisa.gov/news-events/alerts/2026/02/10/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Texas AG Ken Paxton - Conduent Investigation](https://www.texasattorneygeneral.gov/news/releases/attorney-general-ken-paxton-demands-information-blue-cross-blue-shield-texas-and-conduent-part)
- [Conduent Class Action 2026 Update](https://allaboutlawyer.com/conduent-data-breach-class-action-2026-10-feb-update-25m-victims-10-lawsuits-filed-free-credit-monitoring-deadline-march-31/)
- [Data Breach Roundup Jan 30 - Feb 5, 2026](https://www.privacyguides.org/news/2026/02/06/data-breach-roundup-jan-30-feb-5-2026/)
- [Valley News - Cottage Hospital Breach](https://vnews.com/2026/02/12/cottage-hospital-security-breach/)
- [KBTX - BTU Ransomware Impact](https://www.kbtx.com/2026/02/11/cybersecurity-expert-explains-impact-ransomware-attack-halting-online-payments-btu-customers/)
- [BlackFog - State of Ransomware 2026](https://www.blackfog.com/the-state-of-ransomware-2026/)
- [Morphisec - Ransomware Without Encryption](https://www.morphisec.com/blog/ransomware-without-encryption-why-pure-exfiltration-attacks-are-surging-and-why-theyre-so-hard-to-catch/)
- [SecurityWeek - 8000 Ransomware Attacks](https://www.securityweek.com/in-other-news-8000-ransomware-attacks-china-hacked-us-gov-emails-idhs-breach-impacts-700k/)
- [The Record - Nation-State Hackers Using Gemini](https://therecord.media/nation-state-hackers-using-gemini-for-malicious-campaigns)
- [Infosecurity Magazine - Nation-State Hackers Gemini AI](https://www.infosecurity-magazine.com/news/nation-state-hackers-gemini-ai/)
- [CSA Singapore - Operation Cyber Guardian](https://www.csa.gov.sg/news-events/press-releases/largest-multi-agency-cyber-operation-mounted-to-counter-threat-posed-by-advanced-persistent-threat--apt--actor-unc3886-to-singapore-s-telecommunications-sector/)

---

## Appendix: Items from Previous Reports (Not Repeated)

The following were covered in February 10-13, 2026 reports and remain relevant context:

### Vulnerabilities
- Microsoft February 2026 Patch Tuesday (59 CVEs, 6 zero-days, 5 critical)
- CVE-2026-21510/21513/21514/21519/21525/21533 Microsoft zero-days
- CVE-2026-21511 Outlook preview pane spoofing
- CVE-2026-24300 Azure Front Door EoP (CVSS 9.8)
- CVE-2026-0488 SAP CRM/S4HANA code injection (CVSS 9.9)
- CVE-2026-21643 FortiClientEMS SQLi (CVSS 9.1)
- Claude Desktop Extensions zero-click RCE (CVSS 10.0)
- DockerDash MCP injection

### Threat Actors
- Google Gemini AI abuse by APT31, APT42, UNC2970, Russian actors
- ChainedShark APT (Actor240820) targeting Chinese research institutions
- UNC3886 Singapore telecoms Operation Cyber Guardian
- UNC1069 North Korea deepfake Zoom + ClickFix crypto campaign
- APT36/SideCopy three-pronged RAT assault on Indian defense
- Salt Typhoon Norway operations

### Malware & Ransomware
- SSHStalker botnet (7,000 Linux systems, IRC C2)
- Kimwolf botnet I2P disruption
- VoidLink multi-cloud Linux malware
- Picus Red Report 2026 (38% drop in encryption ransomware)
- Warlock ransomware vs SmarterTools
- Iron Mountain / Everest limited breach
- 0APT fake ransomware operation

### Breaches
- MedRevenu healthcare billing breach
- EyeCare Partners 55+ day email access breach
- Conduent 25M+ (covered above with update)
- Evolve Mortgage Services 20TB breach
- Flickr third-party provider breach
- Harvard/UPenn ShinyHunters breaches

---

*Report generated: 2026-02-14*
*Next report: 2026-02-15*
*Classification: TLP:CLEAR*
