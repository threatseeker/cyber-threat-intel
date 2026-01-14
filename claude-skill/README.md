# Threatseeker Report

Automated daily cyber threat intelligence report generation using Claude Code.

## Overview

This skill generates comprehensive cyber threat intelligence reports by scanning authoritative sources for:
- Critical CVEs and CISA KEV additions
- Zero-day vulnerabilities and active exploits
- Ransomware and malware campaigns
- APT/Nation-state threat actor activity
- Vendor security advisories (Microsoft, Apple, Google, etc.)
- Major data breaches and security incidents

Reports are deduplicated to ensure each day only contains **NEW** information.

## Installation

### 1. Copy Skill File

Copy `threatseeker-report.skill` to your Claude Code skills directory:
```bash
cp threatseeker-report.skill ~/.claude/skills/
```

### 2. Set Up Automation (Optional)

For daily automated reports:

1. Copy the runner script:
   ```bash
   mkdir -p ~/.claude/scripts
   cp threatseeker-report-runner.sh ~/.claude/scripts/
   chmod +x ~/.claude/scripts/threatseeker-report-runner.sh
   ```

2. Copy and configure the launchd plist (macOS):
   ```bash
   cp com.claude.threatseeker-report.plist.template ~/Library/LaunchAgents/com.claude.threatseeker-report.plist
   ```

3. Edit the plist and replace:
   - `YOUR_USERNAME` → your macOS username
   - `YOUR_GITHUB_USERNAME` → your GitHub username

4. Load the schedule:
   ```bash
   launchctl load ~/Library/LaunchAgents/com.claude.threatseeker-report.plist
   ```

## Usage

### Manual Invocation

```
/threatseeker-report
```

Or natural language:
- "Run threat intel report"
- "Generate daily security briefing"
- "What are today's critical vulnerabilities?"

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CTI_OUTPUT_DIR` | `/tmp/threatseeker-report` | Output directory |
| `CTI_GIT_REPO` | **(required for auto-push)** | Git repository URL |
| `CTI_AUTO_PUSH` | `true` | Enable automatic git push |
| `CTI_HISTORY_DAYS` | `7` | Days to check for deduplication |

### Example Setup

```bash
export CTI_GIT_REPO="git@github.com:yourusername/threat-intel-reports.git"
export CTI_OUTPUT_DIR="/path/to/reports"
~/.claude/scripts/threatseeker-report-runner.sh
```

## Report Contents

Each report includes:

- **Executive Summary** - Key threats requiring attention
- **Critical Vulnerabilities** - CISA KEV, CVSS 9+ CVEs
- **Exploits & Zero-Days** - Active exploitation, PoCs
- **Malware & Ransomware** - Campaigns, IOCs
- **Threat Actors** - APT activity, criminal groups
- **Vendor Advisories** - Patch Tuesday, security updates
- **Industry News** - Breaches, incidents
- **Recommended Actions** - Prioritized remediation

## Deduplication

The skill tracks previously reported items to avoid repetition:
- Scans last 7 days of reports
- Extracts reported CVE IDs
- Only includes NEW discoveries
- Marks significant updates with `[UPDATE]` prefix

## Intelligence Sources

- CISA Known Exploited Vulnerabilities (KEV)
- NIST National Vulnerability Database (NVD)
- BleepingComputer, The Hacker News, SecurityWeek
- Microsoft MSRC, Google Security Blog, Apple Security
- MITRE ATT&CK, Mandiant, Unit 42

## Requirements

- Claude Code CLI installed and authenticated
- SSH key configured for GitHub (if using auto-push)
- Network access to threat intel sources

## License

MIT
