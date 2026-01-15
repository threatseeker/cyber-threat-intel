# Threatseeker Report

Automated daily cyber threat intelligence report generation using Claude Code.

**Cross-platform:** Works on macOS, Linux, and Windows (WSL).

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

For daily automated reports, copy the runner script:
```bash
mkdir -p ~/.claude/scripts
cp threatseeker-report-runner.sh ~/.claude/scripts/
chmod +x ~/.claude/scripts/threatseeker-report-runner.sh
```

Then configure scheduling for your platform:

#### macOS (launchd)
```bash
cp com.claude.threatseeker-report.plist.template ~/Library/LaunchAgents/com.claude.threatseeker-report.plist
# Edit the plist: replace YOUR_USERNAME and YOUR_GITHUB_USERNAME
launchctl load ~/Library/LaunchAgents/com.claude.threatseeker-report.plist
```

#### Linux (cron)
```bash
crontab -e
# Add: 0 8 * * * CTI_GIT_REPO="git@github.com:USER/repo.git" ~/.claude/scripts/threatseeker-report-runner.sh >> ~/.claude/logs/cron.log 2>&1
```

#### Linux (systemd)
```bash
sudo cp threatseeker-report.service threatseeker-report.timer /etc/systemd/system/
# Edit the service file: replace YOUR_USERNAME and YOUR_GITHUB_USERNAME
sudo systemctl daemon-reload
sudo systemctl enable --now threatseeker-report.timer
```

#### Windows (WSL)
Use the Linux cron method inside WSL. Ensure cron is running:
```bash
sudo apt install cron
sudo service cron start
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

## Platform Support

| Platform | Scheduler | Template File |
|----------|-----------|---------------|
| macOS | launchd | `com.claude.threatseeker-report.plist.template` |
| Linux | cron | `threatseeker-report.cron` |
| Linux | systemd | `threatseeker-report.service` + `.timer` |
| Windows | WSL + cron | Use Linux cron method |

## Requirements

- Claude Code CLI installed and authenticated
- SSH key configured for GitHub (if using auto-push)
- Network access to threat intel sources
- bash shell (included on macOS, Linux, WSL)

## Files Included

| File | Description |
|------|-------------|
| `threatseeker-report.skill` | Main skill file for Claude Code |
| `threatseeker-report-runner.sh` | Cross-platform runner script |
| `com.claude.threatseeker-report.plist.template` | macOS launchd template |
| `threatseeker-report.cron` | Linux cron template |
| `threatseeker-report.service` | Linux systemd service |
| `threatseeker-report.timer` | Linux systemd timer |
| `README.md` | This documentation |

## License

MIT
