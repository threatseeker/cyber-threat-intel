#!/bin/bash
# Threatseeker Report - Cyber Threat Intelligence Runner
# Cross-platform script for macOS, Linux, and WSL
# Schedule via: launchd (macOS), cron (Linux/WSL), or systemd (Linux)
# Creates threat intel report and pushes to GitHub
# Includes deduplication to avoid repeating previously reported items

set -e

# Configuration
# CTI_GIT_REPO must be set in environment for auto-push to work
# Set via: launchd plist (macOS), crontab, systemd service, or shell profile
# Example: export CTI_GIT_REPO="git@github.com:YOUR_USERNAME/threat-intel-reports.git"
export CTI_OUTPUT_DIR="${CTI_OUTPUT_DIR:-/tmp/threatseeker-report}"
export CTI_AUTO_PUSH="${CTI_AUTO_PUSH:-true}"
export CTI_HISTORY_DAYS="${CTI_HISTORY_DAYS:-7}"  # Days of history to check for duplicates

# Validate required config for auto-push
if [ "$CTI_AUTO_PUSH" = "true" ] && [ -z "$CTI_GIT_REPO" ]; then
    echo "ERROR: CTI_GIT_REPO environment variable is required when CTI_AUTO_PUSH=true"
    echo "Set it in your environment or launchd plist, e.g.:"
    echo "  export CTI_GIT_REPO=\"git@github.com:YOUR_USERNAME/threat-intel-reports.git\""
    exit 1
fi

# Logging
LOG_DIR="$HOME/.claude/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/threatseeker-report-$(date +%Y-%m-%d).log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting Threatseeker Report Generation"

# Ensure output directory exists
mkdir -p "$CTI_OUTPUT_DIR/reports"

# Set date for report filename
REPORT_DATE=$(date +%Y-%m-%d)
REPORT_FILE="$CTI_OUTPUT_DIR/reports/${REPORT_DATE}-threat-intel-report.md"
TRACKING_FILE="$CTI_OUTPUT_DIR/reported-items.txt"

log "Report will be saved to: $REPORT_FILE"

# Initialize git repository if needed
cd "$CTI_OUTPUT_DIR"
if [ ! -d ".git" ] && [ "$CTI_AUTO_PUSH" = "true" ]; then
    log "Initializing git repository..."
    git init
    git remote add origin "$CTI_GIT_REPO"
fi

# Collect previously reported items from recent reports
log "Collecting previously reported items for deduplication..."
PREVIOUS_ITEMS=""

# Get list of recent report files (last N days)
for i in $(seq 1 $CTI_HISTORY_DAYS); do
    PAST_DATE=$(date -v-${i}d +%Y-%m-%d 2>/dev/null || date -d "-${i} days" +%Y-%m-%d 2>/dev/null)
    PAST_REPORT="$CTI_OUTPUT_DIR/reports/${PAST_DATE}-threat-intel-report.md"
    if [ -f "$PAST_REPORT" ]; then
        log "Found previous report: $PAST_REPORT"
        # Extract CVE IDs
        CVES=$(grep -oE 'CVE-[0-9]{4}-[0-9]+' "$PAST_REPORT" 2>/dev/null | sort -u | tr '\n' ', ' || true)
        if [ -n "$CVES" ]; then
            PREVIOUS_ITEMS="${PREVIOUS_ITEMS}Previously reported CVEs: ${CVES}\n"
        fi
    fi
done

# Also check tracking file for additional context
if [ -f "$TRACKING_FILE" ]; then
    log "Reading tracking file for additional context..."
    TRACKED=$(cat "$TRACKING_FILE" | tail -100 | tr '\n' ', ')
    PREVIOUS_ITEMS="${PREVIOUS_ITEMS}Tracked items: ${TRACKED}\n"
fi

# Create deduplication context
if [ -n "$PREVIOUS_ITEMS" ]; then
    DEDUP_CONTEXT="
=== PREVIOUSLY REPORTED ITEMS (DO NOT INCLUDE AGAIN) ===
${PREVIOUS_ITEMS}
=== END OF PREVIOUSLY REPORTED ITEMS ===

IMPORTANT DEDUPLICATION RULES:
1. Do NOT include any CVE listed above unless there is SIGNIFICANT NEW information (new exploit, patch released, new victims)
2. Do NOT repeat ransomware incidents or data breaches already reported
3. Focus ONLY on NEW discoveries, NEW vulnerabilities, NEW attacks from TODAY
4. If a vulnerability was reported yesterday, only mention it today if there's a major update
5. Mark any updated items with [UPDATE] prefix to distinguish from new items
"
else
    DEDUP_CONTEXT="This is the first report or no previous reports found. Include all relevant current threats."
fi

log "Deduplication context prepared"

# Run Claude Code to generate the report
log "Running Claude Code to generate threat intel report..."
# Use --dangerously-skip-permissions to run non-interactively without plan mode
# Use --print for non-interactive output
claude --print --dangerously-skip-permissions \
    "You are running in automated mode. Do NOT enter plan mode. Execute immediately.

Generate a comprehensive cyber threat intelligence report for TODAY: ${REPORT_DATE}

CRITICAL: Save the report to ${REPORT_FILE}

${DEDUP_CONTEXT}

FOCUS ON NEW ITEMS ONLY:
- Search specifically for news from TODAY (${REPORT_DATE}) or last 24 hours
- Use search queries with today's date to find fresh content
- Exclude anything that was major news yesterday unless there's an update

Search for and include ONLY NEW:
1. CISA KEV updates (added TODAY or yesterday)
2. NEW Critical CVEs (CVSS 9+) disclosed in last 24-48 hours
3. NEW Zero-day vulnerabilities discovered today
4. NEW Ransomware attacks reported today
5. NEW APT/nation-state activity disclosed today
6. NEW vendor security advisories released today
7. NEW data breaches disclosed today

Report Structure:
- Executive Summary (highlight what's NEW today)
- Critical Vulnerabilities (NEW only, mark updates with [UPDATE])
- Exploits & Zero-Days (NEW discoveries)
- Malware & Ransomware (NEW incidents)
- Threat Actors (NEW activity)
- Vendor Advisories (released TODAY)
- Industry News (NEW breaches/incidents)
- Recommended Actions
- Sources

If an item was in previous reports but has a significant update, include it with [UPDATE] prefix.
If there's genuinely no new activity in a category, note 'No new activity reported today.'

IMPORTANT: You MUST write the file to ${REPORT_FILE} before finishing.

After writing the report, also append any NEW CVE IDs to: ${TRACKING_FILE}" 2>&1 | tee -a "$LOG_FILE"

# Check if report was created
if [ ! -f "$REPORT_FILE" ]; then
    log "ERROR: Report file was not created"
    exit 1
fi

log "Report generated successfully"

# Extract and track new CVEs from today's report
log "Updating tracking file with new items..."
NEW_CVES=$(grep -oE 'CVE-[0-9]{4}-[0-9]+' "$REPORT_FILE" 2>/dev/null | sort -u || true)
if [ -n "$NEW_CVES" ]; then
    echo "# Reported on ${REPORT_DATE}" >> "$TRACKING_FILE"
    echo "$NEW_CVES" >> "$TRACKING_FILE"
    log "Added $(echo "$NEW_CVES" | wc -l | tr -d ' ') CVEs to tracking file"
fi

# Trim tracking file to last 500 lines to prevent it from growing too large
if [ -f "$TRACKING_FILE" ]; then
    tail -500 "$TRACKING_FILE" > "$TRACKING_FILE.tmp" && mv "$TRACKING_FILE.tmp" "$TRACKING_FILE"
fi

# Git operations
if [ "$CTI_AUTO_PUSH" = "true" ]; then
    log "Auto-push enabled, committing and pushing to GitHub..."

    cd "$CTI_OUTPUT_DIR"

    # Ensure we have latest from remote
    git fetch origin main 2>/dev/null || true

    # Add all changes
    git add .

    # Check if there are changes to commit
    if git diff --cached --quiet; then
        log "No changes to commit"
    else
        # Count new items for commit message
        NEW_CVE_COUNT=$(echo "$NEW_CVES" | grep -c 'CVE' || echo "0")

        # Create commit message
        COMMIT_MSG="Add threat intel report for ${REPORT_DATE}

- NEW items only (deduplicated from previous ${CTI_HISTORY_DAYS} days)
- ${NEW_CVE_COUNT} CVEs tracked
- Generated by scheduled automation

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"

        git commit -m "$COMMIT_MSG"

        # Pull and rebase before push
        git pull --rebase origin main 2>/dev/null || {
            log "Rebase conflict detected, resolving..."
            git checkout --theirs . 2>/dev/null || true
            git add .
            git rebase --continue 2>/dev/null || true
        }

        # Push to remote
        git push -u origin main 2>&1 | tee -a "$LOG_FILE"

        log "Report pushed to GitHub successfully"
    fi
else
    log "Auto-push disabled, skipping git operations"
fi

log "Threatseeker Report Generation Complete"
