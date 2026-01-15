#!/usr/bin/env python3
"""
Cyber Threat Intelligence Email Sender

Sends CTI reports via email using Python smtplib.
Supports Gmail with App Passwords and macOS Keychain integration.

Usage:
    python3 cti-email-sender.py /path/to/report.md [options]

Options:
    --to, -t        Recipients (comma-separated), overrides CTI_EMAIL_TO
    --from, -f      Sender address, overrides CTI_EMAIL_FROM
    --dry-run       Print details without sending
    --verbose, -v   Enable verbose logging

Environment Variables:
    CTI_EMAIL_TO            Comma-separated recipient list
    CTI_EMAIL_FROM          Sender Gmail address
    CTI_SMTP_HOST           SMTP server (default: smtp.gmail.com)
    CTI_SMTP_PORT           SMTP port (default: 587)
    CTI_EMAIL_APP_PASSWORD  Gmail App Password
    CTI_EMAIL_USE_KEYCHAIN  Use macOS Keychain for password (true/false)
"""

import smtplib
import ssl
import os
import sys
import argparse
import logging
import subprocess
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging with timestamp and level."""
    log_dir = Path.home() / ".claude" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / f"cti-email-{datetime.now().strftime('%Y-%m-%d')}.log"

    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file)
        ]
    )


def get_password_from_keychain(service: str, account: str) -> str:
    """
    Retrieve password from macOS Keychain.

    Args:
        service: Keychain service name (e.g., "cyber-threat-intel-smtp")
        account: Account name (e.g., Gmail address)

    Returns:
        Password string

    Raises:
        ValueError: If password not found in Keychain
    """
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", service, "-a", account, "-w"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        raise ValueError(f"Password not found in Keychain for service='{service}', account='{account}'")
    except FileNotFoundError:
        raise ValueError("macOS 'security' command not found - Keychain only works on macOS")


def get_smtp_password(sender: str) -> str:
    """
    Get SMTP password from environment or Keychain.

    Priority:
        1. CTI_EMAIL_APP_PASSWORD environment variable
        2. macOS Keychain (if CTI_EMAIL_USE_KEYCHAIN=true)

    Args:
        sender: Sender email address (used as Keychain account)

    Returns:
        Password string

    Raises:
        ValueError: If no password configured
    """
    logger = logging.getLogger("cti-email")

    # Try environment variable first
    password = os.environ.get("CTI_EMAIL_APP_PASSWORD")
    if password:
        logger.debug("Using password from CTI_EMAIL_APP_PASSWORD environment variable")
        return password

    # Try Keychain if enabled
    use_keychain = os.environ.get("CTI_EMAIL_USE_KEYCHAIN", "false").lower() == "true"
    if use_keychain:
        logger.debug("Attempting to retrieve password from macOS Keychain")
        return get_password_from_keychain("cyber-threat-intel-smtp", sender)

    raise ValueError(
        "No SMTP password configured. Either:\n"
        "  1. Set CTI_EMAIL_APP_PASSWORD environment variable, or\n"
        "  2. Set CTI_EMAIL_USE_KEYCHAIN=true and store password in Keychain:\n"
        f"     security add-generic-password -s 'cyber-threat-intel-smtp' -a '{sender}' -w 'YOUR_APP_PASSWORD'"
    )


def markdown_to_html(markdown_content: str) -> str:
    """
    Convert markdown to HTML using regex patterns.

    Handles: headers, bold, italic, links, code blocks, tables, lists, horizontal rules.
    This is a lightweight implementation avoiding external dependencies.

    Args:
        markdown_content: Raw markdown string

    Returns:
        HTML string with styling
    """
    html = markdown_content

    # Preserve code blocks first (to avoid processing their contents)
    code_blocks = []
    def save_code_block(match):
        code_blocks.append(match.group(0))
        return f"__CODE_BLOCK_{len(code_blocks) - 1}__"

    html = re.sub(r'```(\w*)\n(.*?)```', save_code_block, html, flags=re.DOTALL)

    # Escape HTML entities
    html = html.replace("&", "&amp;")
    html = html.replace("<", "&lt;")
    html = html.replace(">", "&gt;")

    # Headers (h1-h6)
    html = re.sub(r'^######\s+(.+)$', r'<h6>\1</h6>', html, flags=re.MULTILINE)
    html = re.sub(r'^#####\s+(.+)$', r'<h5>\1</h5>', html, flags=re.MULTILINE)
    html = re.sub(r'^####\s+(.+)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
    html = re.sub(r'^###\s+(.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^##\s+(.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^#\s+(.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)

    # Bold and italic
    html = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', html)
    html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    html = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html)

    # Links
    html = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', html)

    # Inline code
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)

    # Horizontal rules
    html = re.sub(r'^---+$', r'<hr>', html, flags=re.MULTILINE)

    # Tables (basic support)
    def convert_table(match):
        lines = match.group(0).strip().split('\n')
        if len(lines) < 2:
            return match.group(0)

        table_html = '<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">\n'

        # Header row
        header_cells = [c.strip() for c in lines[0].split('|') if c.strip()]
        table_html += '<thead><tr style="background-color: #f4f4f4;">'
        for cell in header_cells:
            table_html += f'<th style="text-align: left;">{cell}</th>'
        table_html += '</tr></thead>\n<tbody>\n'

        # Data rows (skip separator line)
        for line in lines[2:]:
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if cells:
                table_html += '<tr>'
                for cell in cells:
                    table_html += f'<td>{cell}</td>'
                table_html += '</tr>\n'

        table_html += '</tbody></table>\n'
        return table_html

    # Match tables (lines starting with |)
    html = re.sub(r'(\|[^\n]+\|\n)+', convert_table, html)

    # Unordered lists
    html = re.sub(r'^- \[ \]\s+(.+)$', r'<li style="list-style-type: square;">\1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'^- \[x\]\s+(.+)$', r'<li style="list-style-type: none;">&#9745; \1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'^-\s+(.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'^(\d+)\.\s+(.+)$', r'<li>\2</li>', html, flags=re.MULTILINE)

    # Restore code blocks
    for i, block in enumerate(code_blocks):
        lang_match = re.match(r'```(\w*)\n(.*?)```', block, re.DOTALL)
        if lang_match:
            lang = lang_match.group(1)
            code = lang_match.group(2)
            # Escape HTML in code
            code = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            replacement = f'<pre style="background: #f4f4f4; padding: 1em; border-radius: 5px; overflow-x: auto;"><code class="{lang}">{code}</code></pre>'
        else:
            replacement = block
        html = html.replace(f"__CODE_BLOCK_{i}__", replacement)

    # Wrap in HTML document with styling
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
        }}
        h1, h2, h3, h4, h5, h6 {{
            color: #1a1a1a;
            border-bottom: 1px solid #eee;
            padding-bottom: 0.3em;
            margin-top: 1.5em;
        }}
        h1 {{ font-size: 2em; color: #c0392b; }}
        h2 {{ font-size: 1.5em; }}
        h3 {{ font-size: 1.25em; }}
        code {{
            background: #f4f4f4;
            padding: 0.2em 0.4em;
            border-radius: 3px;
            font-size: 0.9em;
            font-family: 'SF Mono', Menlo, Monaco, monospace;
        }}
        pre {{
            background: #f4f4f4;
            padding: 1em;
            border-radius: 5px;
            overflow-x: auto;
        }}
        pre code {{
            background: none;
            padding: 0;
        }}
        a {{
            color: #0066cc;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        hr {{
            border: none;
            border-top: 2px solid #eee;
            margin: 2em 0;
        }}
        li {{
            margin: 0.3em 0;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f4f4f4;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #fafafa;
        }}
        .critical {{
            color: #c0392b;
            font-weight: bold;
        }}
        .warning {{
            color: #e67e22;
        }}
        .header-banner {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .header-banner h1 {{
            color: white;
            border: none;
            margin: 0;
        }}
        .footer {{
            margin-top: 2em;
            padding-top: 1em;
            border-top: 1px solid #eee;
            font-size: 0.9em;
            color: #666;
        }}
    </style>
</head>
<body>
{html}
<div class="footer">
    <p>This report was generated automatically by the Cyber Threat Intelligence Agent.</p>
    <p>For questions or to unsubscribe, contact your security administrator.</p>
</div>
</body>
</html>"""


def send_email(
    report_path: str,
    recipients: list,
    sender: str,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 587,
    password: str = None
) -> bool:
    """
    Send the threat intel report via email.

    Creates multipart email with:
    - Plain text version (original markdown)
    - HTML version (converted from markdown)

    Args:
        report_path: Path to the markdown report file
        recipients: List of email addresses
        sender: From address (Gmail)
        smtp_host: SMTP server hostname
        smtp_port: SMTP server port
        password: SMTP password (Gmail App Password)

    Returns:
        True if sent successfully, False otherwise
    """
    logger = logging.getLogger("cti-email")

    # Read report file
    report_file = Path(report_path)
    if not report_file.exists():
        logger.error(f"Report file not found: {report_path}")
        return False

    logger.info(f"Reading report: {report_path}")
    markdown_content = report_file.read_text(encoding="utf-8")

    # Extract date from filename for subject
    # Expected format: YYYY-MM-DD-threat-intel-report.md
    report_name = report_file.stem
    date_match = re.match(r'(\d{4}-\d{2}-\d{2})', report_name)
    report_date = date_match.group(1) if date_match else datetime.now().strftime("%Y-%m-%d")

    # Create multipart message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CTI] Cyber Threat Intelligence Report - {report_date}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["X-Priority"] = "1"  # High priority
    msg["X-MSMail-Priority"] = "High"

    # Plain text part (original markdown)
    text_part = MIMEText(markdown_content, "plain", "utf-8")
    msg.attach(text_part)

    # HTML part (converted from markdown)
    logger.info("Converting markdown to HTML...")
    html_content = markdown_to_html(markdown_content)
    html_part = MIMEText(html_content, "html", "utf-8")
    msg.attach(html_part)

    # Send email
    logger.info(f"Connecting to {smtp_host}:{smtp_port}...")
    try:
        context = ssl.create_default_context()

        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.ehlo()
            logger.debug("Starting TLS...")
            server.starttls(context=context)
            server.ehlo()
            logger.debug("Authenticating...")
            server.login(sender, password)
            logger.info(f"Sending email to {len(recipients)} recipient(s)...")
            server.sendmail(sender, recipients, msg.as_string())

        logger.info(f"Email sent successfully to: {', '.join(recipients)}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {e}")
        logger.error("Ensure you're using a Gmail App Password, not your account password.")
        logger.error("Generate one at: Google Account > Security > 2-Step Verification > App passwords")
        return False
    except smtplib.SMTPConnectError as e:
        logger.error(f"Failed to connect to SMTP server: {e}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email: {e}")
        return False


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Send Cyber Threat Intel report via email",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "report_path",
        help="Path to the markdown report file"
    )
    parser.add_argument(
        "--to", "-t",
        help="Recipient email addresses (comma-separated). "
             "Overrides CTI_EMAIL_TO environment variable."
    )
    parser.add_argument(
        "--from", "-f", dest="sender",
        help="Sender email address. Overrides CTI_EMAIL_FROM."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print email details without sending"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    logger = logging.getLogger("cti-email")

    logger.info("=== CTI Email Sender ===")

    # Get configuration
    recipients_str = args.to or os.environ.get("CTI_EMAIL_TO", "")
    recipients = [r.strip() for r in recipients_str.split(",") if r.strip()]

    sender = args.sender or os.environ.get("CTI_EMAIL_FROM", "")
    smtp_host = os.environ.get("CTI_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("CTI_SMTP_PORT", "587"))

    # Validate configuration
    if not recipients:
        logger.error("No recipients specified.")
        logger.error("Set CTI_EMAIL_TO environment variable or use --to option")
        sys.exit(1)

    if not sender:
        logger.error("No sender specified.")
        logger.error("Set CTI_EMAIL_FROM environment variable or use --from option")
        sys.exit(1)

    # Check report file exists
    if not Path(args.report_path).exists():
        logger.error(f"Report file not found: {args.report_path}")
        sys.exit(1)

    # Dry run mode
    if args.dry_run:
        logger.info("DRY RUN MODE - No email will be sent")
        logger.info("-" * 40)
        logger.info(f"From:    {sender}")
        logger.info(f"To:      {', '.join(recipients)}")
        logger.info(f"Report:  {args.report_path}")
        logger.info(f"SMTP:    {smtp_host}:{smtp_port}")
        logger.info(f"Subject: [CTI] Cyber Threat Intelligence Report - {datetime.now().strftime('%Y-%m-%d')}")
        logger.info("-" * 40)

        # Test markdown conversion
        logger.info("Testing markdown to HTML conversion...")
        content = Path(args.report_path).read_text()
        html = markdown_to_html(content)
        logger.info(f"HTML output size: {len(html)} bytes")
        logger.info("Dry run complete. Use without --dry-run to send.")
        sys.exit(0)

    # Get password
    try:
        password = get_smtp_password(sender)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    # Send email
    success = send_email(
        report_path=args.report_path,
        recipients=recipients,
        sender=sender,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        password=password
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
