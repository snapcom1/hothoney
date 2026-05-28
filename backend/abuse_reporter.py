#!/usr/bin/env python3
"""
Abuse Reporter Module - Sends abuse reports to network operators
"""

import asyncio
import aiohttp
import json
import logging
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
from zoneinfo import ZoneInfo
from ip_lookup import lookup_ip

# Central timezone
CENTRAL_TZ = ZoneInfo('America/Chicago')

logger = logging.getLogger(__name__)


class AbuseReporter:
    """Sends abuse reports to abuse contacts for malicious IPs"""

    # Default rate limiting: don't send more than one report per IP per this many days
    DEFAULT_COOLDOWN_DAYS = 7

    def __init__(self, db):
        self.db = db
        # Initialize with environment variables as fallback
        self.smtp_host = os.environ.get('SMTP_HOST', '')
        self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        self.smtp_user = os.environ.get('SMTP_USER', '')
        self.smtp_pass = os.environ.get('SMTP_PASS', '')
        self.smtp_from = os.environ.get('SMTP_FROM', '')
        self.report_from_name = os.environ.get('ABUSE_REPORT_FROM_NAME', 'SIP Honeypot')
        self.honeypot_name = os.environ.get('SERVER_NAME', 'SIP Honeypot')
        self.cooldown_days = self.DEFAULT_COOLDOWN_DAYS

    async def reload_settings(self):
        """Reload settings from database"""
        try:
            async with self.db.get_cursor() as cursor:
                await cursor.execute("SELECT setting_key, setting_value FROM settings")
                results = await cursor.fetchall()

            settings = {r['setting_key']: r['setting_value'] for r in results}

            # Update SMTP settings from database (fallback to env vars)
            self.smtp_host = settings.get('smtp_host') or os.environ.get('SMTP_HOST', '')
            self.smtp_port = int(settings.get('smtp_port') or os.environ.get('SMTP_PORT', '587'))
            self.smtp_user = settings.get('smtp_user') or os.environ.get('SMTP_USER', '')
            self.smtp_pass = settings.get('smtp_pass') or os.environ.get('SMTP_PASS', '')
            self.smtp_from = settings.get('smtp_from') or os.environ.get('SMTP_FROM', '')
            self.report_from_name = settings.get('abuse_report_from_name') or os.environ.get('ABUSE_REPORT_FROM_NAME', 'SIP Honeypot')
            self.report_org_name = settings.get('abuse_report_org_name') or os.environ.get('ABUSE_REPORT_ORG_NAME', self.report_from_name)
            self.report_intro = settings.get('abuse_report_intro') or os.environ.get('ABUSE_REPORT_INTRO', f'This is an automated abuse report from the {self.report_org_name} NOC.')
            self.report_subject_prefix = settings.get('abuse_report_subject_prefix') or os.environ.get('ABUSE_REPORT_SUBJECT_PREFIX', '[X-ARF] SIP/VoIP Attack Report')
            self.cooldown_days = int(settings.get('abuse_report_cooldown_days') or self.DEFAULT_COOLDOWN_DAYS)

            logger.info(f"Abuse reporter settings reloaded (SMTP: {self.smtp_host})")
        except Exception as e:
            logger.error(f"Failed to reload settings: {e}")

    def is_configured(self) -> bool:
        """Check if SMTP is configured"""
        return bool(self.smtp_host and self.smtp_user and self.smtp_pass and self.smtp_from)

    async def init_db(self):
        """Initialize the abuse_reports table"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS abuse_reports (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    abuse_email VARCHAR(255) NOT NULL,
                    network_name VARCHAR(255),
                    organization VARCHAR(255),
                    report_type VARCHAR(50) DEFAULT 'sip_attack',
                    attack_count INT DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'sent',
                    error_message TEXT,
                    email_body TEXT,
                    INDEX idx_ip (ip_address),
                    INDEX idx_email (abuse_email),
                    INDEX idx_sent (sent_at)
                )
            """)
            # Add email_body column if it doesn't exist (for existing tables)
            await cursor.execute("""
                SELECT COUNT(*) as cnt FROM information_schema.columns
                WHERE table_schema = DATABASE()
                AND table_name = 'abuse_reports'
                AND column_name = 'email_body'
            """)
            result = await cursor.fetchone()
            if result['cnt'] == 0:
                await cursor.execute("ALTER TABLE abuse_reports ADD COLUMN email_body TEXT")

            # Create blocked abuse emails table
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS abuse_email_blocklist (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    reason TEXT,
                    added_by VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_email (email)
                )
            """)

            # Add default blocked emails (IANA, RIRs, reserved addresses)
            default_blocked = [
                ('abuse@iana.org', 'IANA - reserved address registry, not a real abuse contact'),
                ('hostmaster@iana.org', 'IANA hostmaster - reserved address registry'),
                ('iana@iana.org', 'IANA - reserved address registry'),
                ('noc@iana.org', 'IANA NOC - reserved address registry'),
                ('abuse@ripe.net', 'RIPE NCC - registry, not operational abuse contact'),
                ('abuse@apnic.net', 'APNIC - registry, not operational abuse contact'),
                ('abuse@arin.net', 'ARIN - registry, not operational abuse contact'),
                ('abuse@lacnic.net', 'LACNIC - registry, not operational abuse contact'),
                ('abuse@afrinic.net', 'AFRINIC - registry, not operational abuse contact'),
                ('abuse@example.com', 'Example domain - not a real abuse contact'),
                ('abuse@example.net', 'Example domain - not a real abuse contact'),
                ('abuse@example.org', 'Example domain - not a real abuse contact'),
            ]
            for email, reason in default_blocked:
                await cursor.execute(
                    "INSERT IGNORE INTO abuse_email_blocklist (email, reason, added_by) VALUES (%s, %s, %s)",
                    (email, reason, 'system')
                )

    async def is_email_blocked(self, email: str) -> bool:
        """Check if an abuse email is on the blocklist"""
        email_lower = email.lower().strip()
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT id FROM abuse_email_blocklist WHERE LOWER(email) = %s",
                (email_lower,)
            )
            return await cursor.fetchone() is not None

    async def add_email_block(self, email: str, reason: str = None, added_by: str = None) -> bool:
        """Add an email to the blocklist"""
        async with self.db.get_cursor() as cursor:
            try:
                await cursor.execute(
                    "INSERT INTO abuse_email_blocklist (email, reason, added_by) VALUES (%s, %s, %s)",
                    (email.lower().strip(), reason, added_by)
                )
                logger.info(f"Added {email} to abuse email blocklist")
                return True
            except Exception as e:
                logger.error(f"Failed to add {email} to blocklist: {e}")
                return False

    async def remove_email_block(self, email: str) -> bool:
        """Remove an email from the blocklist"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "DELETE FROM abuse_email_blocklist WHERE LOWER(email) = %s",
                (email.lower().strip(),)
            )
            return cursor.rowcount > 0

    async def get_email_blocklist(self) -> List[Dict]:
        """Get the list of blocked abuse emails"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM abuse_email_blocklist ORDER BY created_at DESC"
            )
            return await cursor.fetchall()

    async def get_last_report(self, ip: str) -> Optional[Dict]:
        """Get the last abuse report sent for an IP"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT * FROM abuse_reports
                WHERE ip_address = %s
                ORDER BY sent_at DESC
                LIMIT 1
            """, (ip,))
            return await cursor.fetchone()

    async def can_send_report(self, ip: str) -> tuple[bool, Optional[str]]:
        """Check if we can send a report for this IP (rate limiting)"""
        last_report = await self.get_last_report(ip)
        if not last_report:
            return True, None

        cooldown_end = last_report['sent_at'] + timedelta(days=self.cooldown_days)
        if datetime.utcnow() < cooldown_end:
            days_left = (cooldown_end - datetime.utcnow()).days
            return False, f"Report sent {self.cooldown_days - days_left} days ago. Cooldown: {days_left} days remaining."

        return True, None

    async def get_attack_summary(self, ip: str) -> Dict:
        """Get attack summary for an IP from honeypot logs"""
        async with self.db.get_cursor() as cursor:
            # Get attack counts by method
            await cursor.execute("""
                SELECT method, COUNT(*) as count
                FROM honeypot_logs
                WHERE source_ip = %s
                GROUP BY method
                ORDER BY count DESC
            """, (ip,))
            methods = await cursor.fetchall()

            # Get time range
            await cursor.execute("""
                SELECT
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    COUNT(*) as total_attacks
                FROM honeypot_logs
                WHERE source_ip = %s
            """, (ip,))
            stats = await cursor.fetchone()

            # Get sample of captured credentials (usernames only, not passwords)
            await cursor.execute("""
                SELECT DISTINCT
                    JSON_UNQUOTE(JSON_EXTRACT(credentials, '$.username')) as username
                FROM honeypot_logs
                WHERE source_ip = %s
                AND credentials IS NOT NULL
                AND JSON_EXTRACT(credentials, '$.username') IS NOT NULL
                LIMIT 10
            """, (ip,))
            usernames = await cursor.fetchall()

            return {
                'methods': {m['method']: m['count'] for m in methods},
                'first_seen': stats['first_seen'],
                'last_seen': stats['last_seen'],
                'total_attacks': stats['total_attacks'],
                'attempted_usernames': [u['username'] for u in usernames if u['username']]
            }

    def _format_time_central(self, dt) -> str:
        """Convert datetime to Central timezone string"""
        if dt is None:
            return "Unknown"
        if isinstance(dt, str):
            return dt
        # Assume UTC if no timezone, convert to Central
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo('UTC'))
        central_time = dt.astimezone(CENTRAL_TZ)
        return central_time.strftime('%Y-%m-%d %H:%M:%S %Z')

    def generate_report_email(self, ip: str, abuse_contact: str, ip_info: Dict, attack_summary: Dict) -> str:
        """Generate the abuse report email body"""
        methods_str = "\n".join([f"  - {method}: {count} attempts" for method, count in attack_summary['methods'].items()])
        usernames_str = ", ".join(attack_summary['attempted_usernames'][:10]) if attack_summary['attempted_usernames'] else "None captured"

        first_seen = self._format_time_central(attack_summary['first_seen'])
        last_seen = self._format_time_central(attack_summary['last_seen'])

        report = f"""ABUSE REPORT - SIP/VoIP Attack Activity

{self.report_intro}

ATTACKING IP ADDRESS
====================
IP: {ip}
Network: {ip_info.get('network', 'Unknown')}
Organization: {ip_info.get('organization', 'Unknown')}
Country: {ip_info.get('country', 'Unknown')}

ATTACK SUMMARY
==============
Total Attacks: {attack_summary['total_attacks']}
First Seen: {first_seen}
Last Seen: {last_seen}

Attack Methods:
{methods_str}

Attempted Usernames: {usernames_str}

DESCRIPTION
===========
The IP address listed above has been observed conducting malicious SIP/VoIP
scanning and brute-force attacks against our infrastructure. This activity
includes:

- SIP REGISTER brute-force attempts (credential guessing)
- SIP INVITE scanning (toll fraud attempts)
- VoIP provisioning endpoint scanning
- Credential harvesting attempts

This type of activity is commonly associated with:
- VoIP toll fraud (unauthorized long-distance calls)
- PBX hijacking
- Vishing (voice phishing) infrastructure setup

ACTION REQUESTED
================
Please investigate this activity and take appropriate action, which may include:
- Notifying the customer/user responsible for this IP
- Suspending or terminating the offending account
- Implementing network-level blocks

ADDITIONAL INFORMATION
======================
This report was generated automatically by a SIP honeypot system. The honeypot
captures and logs malicious SIP traffic for security research purposes.

If you have questions about this report, please reply to this email.

Logs and evidence are available upon request.

---
This is an automated abuse report in X-ARF format. Replies are monitored.
Report ID: {ip}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}
"""
        return report

    def generate_xarf_json(self, ip: str, abuse_contact: str, ip_info: Dict, attack_summary: Dict) -> Dict:
        """Generate X-ARF machine-readable JSON report"""
        now = datetime.now(timezone.utc)
        first_seen = attack_summary.get('first_seen')
        last_seen = attack_summary.get('last_seen')

        # Convert timestamps to ISO format
        if first_seen and hasattr(first_seen, 'isoformat'):
            first_seen_iso = first_seen.replace(tzinfo=timezone.utc).isoformat() if first_seen.tzinfo is None else first_seen.isoformat()
        else:
            first_seen_iso = str(first_seen) if first_seen else now.isoformat()

        if last_seen and hasattr(last_seen, 'isoformat'):
            last_seen_iso = last_seen.replace(tzinfo=timezone.utc).isoformat() if last_seen.tzinfo is None else last_seen.isoformat()
        else:
            last_seen_iso = str(last_seen) if last_seen else now.isoformat()

        # Build attack details
        attack_types = []
        methods = attack_summary.get('methods', {})
        if methods.get('REGISTER'):
            attack_types.append('sip-brute-force')
        if methods.get('INVITE'):
            attack_types.append('sip-toll-fraud')
        if methods.get('OPTIONS'):
            attack_types.append('sip-scanning')
        if not attack_types:
            attack_types.append('sip-attack')

        xarf_report = {
            # X-ARF required fields
            'Version': '0.2',
            'ReporterInfo': {
                'ReporterOrg': self.report_from_name,
                'ReporterOrgDomain': self.honeypot_name,
                'ReporterOrgEmail': self.smtp_from,
                'ReporterContactEmail': self.smtp_from,
                'ReportType': 'sip-attack'
            },
            'Report': {
                'ReportClass': 'Activity',
                'ReportType': 'sip-attack',
                'ReportSubType': attack_types[0],
                'Date': now.isoformat(),
                'SourceIp': ip,
                'SourcePort': 5060,
                'SourceAsn': ip_info.get('asn'),
                'SourceAsnOrg': ip_info.get('asn_name'),
                'DestinationIp': self.honeypot_name,
                'DestinationPort': 5060,
                'Protocol': 'udp',
                'Occurrences': attack_summary.get('total_attacks', 1),
                'TLP': 'amber'
            },
            'EventData': {
                'Category': 'sip',
                'Type': 'brute-force' if 'REGISTER' in methods else 'toll-fraud',
                'FirstSeen': first_seen_iso,
                'LastSeen': last_seen_iso,
                'AttackTypes': attack_types,
                'Methods': methods,
                'AttemptedUsernames': attack_summary.get('attempted_usernames', [])[:20],
                'Description': 'SIP/VoIP brute-force attack and toll fraud attempts detected by honeypot'
            },
            'SourceInfo': {
                'Ip': ip,
                'Network': ip_info.get('network'),
                'Organization': ip_info.get('organization'),
                'Country': ip_info.get('country'),
                'CountryCode': ip_info.get('country_code'),
                'Asn': ip_info.get('asn'),
                'AsnName': ip_info.get('asn_name'),
                'AbuseContact': abuse_contact
            },
            'Schema-URL': 'https://www.x-arf.org/schema/abuse_login-attack_0.2.2.json',
            'Attachment': 'text/plain'
        }

        return xarf_report

    async def send_report(self, ip: str, manual: bool = False) -> Dict:
        """Send an abuse report for an IP address"""
        result = {
            'success': False,
            'ip': ip,
            'abuse_email': None,
            'error': None
        }

        if not self.is_configured():
            result['error'] = 'SMTP not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_FROM environment variables.'
            return result

        # Check rate limiting (skip for manual reports if forced)
        can_send, reason = await self.can_send_report(ip)
        if not can_send and not manual:
            result['error'] = reason
            return result

        # Lookup IP information
        try:
            ip_info = await lookup_ip(ip)
            if not ip_info or ip_info.get('error'):
                result['error'] = f"Could not lookup IP info: {ip_info.get('error', 'Unknown error')}"
                return result
        except Exception as e:
            result['error'] = f"IP lookup failed: {str(e)}"
            return result

        abuse_email = ip_info.get('abuse_contact')
        if not abuse_email:
            result['error'] = 'No abuse contact found for this IP'
            return result

        result['abuse_email'] = abuse_email

        # Check if email is blocked
        if await self.is_email_blocked(abuse_email):
            result['error'] = f'Email {abuse_email} is on the blocklist'
            return result

        # Get attack summary
        attack_summary = await self.get_attack_summary(ip)
        if attack_summary['total_attacks'] == 0:
            result['error'] = 'No attack logs found for this IP'
            return result

        # Generate email content
        report_body = self.generate_report_email(ip, abuse_email, ip_info, attack_summary)
        xarf_json = self.generate_xarf_json(ip, abuse_email, ip_info, attack_summary)

        # Create X-ARF compliant email message
        # X-ARF requires: multipart/mixed with text/plain and application/json parts
        msg = MIMEMultipart('mixed')
        msg['From'] = f"{self.report_from_name} <{self.smtp_from}>"
        msg['To'] = abuse_email
        msg['Subject'] = f"{self.report_subject_prefix}: {ip}"

        # X-ARF required headers
        msg['X-XARF'] = 'PLAIN'
        msg['X-ARF'] = 'PLAIN'
        msg['Auto-Submitted'] = 'auto-generated'

        # Additional context headers
        msg['X-ARF-Version'] = '0.2'
        msg['X-ARF-Report-Type'] = 'sip-attack'
        msg['X-ARF-Report-ID'] = f"{ip}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        msg['X-Reported-IP'] = ip
        msg['X-Report-Category'] = 'abuse'
        msg['X-Report-Subcategory'] = 'sip-brute-force'

        # Part 1: Human-readable text
        text_part = MIMEText(report_body, 'plain', 'utf-8')
        msg.attach(text_part)

        # Part 2: X-ARF JSON machine-readable report
        json_content = json.dumps(xarf_json, indent=2, default=str)
        json_part = MIMEApplication(json_content.encode('utf-8'), 'json')
        json_part.add_header('Content-Disposition', 'attachment', filename=f'xarf-report-{ip}.json')
        json_part.add_header('X-ARF', 'JSON')
        msg.attach(json_part)

        # Send email
        try:
            # Use asyncio to run SMTP in thread pool (smtplib is synchronous)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_smtp, msg, abuse_email)

            # Log the report with email body
            await self._log_report(ip, abuse_email, ip_info, attack_summary, 'sent', email_body=report_body)

            result['success'] = True
            result['message'] = f"Abuse report sent to {abuse_email}"
            logger.info(f"Abuse report sent for {ip} to {abuse_email}")

        except Exception as e:
            error_msg = str(e)
            result['error'] = f"Failed to send email: {error_msg}"
            await self._log_report(ip, abuse_email, ip_info, attack_summary, 'failed', error_msg, email_body=report_body)
            logger.error(f"Failed to send abuse report for {ip}: {error_msg}")

        return result

    def _send_smtp(self, msg: MIMEMultipart, to_email: str):
        """Send email via SMTP (synchronous, run in executor)"""
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_user, self.smtp_pass)
            server.sendmail(self.smtp_from, to_email, msg.as_string())

    async def _log_report(self, ip: str, abuse_email: str, ip_info: Dict,
                          attack_summary: Dict, status: str, error: str = None,
                          email_body: str = None):
        """Log the abuse report to database"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                INSERT INTO abuse_reports
                (ip_address, abuse_email, network_name, organization, attack_count,
                 first_seen, last_seen, status, error_message, email_body)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ip,
                abuse_email,
                ip_info.get('network'),
                ip_info.get('organization'),
                attack_summary['total_attacks'],
                attack_summary['first_seen'],
                attack_summary['last_seen'],
                status,
                error,
                email_body
            ))

    async def get_report_history(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get abuse report history"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT * FROM abuse_reports
                ORDER BY sent_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            return await cursor.fetchall()

    async def get_report_by_id(self, report_id: int) -> Optional[Dict]:
        """Get a single abuse report by ID"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT * FROM abuse_reports WHERE id = %s
            """, (report_id,))
            return await cursor.fetchone()

    async def get_report_stats(self) -> Dict:
        """Get abuse reporting statistics"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT
                    COUNT(*) as total_reports,
                    SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    COUNT(DISTINCT ip_address) as unique_ips,
                    COUNT(DISTINCT abuse_email) as unique_contacts
                FROM abuse_reports
            """)
            return await cursor.fetchone()
