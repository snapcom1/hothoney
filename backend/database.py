#!/usr/bin/env python3
"""
Database models and handlers for SIP Honeypot
Uses MariaDB with async support via aiomysql
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import aiomysql
from contextlib import asynccontextmanager
import json
import hashlib
import secrets
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Database:
    """MariaDB database handler"""

    def __init__(self, host: str = 'localhost', port: int = 3306,
                 user: str = 'honeypot', password: str = 'honeypot',
                 database: str = 'sip_honeypot'):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.pool: Optional[aiomysql.Pool] = None

    async def connect(self):
        """Create connection pool"""
        self.pool = await aiomysql.create_pool(
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password,
            db=self.database,
            autocommit=True,
            minsize=2,
            maxsize=10
        )
        logger.info("Database connection pool created")

    async def close(self):
        """Close connection pool"""
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()

    @asynccontextmanager
    async def get_cursor(self):
        """Get database cursor from pool"""
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                yield cursor

    async def init_tables(self):
        """Initialize database tables"""
        async with self.get_cursor() as cursor:
            # Users table for web UI
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(255),
                    role ENUM('admin', 'viewer') DEFAULT 'viewer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    active BOOLEAN DEFAULT TRUE
                )
            """)

            # Blocked IPs table
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    reason TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    hit_count INT DEFAULT 1,
                    auto_blocked BOOLEAN DEFAULT TRUE,
                    manually_added BOOLEAN DEFAULT FALSE,
                    added_by VARCHAR(255),
                    active BOOLEAN DEFAULT TRUE,
                    notes TEXT,
                    INDEX idx_ip (ip_address),
                    INDEX idx_active (active)
                )
            """)

            # Honeypot logs table
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS honeypot_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip VARCHAR(45) NOT NULL,
                    source_port INT,
                    protocol VARCHAR(20),
                    method VARCHAR(50),
                    uri TEXT,
                    user_agent TEXT,
                    headers JSON,
                    credentials JSON,
                    raw_data TEXT,
                    honeypot_type VARCHAR(50),
                    INDEX idx_source_ip (source_ip),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_method (method),
                    INDEX idx_method_timestamp (method, timestamp DESC)
                )
            """)

            # Add composite index if table already exists (for upgrades)
            await cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_method_timestamp
                ON honeypot_logs (method, timestamp DESC)
            """)

            # Whitelisted IPs (never block)
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    cidr VARCHAR(50),
                    description TEXT,
                    added_by VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address)
                )
            """)

            # Sessions table for web UI
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    user_id INT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_token (session_token),
                    INDEX idx_expires (expires_at)
                )
            """)

            # Export history
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS export_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    exported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    export_type VARCHAR(50),
                    ip_count INT,
                    exported_by VARCHAR(255),
                    filename VARCHAR(255)
                )
            """)

            # IP geo/ASN cache table
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_geo_cache (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    country VARCHAR(100),
                    country_code VARCHAR(10),
                    region VARCHAR(100),
                    city VARCHAR(100),
                    lat DECIMAL(10, 6),
                    lon DECIMAL(10, 6),
                    isp VARCHAR(255),
                    org VARCHAR(255),
                    asn VARCHAR(20),
                    asn_name VARCHAR(255),
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address),
                    INDEX idx_country (country_code),
                    INDEX idx_asn (asn)
                )
            """)

            # Add lat/lon columns if they don't exist (migration for existing databases)
            try:
                await cursor.execute("ALTER TABLE ip_geo_cache ADD COLUMN lat DECIMAL(10, 6) AFTER city")
            except:
                pass  # Column already exists
            try:
                await cursor.execute("ALTER TABLE ip_geo_cache ADD COLUMN lon DECIMAL(10, 6) AFTER lat")
            except:
                pass  # Column already exists

            # Settings table for configuration
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key VARCHAR(100) PRIMARY KEY,
                    setting_value TEXT,
                    setting_type VARCHAR(20) DEFAULT 'string',
                    description VARCHAR(255),
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    updated_by VARCHAR(100)
                )
            """)

            logger.info("Database tables initialized")

    async def create_default_admin(self, username: str = 'admin', password: str = 'changeme'):
        """Create default admin user if none exists"""
        async with self.get_cursor() as cursor:
            await cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
            result = await cursor.fetchone()

            if result['count'] == 0:
                password_hash = self.hash_password(password)
                await cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                    (username, password_hash)
                )
                logger.info(f"Created default admin user: {username}")

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{hash_obj.hex()}"

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_hex = password_hash.split(':')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_obj.hex() == hash_hex
        except:
            return False


class BlocklistManager:
    """Manage IP blocklist"""

    def __init__(self, db: Database):
        self.db = db

    async def add_ip(self, ip: str, reason: str = None, auto: bool = True,
                     added_by: str = None, notes: str = None) -> bool:
        """Add IP to blocklist"""
        # Check whitelist first
        if await self.is_whitelisted(ip):
            logger.info(f"IP {ip} is whitelisted, not blocking")
            return False

        async with self.db.get_cursor() as cursor:
            try:
                await cursor.execute("""
                    INSERT INTO blocked_ips (ip_address, reason, auto_blocked, manually_added, added_by, notes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        hit_count = hit_count + 1,
                        last_seen = CURRENT_TIMESTAMP,
                        reason = COALESCE(VALUES(reason), reason)
                """, (ip, reason, auto, not auto, added_by, notes))
                return True
            except Exception as e:
                logger.error(f"Failed to add IP {ip}: {e}")
                return False

    async def remove_ip(self, ip: str) -> bool:
        """Remove IP from blocklist"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("UPDATE blocked_ips SET active = FALSE WHERE ip_address = %s", (ip,))
            return cursor.rowcount > 0

    async def _get_expiry_days(self) -> int:
        """Get blocklist expiry days from settings"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT setting_value FROM settings WHERE setting_key = 'blocklist_expiry_days'"
            )
            result = await cursor.fetchone()
            if result and result['setting_value']:
                return int(result['setting_value'])
            return 60  # Default

    async def get_blocked_ips(self, active_only: bool = True, limit: int = 1000,
                               offset: int = 0, source_filter: str = '', search: str = '') -> List[Dict]:
        """Get list of blocked IPs (excludes expired IPs based on settings)"""
        expiry_days = await self._get_expiry_days()
        async with self.db.get_cursor() as cursor:
            # Join with public_blocklist_ips to check if IP is also in APIBAN
            query = """
                SELECT b.*,
                       (SELECT COUNT(*) FROM public_blocklist_ips p
                        WHERE p.ip_address = b.ip_address AND p.list_id = 'apiban') > 0 AS in_apiban
                FROM blocked_ips b
            """
            conditions = []
            params = []
            if active_only:
                conditions.append(f"b.active = TRUE AND b.last_seen >= DATE_SUB(NOW(), INTERVAL {expiry_days} DAY)")
            if source_filter == 'external':
                conditions.append("b.added_by IN ('apiban')")
            elif source_filter == 'internal':
                conditions.append("(b.added_by IS NULL OR b.added_by NOT IN ('apiban'))")
            elif source_filter == 'both':
                # IPs that are internal but also exist in APIBAN
                conditions.append("""(b.added_by IS NULL OR b.added_by NOT IN ('apiban'))
                    AND EXISTS (SELECT 1 FROM public_blocklist_ips p
                                WHERE p.ip_address = b.ip_address AND p.list_id = 'apiban')""")
            if search:
                conditions.append("(b.ip_address LIKE %s OR b.reason LIKE %s)")
                search_pattern = f"%{search}%"
                params.extend([search_pattern, search_pattern])
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY b.last_seen DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            await cursor.execute(query, params)
            return await cursor.fetchall()

    async def get_blocked_ip_count(self, active_only: bool = True, source_filter: str = '', search: str = '') -> int:
        """Get count of blocked IPs (excludes expired IPs based on settings)"""
        expiry_days = await self._get_expiry_days()
        async with self.db.get_cursor() as cursor:
            query = "SELECT COUNT(*) as count FROM blocked_ips"
            conditions = []
            params = []
            if active_only:
                conditions.append(f"active = TRUE AND last_seen >= DATE_SUB(NOW(), INTERVAL {expiry_days} DAY)")
            if source_filter == 'external':
                conditions.append("added_by IN ('apiban')")
            elif source_filter == 'internal':
                conditions.append("(added_by IS NULL OR added_by NOT IN ('apiban'))")
            elif source_filter == 'both':
                # IPs that are internal but also exist in APIBAN
                conditions.append("""(added_by IS NULL OR added_by NOT IN ('apiban'))
                    AND EXISTS (SELECT 1 FROM public_blocklist_ips p
                                WHERE p.ip_address = blocked_ips.ip_address AND p.list_id = 'apiban')""")
            if search:
                conditions.append("(ip_address LIKE %s OR reason LIKE %s)")
                search_pattern = f"%{search}%"
                params.extend([search_pattern, search_pattern])
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            await cursor.execute(query, params if params else None)
            result = await cursor.fetchone()
            return result['count']

    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT id FROM blocked_ips WHERE ip_address = %s AND active = TRUE",
                (ip,)
            )
            return await cursor.fetchone() is not None

    async def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted (supports exact match and CIDR ranges)"""
        # Strip CIDR notation from input IP if present (e.g., "1.2.3.4/32" -> "1.2.3.4")
        check_ip = ip.split('/')[0]

        try:
            ip_obj = ipaddress.ip_address(check_ip)
        except ValueError:
            # Invalid IP format, can't check
            return False

        async with self.db.get_cursor() as cursor:
            # Get all whitelist entries
            await cursor.execute("SELECT ip_address FROM whitelist")
            entries = await cursor.fetchall()

            for entry in entries:
                whitelist_ip = entry['ip_address']
                try:
                    # Check if it's a CIDR range (contains /)
                    if '/' in whitelist_ip:
                        network = ipaddress.ip_network(whitelist_ip, strict=False)
                        if ip_obj in network:
                            return True
                    else:
                        # Exact match
                        if ipaddress.ip_address(whitelist_ip) == ip_obj:
                            return True
                except ValueError:
                    # Invalid entry in whitelist, skip
                    continue

            return False

    async def add_whitelist(self, ip: str, description: str = None, added_by: str = None) -> bool:
        """Add IP to whitelist"""
        async with self.db.get_cursor() as cursor:
            try:
                await cursor.execute(
                    "INSERT INTO whitelist (ip_address, description, added_by) VALUES (%s, %s, %s)",
                    (ip, description, added_by)
                )
                # Remove from blocklist if present
                await cursor.execute("UPDATE blocked_ips SET active = FALSE WHERE ip_address = %s", (ip,))
                return True
            except Exception as e:
                logger.error(f"Failed to whitelist IP {ip}: {e}")
                return False

    async def remove_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("DELETE FROM whitelist WHERE ip_address = %s", (ip,))
            return cursor.rowcount > 0

    async def get_whitelist(self) -> List[Dict]:
        """Get whitelist"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("SELECT * FROM whitelist ORDER BY created_at DESC")
            return await cursor.fetchall()


class HoneypotLogger:
    """Log honeypot events to database"""

    # SIP methods that trigger immediate block
    SIP_METHODS = ['REGISTER', 'INVITE', 'OPTIONS', 'ACK', 'BYE', 'CANCEL', 'SUBSCRIBE', 'NOTIFY', 'REFER', 'INFO']

    def __init__(self, db: Database, blocklist: BlocklistManager, abuse_reporter=None):
        self.db = db
        self.blocklist = blocklist
        self.abuse_reporter = abuse_reporter
        self.http_block_threshold = 3  # HTTP provisioning: block after 3 attempts
        # Log throttling - track log counts per IP
        self._log_counts: Dict[str, list] = {}  # ip -> list of timestamps
        self._throttle_enabled = True
        self._throttle_logs_per_minute = 10
        self._throttle_stats: Dict[str, int] = {}  # ip -> dropped count
        # Credential rate limiting - track credential attempts per IP
        self._credential_attempts: Dict[str, list] = {}  # ip -> list of timestamps
        self._credential_ratelimit_enabled = True
        self._credential_ratelimit_attempts = 5
        self._credential_ratelimit_window_seconds = 60

    async def _get_expiry_days(self) -> int:
        """Get blocklist expiry days from settings"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT setting_value FROM settings WHERE setting_key = 'blocklist_expiry_days'"
            )
            result = await cursor.fetchone()
            if result and result['setting_value']:
                return int(result['setting_value'])
            return 60  # Default

    async def reload_throttle_settings(self):
        """Reload throttle settings from database"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE 'throttle_%'"
            )
            results = await cursor.fetchall()
            for row in results:
                if row['setting_key'] == 'throttle_log_enabled':
                    self._throttle_enabled = row['setting_value'].lower() == 'true'
                elif row['setting_key'] == 'throttle_logs_per_minute':
                    self._throttle_logs_per_minute = int(row['setting_value'] or 10)

    async def reload_credential_ratelimit_settings(self):
        """Reload credential rate limit settings from database"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE 'credential_ratelimit_%'"
            )
            results = await cursor.fetchall()
            for row in results:
                if row['setting_key'] == 'credential_ratelimit_enabled':
                    self._credential_ratelimit_enabled = row['setting_value'].lower() == 'true'
                elif row['setting_key'] == 'credential_ratelimit_attempts':
                    self._credential_ratelimit_attempts = int(row['setting_value'] or 5)
                elif row['setting_key'] == 'credential_ratelimit_window_seconds':
                    self._credential_ratelimit_window_seconds = int(row['setting_value'] or 60)

    def _check_credential_ratelimit(self, ip: str) -> bool:
        """Check if IP has exceeded credential attempt rate limit. Returns True if should be blocked."""
        if not self._credential_ratelimit_enabled or self._credential_ratelimit_attempts <= 0:
            return False

        now = datetime.now()
        window_start = now - timedelta(seconds=self._credential_ratelimit_window_seconds)

        # Get or create timestamp list for this IP
        if ip not in self._credential_attempts:
            self._credential_attempts[ip] = []

        # Clean old timestamps outside the window
        self._credential_attempts[ip] = [ts for ts in self._credential_attempts[ip] if ts > window_start]

        # Add current attempt
        self._credential_attempts[ip].append(now)

        # Check if over limit
        return len(self._credential_attempts[ip]) >= self._credential_ratelimit_attempts

    def _should_throttle_log(self, ip: str) -> bool:
        """Check if we should throttle logging for this IP"""
        if not self._throttle_enabled or self._throttle_logs_per_minute <= 0:
            return False

        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)

        # Get or create timestamp list for this IP
        if ip not in self._log_counts:
            self._log_counts[ip] = []

        # Clean old timestamps
        self._log_counts[ip] = [ts for ts in self._log_counts[ip] if ts > minute_ago]

        # Check if over limit
        if len(self._log_counts[ip]) >= self._throttle_logs_per_minute:
            # Track dropped count
            self._throttle_stats[ip] = self._throttle_stats.get(ip, 0) + 1
            return True

        # Add current timestamp
        self._log_counts[ip].append(now)
        return False

    def get_throttle_stats(self) -> Dict[str, int]:
        """Get throttle statistics (dropped counts per IP)"""
        return dict(self._throttle_stats)

    def clear_throttle_stats(self):
        """Clear throttle statistics"""
        self._throttle_stats.clear()

    async def log_event(self, event: Dict[str, Any]):
        """Log honeypot event and potentially auto-block"""
        ip = event.get('source_ip')

        # Check log throttling - still auto-block but skip DB write
        if ip and self._should_throttle_log(ip):
            # Still check auto-block even if we skip logging
            await self._check_auto_block(event)
            return

        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                INSERT INTO honeypot_logs
                (source_ip, source_port, protocol, method, uri, user_agent, headers, credentials, raw_data, honeypot_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                ip,
                event.get('source_port'),
                event.get('protocol', 'SIP'),
                event.get('method'),
                event.get('uri'),
                event.get('user_agent'),
                json.dumps(event.get('headers', {})),
                json.dumps(event.get('credentials', {})),
                event.get('raw_message') or event.get('raw_data'),
                event.get('honeypot_type', 'sip')
            ))

        # Check if we should auto-block this IP
        await self._check_auto_block(event)

    async def _check_auto_block(self, event: Dict[str, Any]):
        """Auto-block IP based on protocol type"""
        ip = event.get('source_ip')
        if not ip:
            return

        # Check if already blocked
        if await self.blocklist.is_blocked(ip):
            return

        method = event.get('method', '')
        honeypot_type = event.get('honeypot_type', 'sip')
        protocol = event.get('protocol', 'SIP')
        expiry_days = await self._get_expiry_days()
        credentials = event.get('credentials', {})

        # Check credential rate limiting - block if too many credential attempts in window
        if credentials and (credentials.get('username') or credentials.get('auth_user')):
            if self._check_credential_ratelimit(ip):
                window_secs = self._credential_ratelimit_window_seconds
                attempts = self._credential_ratelimit_attempts
                reason = f"Credential brute force: {attempts} attempts in {window_secs} seconds ({expiry_days} day block)"
                await self.blocklist.add_ip(ip, reason=reason, auto=True)
                logger.warning(f"CREDENTIAL RATELIMIT BLOCK - {ip}: {attempts} credential attempts in {window_secs}s")
                # Send automatic abuse report
                await self._send_abuse_report(ip)
                return

        # SIP traffic: BLOCK IMMEDIATELY on first attempt
        if protocol == 'SIP' or honeypot_type == 'sip' or method in self.SIP_METHODS:
            reason = f"SIP attack: {method} attempt (instant block, {expiry_days} days)"
            await self.blocklist.add_ip(ip, reason=reason, auto=True)
            logger.warning(f"INSTANT BLOCK - SIP attack from {ip}: {method}")
            # Send automatic abuse report
            await self._send_abuse_report(ip)
            return

        # HTTP provisioning: block after threshold
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT COUNT(*) as count FROM honeypot_logs
                WHERE source_ip = %s AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
                AND honeypot_type = 'provisioning'
            """, (ip,))
            result = await cursor.fetchone()

            if result['count'] >= self.http_block_threshold:
                reason = f"HTTP provisioning scan: {result['count']} attempts in 1 hour ({expiry_days} day block)"
                await self.blocklist.add_ip(ip, reason=reason, auto=True)
                logger.warning(f"Auto-blocked IP {ip}: {reason}")
                # Send automatic abuse report
                await self._send_abuse_report(ip)

    async def _is_confirmed_attacker(self, ip: str) -> bool:
        """Verify an IP shows real attack intent before reporting.

        Filters out DDoS mitigation/reflection traffic which typically shows
        only a single method with no credentials. Requires at least one of:
        - Credential attempts (username/password guessing)
        - 2+ distinct SIP methods (scanning behavior)
        - Provisioning endpoint access (targeted recon)
        """
        async with self.db.get_cursor() as cursor:
            # Check for credential attempts
            await cursor.execute("""
                SELECT COUNT(*) as count FROM honeypot_logs
                WHERE source_ip = %s
                AND credentials IS NOT NULL
                AND JSON_EXTRACT(credentials, '$.username') IS NOT NULL
            """, (ip,))
            cred_result = await cursor.fetchone()
            if cred_result['count'] > 0:
                return True

            # Check for multiple distinct methods
            await cursor.execute("""
                SELECT COUNT(DISTINCT method) as methods FROM honeypot_logs
                WHERE source_ip = %s
            """, (ip,))
            method_result = await cursor.fetchone()
            if method_result['methods'] >= 2:
                return True

            # Check for provisioning/webshell honeypot access
            await cursor.execute("""
                SELECT COUNT(*) as count FROM honeypot_logs
                WHERE source_ip = %s
                AND honeypot_type IN ('provisioning', 'webshell')
            """, (ip,))
            prov_result = await cursor.fetchone()
            if prov_result['count'] > 0:
                return True

            return False

    async def _send_abuse_report(self, ip: str):
        """Send automatic abuse report for blocked IP"""
        if not self.abuse_reporter:
            return

        try:
            # Verify real attack intent before reporting (filters reflection/mitigation traffic)
            if not await self._is_confirmed_attacker(ip):
                logger.info(f"Skipping abuse report for {ip}: insufficient attack indicators (possible reflection/mitigation)")
                return

            # Reload settings to ensure we have latest SMTP config
            await self.abuse_reporter.reload_settings()

            if not self.abuse_reporter.is_configured():
                logger.debug(f"Abuse reporter not configured, skipping report for {ip}")
                return

            result = await self.abuse_reporter.send_report(ip, manual=False)
            if result['success']:
                logger.info(f"Automatic abuse report sent for {ip} to {result.get('abuse_email')}")
            else:
                logger.debug(f"Abuse report not sent for {ip}: {result.get('error')}")
        except Exception as e:
            logger.error(f"Failed to send automatic abuse report for {ip}: {e}")

    async def cleanup_expired_blocks(self):
        """Remove auto-blocked IPs older than blocklist_expiry_days setting"""
        expiry_days = await self._get_expiry_days()
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                UPDATE blocked_ips
                SET active = FALSE
                WHERE auto_blocked = TRUE
                AND last_seen < DATE_SUB(NOW(), INTERVAL %s DAY)
                AND active = TRUE
            """, (expiry_days,))
            removed = cursor.rowcount
            if removed > 0:
                logger.info(f"Expired {removed} blocks older than {expiry_days} days")

    async def cleanup_old_logs(self, max_rows: int = 1000000):
        """Delete oldest logs when exceeding max_rows"""
        if max_rows <= 0:
            return 0

        async with self.db.get_cursor() as cursor:
            # Get current count
            await cursor.execute("SELECT COUNT(*) as cnt FROM honeypot_logs")
            result = await cursor.fetchone()
            current_count = result['cnt']

            if current_count <= max_rows:
                return 0

            # Calculate how many to delete (delete 10% extra to avoid constant cleanup)
            to_delete = current_count - max_rows + int(max_rows * 0.1)

            # Delete oldest logs
            await cursor.execute("""
                DELETE FROM honeypot_logs
                ORDER BY timestamp ASC
                LIMIT %s
            """, (to_delete,))
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Log cleanup: deleted {deleted} old logs (was {current_count}, max {max_rows})")
            return deleted

    async def get_logs(self, limit: int = 100, offset: int = 0,
                       ip_filter: str = None, method_filter: str = None) -> dict:
        """Get honeypot logs with optional filters. Returns dict with logs and total_count."""
        async with self.db.get_cursor() as cursor:
            # Build WHERE clause
            where_clause = "WHERE 1=1"
            params = []
            has_filters = False

            if ip_filter:
                has_filters = True
                # Use prefix match (LIKE 'x%') for index usage, or exact match for full IPs
                if ip_filter.count('.') == 3 and all(p.isdigit() for p in ip_filter.split('.')):
                    # Looks like a complete IP - use exact match
                    where_clause += " AND source_ip = %s"
                    params.append(ip_filter)
                else:
                    # Partial IP - use prefix match (much faster than %x%)
                    where_clause += " AND source_ip LIKE %s"
                    params.append(f"{ip_filter}%")

            if method_filter:
                has_filters = True
                where_clause += " AND method = %s"
                params.append(method_filter)

            # Get total count - skip expensive count for filtered queries on first page
            # For filtered queries, we'll get count only if needed for pagination
            if has_filters and offset == 0:
                # First page with filters - skip count, we'll estimate from results
                total_count = None
            else:
                count_query = f"SELECT COUNT(*) as total FROM honeypot_logs {where_clause}"
                await cursor.execute(count_query, list(params))  # Copy params
                total_count = (await cursor.fetchone())['total']

            # Get paginated results - only select needed columns for performance
            query = f"""SELECT id, timestamp, source_ip, source_port, honeypot_type,
                              method, uri, user_agent, headers, credentials
                       FROM honeypot_logs {where_clause}
                       ORDER BY timestamp DESC LIMIT %s OFFSET %s"""
            params.extend([limit, offset])

            await cursor.execute(query, params)
            logs = await cursor.fetchall()

            # If we skipped count and got full page, there's probably more
            if total_count is None:
                if len(logs) == limit:
                    total_count = -1  # Signal "more available"
                else:
                    total_count = offset + len(logs)  # Exact count for partial page

            return {'logs': logs, 'total_count': total_count}

    async def get_stats(self) -> Dict:
        """Get honeypot statistics"""
        async with self.db.get_cursor() as cursor:
            stats = {}

            # Total logs
            await cursor.execute("SELECT COUNT(*) as count FROM honeypot_logs")
            stats['total_logs'] = (await cursor.fetchone())['count']

            # Logs in last 24h
            await cursor.execute("""
                SELECT COUNT(*) as count FROM honeypot_logs
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            stats['logs_24h'] = (await cursor.fetchone())['count']

            # Unique IPs
            await cursor.execute("SELECT COUNT(DISTINCT source_ip) as count FROM honeypot_logs")
            stats['unique_ips'] = (await cursor.fetchone())['count']

            # Blocked IPs
            await cursor.execute("SELECT COUNT(*) as count FROM blocked_ips WHERE active = TRUE")
            stats['blocked_ips'] = (await cursor.fetchone())['count']

            # Top attacking IPs
            await cursor.execute("""
                SELECT source_ip, COUNT(*) as count
                FROM honeypot_logs
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['top_attackers'] = await cursor.fetchall()

            # Method breakdown
            await cursor.execute("""
                SELECT method, COUNT(*) as count
                FROM honeypot_logs
                GROUP BY method
                ORDER BY count DESC
            """)
            stats['method_breakdown'] = await cursor.fetchall()

            # Get time wasted stat from settings
            await cursor.execute("""
                SELECT setting_value FROM settings WHERE setting_key = 'stat_time_wasted'
            """)
            result = await cursor.fetchone()
            stats['time_wasted'] = int(result['setting_value']) if result else 0

            return stats

    async def save_ip_geo(self, ip: str, geo_data: Dict):
        """Save IP geo/ASN data to cache"""
        async with self.db.get_cursor() as cursor:
            try:
                await cursor.execute("""
                    INSERT INTO ip_geo_cache
                    (ip_address, country, country_code, region, city, lat, lon, isp, org, asn, asn_name)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        country = VALUES(country),
                        country_code = VALUES(country_code),
                        region = VALUES(region),
                        city = VALUES(city),
                        lat = VALUES(lat),
                        lon = VALUES(lon),
                        isp = VALUES(isp),
                        org = VALUES(org),
                        asn = VALUES(asn),
                        asn_name = VALUES(asn_name),
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    ip,
                    geo_data.get('country'),
                    geo_data.get('country_code'),
                    geo_data.get('region'),
                    geo_data.get('city'),
                    geo_data.get('lat'),
                    geo_data.get('lon'),
                    geo_data.get('isp'),
                    geo_data.get('org'),
                    geo_data.get('asn'),
                    geo_data.get('asn_name')
                ))
            except Exception as e:
                logger.error(f"Failed to save geo data for {ip}: {e}")

    async def get_ip_geo(self, ip: str) -> Optional[Dict]:
        """Get cached IP geo data"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM ip_geo_cache WHERE ip_address = %s",
                (ip,)
            )
            return await cursor.fetchone()

    async def get_uncached_ips(self, limit: int = 50) -> List[str]:
        """Get IPs from logs that don't have geo data cached"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT DISTINCT l.source_ip
                FROM honeypot_logs l
                LEFT JOIN ip_geo_cache g ON l.source_ip = g.ip_address
                WHERE g.ip_address IS NULL OR g.lat IS NULL
                ORDER BY l.timestamp DESC
                LIMIT %s
            """, (limit,))
            rows = await cursor.fetchall()
            return [row['source_ip'] for row in rows]

    async def get_country_stats(self) -> List[Dict]:
        """Get attack statistics by country"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT
                    g.country_code,
                    g.country,
                    COUNT(DISTINCT l.source_ip) as unique_ips,
                    COUNT(*) as total_attacks
                FROM honeypot_logs l
                JOIN ip_geo_cache g ON l.source_ip = g.ip_address
                WHERE g.country_code IS NOT NULL
                GROUP BY g.country_code, g.country
                ORDER BY total_attacks DESC
                LIMIT 20
            """)
            return await cursor.fetchall()

    async def get_asn_stats(self) -> List[Dict]:
        """Get attack statistics by ASN"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT
                    g.asn,
                    g.asn_name,
                    g.isp,
                    COUNT(DISTINCT l.source_ip) as unique_ips,
                    COUNT(*) as total_attacks
                FROM honeypot_logs l
                JOIN ip_geo_cache g ON l.source_ip = g.ip_address
                WHERE g.asn IS NOT NULL
                GROUP BY g.asn, g.asn_name, g.isp
                ORDER BY total_attacks DESC
                LIMIT 20
            """)
            return await cursor.fetchall()

    async def get_uncached_ips(self, limit: int = 100) -> List[str]:
        """Get IPs that don't have geo data cached"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT DISTINCT l.source_ip
                FROM honeypot_logs l
                LEFT JOIN ip_geo_cache g ON l.source_ip = g.ip_address
                WHERE g.ip_address IS NULL
                LIMIT %s
            """, (limit,))
            results = await cursor.fetchall()
            return [r['source_ip'] for r in results]


class SettingsManager:
    """Manage application settings stored in database"""

    # Define setting keys and their metadata
    SETTINGS_SCHEMA = {
        'smtp_host': {'type': 'string', 'description': 'SMTP server hostname', 'sensitive': False},
        'smtp_port': {'type': 'integer', 'description': 'SMTP server port', 'sensitive': False, 'default': '587'},
        'smtp_user': {'type': 'string', 'description': 'SMTP username/email', 'sensitive': False},
        'smtp_pass': {'type': 'password', 'description': 'SMTP password', 'sensitive': True},
        'smtp_from': {'type': 'string', 'description': 'From email address for abuse reports', 'sensitive': False},
        'abuse_report_from_name': {'type': 'string', 'description': 'From name for abuse reports', 'sensitive': False, 'default': 'SIP Honeypot'},
        'abuse_report_cooldown_days': {'type': 'integer', 'description': 'Days between reports for same IP', 'sensitive': False, 'default': '7'},
        'auto_block_threshold': {'type': 'integer', 'description': 'Attempts before auto-blocking', 'sensitive': False, 'default': '3'},
        'blocklist_expiry_days': {'type': 'integer', 'description': 'Days before blocked IPs expire from list', 'sensitive': False, 'default': '60'},
        # Tarpit settings
        'tarpit_enabled': {'type': 'boolean', 'description': 'Enable SIP tarpit for attackers', 'sensitive': False, 'default': 'false'},
        'tarpit_delay_ms': {'type': 'integer', 'description': 'Delay in milliseconds between tarpit responses (ring interval)', 'sensitive': False, 'default': '20000'},
        'tarpit_ringing_count': {'type': 'integer', 'description': 'Number of 180 Ringing responses to send', 'sensitive': False, 'default': '30'},
        'tarpit_blocklist_only': {'type': 'boolean', 'description': 'Only tarpit IPs already on blocklist', 'sensitive': False, 'default': 'true'},
        'tarpit_rtp_farts': {'type': 'boolean', 'description': 'Send fart sounds via RTP to attackers during tarpit', 'sensitive': False, 'default': 'false'},
        'tarpit_call_min_minutes': {'type': 'integer', 'description': 'Minimum fake call duration in minutes', 'sensitive': False, 'default': '5'},
        'tarpit_call_max_minutes': {'type': 'integer', 'description': 'Maximum fake call duration in minutes', 'sensitive': False, 'default': '20'},
        # Throttling settings
        'throttle_enabled': {'type': 'boolean', 'description': 'Enable response throttling per IP', 'sensitive': False, 'default': 'true'},
        'throttle_requests_per_minute': {'type': 'integer', 'description': 'Max responses per IP per minute (0=unlimited)', 'sensitive': False, 'default': '30'},
        'throttle_log_enabled': {'type': 'boolean', 'description': 'Enable log throttling per IP', 'sensitive': False, 'default': 'true'},
        'throttle_logs_per_minute': {'type': 'integer', 'description': 'Max log entries per IP per minute (0=unlimited)', 'sensitive': False, 'default': '10'},
        # Log retention
        'log_max_rows': {'type': 'integer', 'description': 'Maximum log entries to keep (0=unlimited)', 'sensitive': False, 'default': '1000000'},
        # Credential rate limiting
        'credential_ratelimit_enabled': {'type': 'boolean', 'description': 'Enable auto-block for credential attempt rate limiting', 'sensitive': False, 'default': 'true'},
        'credential_ratelimit_attempts': {'type': 'integer', 'description': 'Number of credential attempts before auto-block', 'sensitive': False, 'default': '5'},
        'credential_ratelimit_window_seconds': {'type': 'integer', 'description': 'Time window in seconds for credential rate limiting', 'sensitive': False, 'default': '60'},
    }

    def __init__(self, db: Database):
        self.db = db

    async def get_setting(self, key: str) -> Optional[str]:
        """Get a single setting value"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT setting_value FROM settings WHERE setting_key = %s",
                (key,)
            )
            result = await cursor.fetchone()
            if result:
                return result['setting_value']
            # Return default if defined
            schema = self.SETTINGS_SCHEMA.get(key, {})
            return schema.get('default')

    async def get_settings(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Get all settings"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("SELECT setting_key, setting_value, setting_type FROM settings")
            results = await cursor.fetchall()

        settings = {}
        for row in results:
            key = row['setting_key']
            schema = self.SETTINGS_SCHEMA.get(key, {})

            # Mask sensitive values unless explicitly requested
            if schema.get('sensitive') and not include_sensitive:
                settings[key] = '********' if row['setting_value'] else ''
            else:
                settings[key] = row['setting_value']

        # Add defaults for missing settings
        for key, schema in self.SETTINGS_SCHEMA.items():
            if key not in settings:
                if schema.get('sensitive') and not include_sensitive:
                    settings[key] = ''
                else:
                    settings[key] = schema.get('default', '')

        return settings

    async def set_setting(self, key: str, value: str, updated_by: str = None) -> bool:
        """Set a single setting value"""
        if key not in self.SETTINGS_SCHEMA:
            return False

        schema = self.SETTINGS_SCHEMA[key]
        setting_type = schema.get('type', 'string')

        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                INSERT INTO settings (setting_key, setting_value, setting_type, updated_by)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    setting_value = VALUES(setting_value),
                    updated_by = VALUES(updated_by),
                    updated_at = CURRENT_TIMESTAMP
            """, (key, value, setting_type, updated_by))
            return True

    async def set_settings(self, settings: Dict[str, str], updated_by: str = None) -> Dict[str, bool]:
        """Set multiple settings at once"""
        results = {}
        for key, value in settings.items():
            # Skip empty password fields (don't overwrite with empty)
            schema = self.SETTINGS_SCHEMA.get(key, {})
            if schema.get('sensitive') and not value:
                results[key] = True  # Skip but report success
                continue
            results[key] = await self.set_setting(key, value, updated_by)
        return results

    async def delete_setting(self, key: str) -> bool:
        """Delete a setting"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "DELETE FROM settings WHERE setting_key = %s",
                (key,)
            )
            return cursor.rowcount > 0

    async def test_smtp(self) -> Dict[str, Any]:
        """Test SMTP connection with current settings"""
        import smtplib
        import asyncio

        host = await self.get_setting('smtp_host')
        port = int(await self.get_setting('smtp_port') or 587)
        user = await self.get_setting('smtp_user')
        password = await self.get_setting('smtp_pass')

        if not all([host, user, password]):
            return {'success': False, 'error': 'SMTP settings incomplete'}

        def _test_connection():
            try:
                with smtplib.SMTP(host, port, timeout=10) as server:
                    server.starttls()
                    server.login(user, password)
                return {'success': True, 'message': 'SMTP connection successful'}
            except smtplib.SMTPAuthenticationError:
                return {'success': False, 'error': 'Authentication failed - check username/password'}
            except smtplib.SMTPConnectError:
                return {'success': False, 'error': f'Could not connect to {host}:{port}'}
            except Exception as e:
                return {'success': False, 'error': str(e)}

        # Run blocking SMTP test in executor
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _test_connection)


class UserManager:
    """Manage web UI users"""

    def __init__(self, db: Database):
        self.db = db

    async def create_user(self, username: str, password: str, email: str = None,
                          role: str = 'viewer') -> Optional[int]:
        """Create new user"""
        async with self.db.get_cursor() as cursor:
            try:
                password_hash = self.db.hash_password(password)
                await cursor.execute(
                    "INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s)",
                    (username, password_hash, email, role)
                )
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Failed to create user {username}: {e}")
                return None

    async def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user and return user data"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM users WHERE username = %s AND active = TRUE",
                (username,)
            )
            user = await cursor.fetchone()

            if user and self.db.verify_password(password, user['password_hash']):
                # Update last login
                await cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                    (user['id'],)
                )
                return user
            return None

    async def create_session(self, user_id: int, ip: str = None, user_agent: str = None) -> str:
        """Create login session"""
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=24)

        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                INSERT INTO sessions (session_token, user_id, expires_at, ip_address, user_agent)
                VALUES (%s, %s, %s, %s, %s)
            """, (token, user_id, expires, ip, user_agent))

        return token

    async def validate_session(self, token: str) -> Optional[Dict]:
        """Validate session token and return user"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                SELECT u.* FROM users u
                JOIN sessions s ON u.id = s.user_id
                WHERE s.session_token = %s AND s.expires_at > NOW() AND u.active = TRUE
            """, (token,))
            return await cursor.fetchone()

    async def delete_session(self, token: str):
        """Delete session (logout)"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("DELETE FROM sessions WHERE session_token = %s", (token,))

    async def get_users(self) -> List[Dict]:
        """Get all users"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT id, username, email, role, created_at, last_login, active FROM users"
            )
            return await cursor.fetchall()

    async def update_user(self, user_id: int, **kwargs) -> bool:
        """Update user"""
        allowed_fields = ['email', 'role', 'active']
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if 'password' in kwargs:
            updates['password_hash'] = self.db.hash_password(kwargs['password'])

        if not updates:
            return False

        async with self.db.get_cursor() as cursor:
            set_clause = ', '.join(f"{k} = %s" for k in updates.keys())
            await cursor.execute(
                f"UPDATE users SET {set_clause} WHERE id = %s",
                (*updates.values(), user_id)
            )
            return cursor.rowcount > 0

    async def delete_user(self, user_id: int) -> bool:
        """Delete user"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            return cursor.rowcount > 0
