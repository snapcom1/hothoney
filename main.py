#!/usr/bin/env python3
"""
SIP Honeypot - Main Application Entry Point
Runs all honeypot services concurrently
"""

import asyncio
import logging
import os
import signal
import sys

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'honeypot'))

from database import Database, BlocklistManager, HoneypotLogger, UserManager, SettingsManager
from abuse_reporter import AbuseReporter
from public_blocklists import PublicBlocklistManager
from api import HoneypotAPI
from sip_server import run_sip_honeypot
from provisioning_server import run_provisioning_honeypot
from tftp_server import run_tftp_honeypot
from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SIPHoneypotApp:
    """Main application coordinator"""

    def __init__(self):
        self.db = None
        self.blocklist = None
        self.honeypot_logger = None
        self.tasks = []
        # Holder for SIP protocol reference (for API access to active sessions)
        self.sip_protocol_holder = {}

        # Configuration from environment
        self.config = {
            'db_host': os.getenv('DB_HOST', 'localhost'),
            'db_port': int(os.getenv('DB_PORT', 3306)),
            'db_user': os.getenv('DB_USER', 'honeypot'),
            'db_password': os.getenv('DB_PASSWORD', 'honeypot'),
            'db_name': os.getenv('DB_NAME', 'sip_honeypot'),

            'sip_host': os.getenv('SIP_HOST', '0.0.0.0'),
            'sip_port': int(os.getenv('SIP_PORT', 5060)),

            'http_host': os.getenv('HTTP_HOST', '0.0.0.0'),
            'http_port': int(os.getenv('HTTP_PORT', 8080)),

            'api_host': os.getenv('API_HOST', '0.0.0.0'),
            'api_port': int(os.getenv('API_PORT', 8081)),

            'tftp_host': os.getenv('TFTP_HOST', '0.0.0.0'),
            'tftp_port': int(os.getenv('TFTP_PORT', 69)),

            'admin_user': os.getenv('ADMIN_USER', 'admin'),
            'admin_pass': os.getenv('ADMIN_PASS', 'changeme'),

            'auto_block_threshold': int(os.getenv('AUTO_BLOCK_THRESHOLD', 3)),
        }

    async def init_database(self):
        """Initialize database connection and tables"""
        logger.info("Initializing database connection...")

        self.db = Database(
            host=self.config['db_host'],
            port=self.config['db_port'],
            user=self.config['db_user'],
            password=self.config['db_password'],
            database=self.config['db_name']
        )

        # Retry connection with backoff
        for attempt in range(10):
            try:
                await self.db.connect()
                break
            except Exception as e:
                logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        else:
            raise Exception("Failed to connect to database after 10 attempts")

        await self.db.init_tables()
        await self.db.create_default_admin(
            self.config['admin_user'],
            self.config['admin_pass']
        )

        self.blocklist = BlocklistManager(self.db)
        self.settings_manager = SettingsManager(self.db)
        self.abuse_reporter = AbuseReporter(self.db)
        await self.abuse_reporter.init_db()
        await self.abuse_reporter.reload_settings()
        self.public_blocklist = PublicBlocklistManager(self.db, self.blocklist)
        await self.public_blocklist.init_db()
        self.honeypot_logger = HoneypotLogger(self.db, self.blocklist, self.abuse_reporter)
        self.honeypot_logger.auto_block_threshold = self.config['auto_block_threshold']

        logger.info("Database initialized successfully")

    async def get_tarpit_config(self) -> dict:
        """Load tarpit configuration from settings"""
        settings = await self.settings_manager.get_settings()
        return {
            'enabled': settings.get('tarpit_enabled', 'false').lower() == 'true',
            'delay_ms': int(settings.get('tarpit_delay_ms', '20000')),
            'ringing_count': int(settings.get('tarpit_ringing_count', '30')),
            'blocklist_only': settings.get('tarpit_blocklist_only', 'true').lower() == 'true',
            'rtp_farts': settings.get('tarpit_rtp_farts', 'false').lower() == 'true',
            'call_min_minutes': int(settings.get('tarpit_call_min_minutes', '5')),
            'call_max_minutes': int(settings.get('tarpit_call_max_minutes', '20'))
        }

    async def get_throttle_config(self) -> dict:
        """Load throttle configuration from settings"""
        settings = await self.settings_manager.get_settings()
        return {
            'enabled': settings.get('throttle_enabled', 'true').lower() == 'true',
            'requests_per_minute': int(settings.get('throttle_requests_per_minute', '30'))
        }

    async def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is on blocklist (for tarpit decisions)"""
        return await self.blocklist.is_blocked(ip)

    async def log_event(self, event: dict):
        """Callback for honeypot events"""
        await self.honeypot_logger.log_event(event)

    async def run_api_server(self):
        """Run the REST API server"""
        api = HoneypotAPI(self.db, sip_protocol_holder=self.sip_protocol_holder)
        runner = web.AppRunner(api.app)
        await runner.setup()
        site = web.TCPSite(
            runner,
            self.config['api_host'],
            self.config['api_port']
        )
        await site.start()
        logger.info(f"API server started on http://{self.config['api_host']}:{self.config['api_port']}")

        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await runner.cleanup()

    async def update_stats(self, stat_name: str, value: int):
        """Update a stat in the database (increment)"""
        try:
            current = await self.settings_manager.get_setting(f'stat_{stat_name}')
            current_val = int(current) if current else 0
            new_val = current_val + value
            await self.settings_manager.set_setting(f'stat_{stat_name}', str(new_val), 'system')
        except Exception as e:
            logger.error(f"Failed to update stat {stat_name}: {e}")

    async def run_sip_server(self):
        """Run the SIP honeypot server"""
        tarpit_config = await self.get_tarpit_config()
        throttle_config = await self.get_throttle_config()
        # Also load log throttle settings and credential rate limit settings
        await self.honeypot_logger.reload_throttle_settings()
        await self.honeypot_logger.reload_credential_ratelimit_settings()
        await run_sip_honeypot(
            host=self.config['sip_host'],
            port=self.config['sip_port'],
            log_callback=self.log_event,
            tarpit_config=tarpit_config,
            is_blocked_callback=self.is_ip_blocked,
            throttle_config=throttle_config,
            protocol_holder=self.sip_protocol_holder,
            stats_callback=self.update_stats,
            get_tarpit_config_callback=self.get_tarpit_config
        )

    async def run_http_server(self):
        """Run the HTTP provisioning honeypot"""
        await run_provisioning_honeypot(
            host=self.config['http_host'],
            port=self.config['http_port'],
            log_callback=self.log_event
        )

    async def run_tftp_server(self):
        """Run the TFTP honeypot server"""
        await run_tftp_honeypot(
            host=self.config['tftp_host'],
            port=self.config['tftp_port'],
            log_callback=self.log_event
        )

    async def run_cleanup_task(self):
        """Periodically clean up expired blocks and old logs"""
        cleanup_counter = 0
        while True:
            try:
                await asyncio.sleep(3600)  # Run hourly
                cleanup_counter += 1

                # Log cleanup every hour
                settings = await self.settings_manager.get_settings()
                max_rows = int(settings.get('log_max_rows', '1000000'))
                deleted = await self.honeypot_logger.cleanup_old_logs(max_rows)
                if deleted > 0:
                    logger.info(f"Log cleanup: removed {deleted} old entries")

                # Block expiry cleanup daily (every 24 hours)
                if cleanup_counter >= 24:
                    cleanup_counter = 0
                    await self.honeypot_logger.cleanup_expired_blocks()
                    logger.info("Completed daily cleanup of expired blocks")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

    async def run(self):
        """Run all services"""
        logger.info("Starting SIP Honeypot...")
        logger.info(f"Configuration: SIP={self.config['sip_port']}, HTTP={self.config['http_port']}, TFTP={self.config['tftp_port']}, API={self.config['api_port']}")

        await self.init_database()

        # Create tasks for all services
        self.tasks = [
            asyncio.create_task(self.run_api_server()),
            asyncio.create_task(self.run_sip_server()),
            asyncio.create_task(self.run_http_server()),
            asyncio.create_task(self.run_tftp_server()),
            asyncio.create_task(self.run_cleanup_task()),
        ]

        logger.info("All services started")

        # Wait for all tasks
        try:
            await asyncio.gather(*self.tasks)
        except asyncio.CancelledError:
            logger.info("Shutting down...")

    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Initiating graceful shutdown...")

        for task in self.tasks:
            task.cancel()

        await asyncio.gather(*self.tasks, return_exceptions=True)

        if self.db:
            await self.db.close()

        logger.info("Shutdown complete")


def main():
    app = SIPHoneypotApp()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Handle signals
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(app.shutdown()))

    try:
        loop.run_until_complete(app.run())
    except KeyboardInterrupt:
        loop.run_until_complete(app.shutdown())
    finally:
        loop.close()


if __name__ == '__main__':
    main()
