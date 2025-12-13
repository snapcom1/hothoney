#!/usr/bin/env python3
"""
Public Blocklist Integration - Import IPs from external blocklists like APIBAN
"""

import asyncio
import aiohttp
import logging
from datetime import datetime
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class PublicBlocklistManager:
    """Manages importing IPs from public blocklists"""

    # Supported public blocklists
    BLOCKLISTS = {
        'apiban': {
            'name': 'APIBAN',
            'description': 'Community-driven SIP/VoIP threat intelligence',
            'url': 'https://apiban.org',
            'api_base': 'https://apiban.org/api',
            'requires_key': True,
        },
    }

    def __init__(self, db, blocklist_manager):
        self.db = db
        self.blocklist = blocklist_manager

    async def init_db(self):
        """Initialize the public_blocklist_config table"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS public_blocklist_config (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    list_id VARCHAR(50) NOT NULL UNIQUE,
                    enabled BOOLEAN DEFAULT FALSE,
                    api_key VARCHAR(255),
                    last_sync TIMESTAMP NULL,
                    last_id VARCHAR(255),
                    ips_imported INT DEFAULT 0,
                    last_error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_list (list_id)
                )
            """)

            # Create tracking table for imported IPs
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS public_blocklist_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    list_id VARCHAR(50) NOT NULL,
                    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    UNIQUE KEY idx_ip_list (ip_address, list_id),
                    INDEX idx_list (list_id),
                    INDEX idx_expires (expires_at)
                )
            """)

    async def get_config(self, list_id: str) -> Optional[Dict]:
        """Get configuration for a blocklist"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM public_blocklist_config WHERE list_id = %s",
                (list_id,)
            )
            return await cursor.fetchone()

    async def get_all_configs(self) -> List[Dict]:
        """Get all blocklist configurations"""
        configs = []
        for list_id, info in self.BLOCKLISTS.items():
            config = await self.get_config(list_id)
            configs.append({
                'list_id': list_id,
                'name': info['name'],
                'description': info['description'],
                'url': info['url'],
                'requires_key': info['requires_key'],
                'enabled': config['enabled'] if config else False,
                'has_key': bool(config['api_key']) if config else False,
                'last_sync': config['last_sync'].isoformat() if config and config['last_sync'] else None,
                'ips_imported': config['ips_imported'] if config else 0,
                'last_error': config['last_error'] if config else None,
            })
        return configs

    async def save_config(self, list_id: str, enabled: bool, api_key: str = None):
        """Save blocklist configuration"""
        if list_id not in self.BLOCKLISTS:
            raise ValueError(f"Unknown blocklist: {list_id}")

        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                INSERT INTO public_blocklist_config (list_id, enabled, api_key)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    enabled = VALUES(enabled),
                    api_key = COALESCE(NULLIF(VALUES(api_key), ''), api_key),
                    updated_at = CURRENT_TIMESTAMP
            """, (list_id, enabled, api_key))

    async def sync_apiban(self) -> Dict:
        """Sync with APIBAN API"""
        config = await self.get_config('apiban')
        if not config or not config['enabled']:
            return {'success': False, 'error': 'APIBAN not enabled'}

        api_key = config['api_key']
        if not api_key:
            return {'success': False, 'error': 'APIBAN API key not configured'}

        current_id = config['last_id'] or ''
        imported = 0
        new_last_id = current_id

        try:
            async with aiohttp.ClientSession() as session:
                # APIBAN API v2: POST /api/get with Bearer auth
                url = "https://apiban.org/api/get"
                headers = {
                    'User-Agent': 'SIP-Honeypot/1.0',
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/json'
                }

                # Keep fetching until no more IPs (API returns 250 per batch)
                while True:
                    payload = {
                        'set': 'sip',
                        'id': current_id
                    }

                    async with session.post(url, headers=headers, json=payload, timeout=30) as resp:
                        if resp.status == 200:
                            data = await resp.json()

                            if 'ipaddress' in data:
                                ips = data['ipaddress']
                                if isinstance(ips, list):
                                    for ip in ips:
                                        await self._import_ip(ip, 'apiban')
                                        imported += 1

                            if 'ID' in data:
                                new_last_id = data['ID']
                                current_id = data['ID']  # Use this ID for next batch
                            else:
                                break  # No more batches

                            # If we got less than 250, we're done
                            if not isinstance(ips, list) or len(ips) < 250:
                                break

                        elif resp.status == 404:
                            # No new IPs
                            break
                        elif resp.status == 401:
                            raise Exception("Invalid API key")
                        elif resp.status == 400:
                            # Try to get error details from response
                            try:
                                err_data = await resp.json()
                                err_msg = err_data.get('ID', 'Bad request')
                                raise Exception(f"APIBAN error: {err_msg}")
                            except:
                                raise Exception("Invalid request - check API key format")
                        elif resp.status == 429:
                            raise Exception("Rate limited - try again later")
                        elif resp.status == 503:
                            raise Exception("APIBAN service temporarily unavailable - try again later")
                        elif resp.status >= 500:
                            raise Exception(f"APIBAN server error ({resp.status}) - try again later")
                        else:
                            raise Exception(f"API returned status {resp.status}")

            # Update config
            async with self.db.get_cursor() as cursor:
                await cursor.execute("""
                    UPDATE public_blocklist_config
                    SET last_sync = NOW(), last_id = %s,
                        ips_imported = ips_imported + %s, last_error = NULL
                    WHERE list_id = 'apiban'
                """, (new_last_id, imported))

            logger.info(f"APIBAN sync complete: {imported} new IPs imported")
            return {'success': True, 'imported': imported}

        except Exception as e:
            error_msg = str(e)
            async with self.db.get_cursor() as cursor:
                await cursor.execute("""
                    UPDATE public_blocklist_config
                    SET last_error = %s, updated_at = NOW()
                    WHERE list_id = 'apiban'
                """, (error_msg,))

            logger.error(f"APIBAN sync failed: {error_msg}")
            return {'success': False, 'error': error_msg}

    async def _import_ip(self, ip: str, list_id: str):
        """Import an IP from a public blocklist"""
        # Add to our blocklist
        reason = f"Public blocklist: {self.BLOCKLISTS[list_id]['name']}"
        await self.blocklist.add_ip(ip, reason=reason, auto=True, added_by=list_id)

        # Track in public_blocklist_ips
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                INSERT IGNORE INTO public_blocklist_ips (ip_address, list_id)
                VALUES (%s, %s)
            """, (ip, list_id))

    async def get_imported_count(self, list_id: str) -> int:
        """Get count of IPs imported from a specific list"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT COUNT(*) as count FROM public_blocklist_ips WHERE list_id = %s",
                (list_id,)
            )
            result = await cursor.fetchone()
            return result['count']

    async def cleanup_apiban(self) -> Dict:
        """Remove IPs that are no longer in APIBAN's list"""
        config = await self.get_config('apiban')
        if not config or not config['enabled']:
            return {'success': False, 'error': 'APIBAN not enabled'}

        api_key = config['api_key']
        if not api_key:
            return {'success': False, 'error': 'APIBAN API key not configured'}

        removed = 0
        checked = 0
        errors = 0

        try:
            # Get all IPs we imported from APIBAN
            async with self.db.get_cursor() as cursor:
                await cursor.execute("""
                    SELECT ip_address FROM public_blocklist_ips
                    WHERE list_id = 'apiban'
                """)
                apiban_ips = [row['ip_address'] for row in await cursor.fetchall()]

            if not apiban_ips:
                return {'success': True, 'removed': 0, 'checked': 0}

            async with aiohttp.ClientSession() as session:
                headers = {
                    'User-Agent': 'SIP-Honeypot/1.0',
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/json'
                }

                # Check each IP (with rate limiting - max 5 per second)
                for ip in apiban_ips:
                    try:
                        url = "https://apiban.org/api/check"
                        payload = {'set': 'sip', 'ipaddress': ip}

                        async with session.post(url, headers=headers, json=payload, timeout=10) as resp:
                            checked += 1

                            if resp.status == 404:
                                # IP is no longer banned - remove it
                                await self._remove_apiban_ip(ip)
                                removed += 1
                                logger.info(f"Removed delisted APIBAN IP: {ip}")
                            elif resp.status == 429:
                                # Rate limited - stop and try again later
                                logger.warning("APIBAN rate limit hit during cleanup")
                                break

                        # Rate limit ourselves: ~5 requests per second
                        await asyncio.sleep(0.2)

                    except Exception as e:
                        errors += 1
                        logger.debug(f"Error checking IP {ip}: {e}")

            logger.info(f"APIBAN cleanup complete: {removed} removed, {checked} checked, {errors} errors")
            return {'success': True, 'removed': removed, 'checked': checked, 'errors': errors}

        except Exception as e:
            logger.error(f"APIBAN cleanup failed: {e}")
            return {'success': False, 'error': str(e)}

    async def _remove_apiban_ip(self, ip: str):
        """Remove an IP that was imported from APIBAN"""
        async with self.db.get_cursor() as cursor:
            # Remove from tracking table
            await cursor.execute("""
                DELETE FROM public_blocklist_ips
                WHERE ip_address = %s AND list_id = 'apiban'
            """, (ip,))

            # Remove from blocklist (only if added by apiban)
            await cursor.execute("""
                DELETE FROM blocked_ips
                WHERE ip_address = %s AND added_by = 'apiban'
            """, (ip,))

    async def sync_all(self) -> Dict:
        """Sync all enabled blocklists"""
        results = {}

        # APIBAN
        config = await self.get_config('apiban')
        if config and config['enabled']:
            results['apiban'] = await self.sync_apiban()

        return results
