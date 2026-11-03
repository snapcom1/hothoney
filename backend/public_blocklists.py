#!/usr/bin/env python3
"""
Public Blocklist Integration - Import IPs from external blocklists
Supports APIBAN, CrowdSec, OpenDBL, and custom URL-based lists
"""

import asyncio
import aiohttp
import ipaddress
import logging
import re
from datetime import datetime
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


class PublicBlocklistManager:
    """Manages importing IPs from public blocklists"""

    # Built-in blocklists
    BLOCKLISTS = {
        'apiban': {
            'name': 'APIBAN',
            'description': 'Community-driven SIP/VoIP threat intelligence',
            'url': 'https://apiban.org',
            'api_base': 'https://apiban.org/api',
            'requires_key': True,
            'type': 'api',
        },
        'crowdsec': {
            'name': 'CrowdSec',
            'description': 'Community-driven threat intelligence (SIP blocklist)',
            'url': 'https://app.crowdsec.net',
            'list_url': 'https://cti.api.crowdsec.net/v2/fire',
            'requires_key': True,
            'type': 'api',
        },
        'opendbl': {
            'name': 'OpenDBL',
            'description': 'Open DNS blocklist - broad coverage IP list',
            'url': 'https://opendbl.net',
            'list_url': 'https://opendbl.net/lists/broad-coverage.list',
            'requires_key': False,
            'type': 'url_list',
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

            # Create custom URL lists table
            await cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_blocklist_urls (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    list_id VARCHAR(50) NOT NULL UNIQUE,
                    name VARCHAR(100) NOT NULL,
                    url VARCHAR(500) NOT NULL,
                    description TEXT,
                    enabled BOOLEAN DEFAULT TRUE,
                    auth_header VARCHAR(500),
                    last_sync TIMESTAMP NULL,
                    ips_imported INT DEFAULT 0,
                    last_error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_list (list_id)
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
        """Get all blocklist configurations (built-in + custom)"""
        configs = []
        for list_id, info in self.BLOCKLISTS.items():
            config = await self.get_config(list_id)
            configs.append({
                'list_id': list_id,
                'name': info['name'],
                'description': info['description'],
                'url': info['url'],
                'requires_key': info['requires_key'],
                'type': info.get('type', 'api'),
                'builtin': True,
                'enabled': config['enabled'] if config else False,
                'has_key': bool(config['api_key']) if config else False,
                'last_sync': config['last_sync'].isoformat() if config and config['last_sync'] else None,
                'ips_imported': config['ips_imported'] if config else 0,
                'last_error': config['last_error'] if config else None,
            })

        # Add custom URL lists
        custom = await self.get_custom_lists()
        for c in custom:
            configs.append({
                'list_id': c['list_id'],
                'name': c['name'],
                'description': c['description'] or f"Custom list: {c['url']}",
                'url': c['url'],
                'requires_key': bool(c.get('auth_header')),
                'type': 'custom_url',
                'builtin': False,
                'enabled': c['enabled'],
                'has_key': bool(c.get('auth_header')),
                'last_sync': c['last_sync'].isoformat() if c.get('last_sync') else None,
                'ips_imported': c['ips_imported'] or 0,
                'last_error': c.get('last_error'),
            })

        return configs

    async def save_config(self, list_id: str, enabled: bool, api_key: str = None):
        """Save blocklist configuration"""
        if list_id not in self.BLOCKLISTS:
            # Check if it's a custom list
            custom = await self._get_custom_list(list_id)
            if custom:
                await self._update_custom_list(list_id, enabled=enabled, auth_header=api_key)
                return
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

    # ==================== Custom URL Lists ====================

    async def get_custom_lists(self) -> List[Dict]:
        """Get all custom URL blocklists"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("SELECT * FROM custom_blocklist_urls ORDER BY name")
            return await cursor.fetchall()

    async def _get_custom_list(self, list_id: str) -> Optional[Dict]:
        """Get a single custom list by list_id"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM custom_blocklist_urls WHERE list_id = %s",
                (list_id,)
            )
            return await cursor.fetchone()

    async def add_custom_list(self, name: str, url: str, description: str = '', auth_header: str = '') -> Dict:
        """Add a new custom URL blocklist"""
        list_id = 'custom_' + re.sub(r'[^a-z0-9]', '_', name.lower().strip())[:30]

        # Check for duplicate
        existing = await self._get_custom_list(list_id)
        if existing:
            raise ValueError(f"A list with ID '{list_id}' already exists")

        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                INSERT INTO custom_blocklist_urls (list_id, name, url, description, auth_header, enabled)
                VALUES (%s, %s, %s, %s, %s, TRUE)
            """, (list_id, name.strip(), url.strip(), description.strip(), auth_header.strip() if auth_header else None))

        return {'list_id': list_id, 'name': name, 'url': url}

    async def _update_custom_list(self, list_id: str, enabled: bool = None, auth_header: str = None):
        """Update a custom list"""
        updates = []
        params = []
        if enabled is not None:
            updates.append("enabled = %s")
            params.append(enabled)
        if auth_header is not None:
            updates.append("auth_header = %s")
            params.append(auth_header if auth_header else None)
        if not updates:
            return
        params.append(list_id)
        async with self.db.get_cursor() as cursor:
            await cursor.execute(
                f"UPDATE custom_blocklist_urls SET {', '.join(updates)} WHERE list_id = %s",
                params
            )

    async def remove_custom_list(self, list_id: str) -> Dict:
        """Remove a custom URL blocklist and its imported IPs"""
        custom = await self._get_custom_list(list_id)
        if not custom:
            return {'success': False, 'error': 'List not found'}

        async with self.db.get_cursor() as cursor:
            # Remove imported IPs
            await cursor.execute(
                "DELETE FROM public_blocklist_ips WHERE list_id = %s", (list_id,))
            removed_tracking = cursor.rowcount

            await cursor.execute(
                "DELETE FROM blocked_ips WHERE added_by = %s", (list_id,))
            removed_blocked = cursor.rowcount

            # Remove the list config
            await cursor.execute(
                "DELETE FROM custom_blocklist_urls WHERE list_id = %s", (list_id,))

        logger.info(f"Removed custom list {list_id}: {removed_tracking} tracking, {removed_blocked} blocked IPs")
        return {'success': True, 'removed_ips': removed_tracking}

    # ==================== Generic URL List Sync ====================

    def _parse_ip_list(self, text: str) -> List[str]:
        """Parse a text IP list (one IP/CIDR per line, skip comments and blanks)"""
        ips = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//') or line.startswith(';'):
                continue
            # Take first whitespace-delimited token (some lists have comments after IP)
            token = line.split()[0]
            # Strip trailing CIDR /32 to normalize
            if token.endswith('/32'):
                token = token[:-3]
            try:
                # Validate it's a real IP or CIDR
                if '/' in token:
                    ipaddress.ip_network(token, strict=False)
                else:
                    ipaddress.ip_address(token)
                ips.append(token)
            except ValueError:
                continue
        return ips

    async def sync_url_list(self, list_id: str, url: str, auth_header: str = None, name: str = None) -> Dict:
        """Sync a URL-based IP list (plain text, one IP per line)"""
        imported = 0
        try:
            headers = {'User-Agent': 'SIP-Honeypot/1.0'}
            if auth_header:
                # Support "Bearer xxx" or "Token xxx" or just a raw key
                if ':' in auth_header:
                    key, val = auth_header.split(':', 1)
                    headers[key.strip()] = val.strip()
                else:
                    headers['Authorization'] = auth_header

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=60) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status} from {url}")
                    text = await resp.text()

            ips = self._parse_ip_list(text)
            if not ips:
                raise Exception("No valid IPs found in list")

            for ip in ips:
                await self._import_ip(ip, list_id)
                imported += 1

            # Update config
            display_name = name or list_id
            if list_id in self.BLOCKLISTS:
                async with self.db.get_cursor() as cursor:
                    await cursor.execute("""
                        INSERT INTO public_blocklist_config (list_id, enabled, last_sync, ips_imported, last_error)
                        VALUES (%s, TRUE, NOW(), %s, NULL)
                        ON DUPLICATE KEY UPDATE
                            last_sync = NOW(), ips_imported = ips_imported + VALUES(ips_imported), last_error = NULL
                    """, (list_id, imported))
            else:
                async with self.db.get_cursor() as cursor:
                    await cursor.execute("""
                        UPDATE custom_blocklist_urls
                        SET last_sync = NOW(), ips_imported = ips_imported + %s, last_error = NULL
                        WHERE list_id = %s
                    """, (imported, list_id))

            logger.info(f"{display_name} sync complete: {imported} IPs imported from {url}")
            return {'success': True, 'imported': imported, 'total_in_list': len(ips)}

        except Exception as e:
            error_msg = str(e)
            # Update error
            if list_id in self.BLOCKLISTS:
                async with self.db.get_cursor() as cursor:
                    await cursor.execute("""
                        INSERT INTO public_blocklist_config (list_id, last_error)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE last_error = VALUES(last_error), updated_at = NOW()
                    """, (list_id, error_msg))
            else:
                async with self.db.get_cursor() as cursor:
                    await cursor.execute(
                        "UPDATE custom_blocklist_urls SET last_error = %s WHERE list_id = %s",
                        (error_msg, list_id))

            logger.error(f"{list_id} sync failed: {error_msg}")
            return {'success': False, 'error': error_msg}

    # ==================== CrowdSec ====================

    async def sync_crowdsec(self) -> Dict:
        """Sync with CrowdSec CTI smoke dataset (SIP-related)"""
        config = await self.get_config('crowdsec')
        if not config or not config['enabled']:
            return {'success': False, 'error': 'CrowdSec not enabled'}

        api_key = config['api_key']
        if not api_key:
            return {'success': False, 'error': 'CrowdSec API key not configured'}

        imported = 0
        try:
            headers = {
                'User-Agent': 'SIP-Honeypot/1.0',
                'x-api-key': api_key,
                'Accept': 'application/json'
            }

            async with aiohttp.ClientSession() as session:
                # CrowdSec CTI Fire API - get SIP-related IPs
                url = "https://cti.api.crowdsec.net/v2/fire"
                params = {'page': 1, 'limit': 1000}

                async with session.get(url, headers=headers, params=params, timeout=60) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get('items', [])
                        for item in items:
                            ip = item.get('ip')
                            if not ip:
                                continue
                            # Check if this IP has SIP/VoIP related classifications
                            behaviors = [b.get('name', '') for b in item.get('behaviors', [])]
                            classifications = item.get('classifications', {})
                            class_list = [c.get('name', '') for c in classifications.get('classifications', [])]

                            is_sip = any('sip' in b.lower() or 'voip' in b.lower() for b in behaviors + class_list)
                            is_scan = any('scan' in b.lower() or 'brute' in b.lower() for b in behaviors)

                            if is_sip or is_scan:
                                await self._import_ip(ip, 'crowdsec')
                                imported += 1
                    elif resp.status == 401 or resp.status == 403:
                        raise Exception("Invalid or unauthorized API key")
                    elif resp.status == 429:
                        raise Exception("Rate limited - try again later")
                    else:
                        raise Exception(f"API returned status {resp.status}")

            async with self.db.get_cursor() as cursor:
                await cursor.execute("""
                    UPDATE public_blocklist_config
                    SET last_sync = NOW(), ips_imported = ips_imported + %s, last_error = NULL
                    WHERE list_id = 'crowdsec'
                """, (imported,))

            logger.info(f"CrowdSec sync complete: {imported} SIP/scan IPs imported")
            return {'success': True, 'imported': imported}

        except Exception as e:
            error_msg = str(e)
            async with self.db.get_cursor() as cursor:
                await cursor.execute("""
                    UPDATE public_blocklist_config
                    SET last_error = %s, updated_at = NOW()
                    WHERE list_id = 'crowdsec'
                """, (error_msg,))
            logger.error(f"CrowdSec sync failed: {error_msg}")
            return {'success': False, 'error': error_msg}

    # ==================== OpenDBL ====================

    async def sync_opendbl(self) -> Dict:
        """Sync with OpenDBL broad coverage list"""
        config = await self.get_config('opendbl')
        if not config or not config['enabled']:
            return {'success': False, 'error': 'OpenDBL not enabled'}

        return await self.sync_url_list(
            'opendbl',
            self.BLOCKLISTS['opendbl']['list_url'],
            name='OpenDBL'
        )

    # ==================== APIBAN ====================

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
                url = "https://apiban.org/api/get"
                headers = {
                    'User-Agent': 'SIP-Honeypot/1.0',
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/json'
                }

                batch_count = 0
                while True:
                    payload = {'set': 'sip', 'id': current_id}

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
                                current_id = data['ID']
                            else:
                                break

                            if not isinstance(ips, list) or len(ips) < 250:
                                break

                            batch_count += 1
                            if batch_count >= 10:
                                logger.info(f"APIBAN: Imported {imported} IPs, waiting for rate limit reset...")
                                await asyncio.sleep(120)
                                batch_count = 0
                            else:
                                await asyncio.sleep(1)

                        elif resp.status == 404:
                            break
                        elif resp.status == 401:
                            raise Exception("Invalid API key")
                        elif resp.status == 400:
                            try:
                                err_data = await resp.json()
                                err_msg = err_data.get('ID', 'Bad request')
                                if 'rate' in err_msg.lower() or 'limit' in err_msg.lower():
                                    raise Exception("Rate limited - try again later")
                                raise Exception(f"APIBAN error: {err_msg}")
                            except Exception as e:
                                if 'Rate limited' in str(e):
                                    raise
                                raise Exception("Rate limited or invalid request - try again later")
                        elif resp.status == 429:
                            raise Exception("Rate limited - try again later")
                        elif resp.status == 503:
                            raise Exception("APIBAN service temporarily unavailable - try again later")
                        elif resp.status >= 500:
                            raise Exception(f"APIBAN server error ({resp.status}) - try again later")
                        else:
                            raise Exception(f"API returned status {resp.status}")

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

    # ==================== Shared helpers ====================

    async def _import_ip(self, ip: str, list_id: str):
        """Import an IP from a public blocklist"""
        name = self.BLOCKLISTS.get(list_id, {}).get('name', list_id)
        reason = f"Public blocklist: {name}"
        await self.blocklist.add_ip(ip, reason=reason, auto=True, added_by=list_id)

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

                for ip in apiban_ips:
                    try:
                        url = "https://apiban.org/api/check"
                        payload = {'set': 'sip', 'ipaddress': ip}

                        async with session.post(url, headers=headers, json=payload, timeout=10) as resp:
                            checked += 1
                            if resp.status == 404:
                                await self._remove_list_ip(ip, 'apiban')
                                removed += 1
                                logger.info(f"Removed delisted APIBAN IP: {ip}")
                            elif resp.status == 429:
                                logger.warning("APIBAN rate limit hit during cleanup")
                                break

                        await asyncio.sleep(0.2)

                    except Exception as e:
                        errors += 1
                        logger.debug(f"Error checking IP {ip}: {e}")

            logger.info(f"APIBAN cleanup complete: {removed} removed, {checked} checked, {errors} errors")
            return {'success': True, 'removed': removed, 'checked': checked, 'errors': errors}

        except Exception as e:
            logger.error(f"APIBAN cleanup failed: {e}")
            return {'success': False, 'error': str(e)}

    async def _remove_list_ip(self, ip: str, list_id: str):
        """Remove an IP that was imported from a list"""
        async with self.db.get_cursor() as cursor:
            await cursor.execute("""
                DELETE FROM public_blocklist_ips
                WHERE ip_address = %s AND list_id = %s
            """, (ip, list_id))
            await cursor.execute("""
                DELETE FROM blocked_ips
                WHERE ip_address = %s AND added_by = %s
            """, (ip, list_id))

    async def purge_old_entries(self, max_age_days: int = 90) -> Dict:
        """Remove public blocklist entries older than max_age_days"""
        try:
            async with self.db.get_cursor() as cursor:
                await cursor.execute("""
                    SELECT ip_address, list_id FROM public_blocklist_ips
                    WHERE imported_at < DATE_SUB(NOW(), INTERVAL %s DAY)
                """, (max_age_days,))
                old_entries = await cursor.fetchall()

                if not old_entries:
                    return {'success': True, 'purged': 0}

                await cursor.execute("""
                    DELETE FROM public_blocklist_ips
                    WHERE imported_at < DATE_SUB(NOW(), INTERVAL %s DAY)
                """, (max_age_days,))
                purged_tracking = cursor.rowcount

                purged_blocked = 0
                for entry in old_entries:
                    await cursor.execute("""
                        DELETE FROM blocked_ips
                        WHERE ip_address = %s AND added_by = %s
                    """, (entry['ip_address'], entry['list_id']))
                    purged_blocked += cursor.rowcount

            logger.info(f"Public blocklist purge: {purged_tracking} tracking entries and {purged_blocked} blocked IPs older than {max_age_days} days removed")
            return {'success': True, 'purged': purged_tracking, 'purged_blocked': purged_blocked}

        except Exception as e:
            logger.error(f"Public blocklist purge failed: {e}")
            return {'success': False, 'error': str(e)}

    async def sync_all(self) -> Dict:
        """Sync all enabled blocklists"""
        results = {}

        # APIBAN
        config = await self.get_config('apiban')
        if config and config['enabled']:
            results['apiban'] = await self.sync_apiban()

        # CrowdSec
        config = await self.get_config('crowdsec')
        if config and config['enabled']:
            results['crowdsec'] = await self.sync_crowdsec()

        # OpenDBL
        config = await self.get_config('opendbl')
        if config and config['enabled']:
            results['opendbl'] = await self.sync_opendbl()

        # Custom URL lists
        custom_lists = await self.get_custom_lists()
        for cl in custom_lists:
            if cl['enabled']:
                results[cl['list_id']] = await self.sync_url_list(
                    cl['list_id'],
                    cl['url'],
                    auth_header=cl.get('auth_header'),
                    name=cl['name']
                )

        return results
