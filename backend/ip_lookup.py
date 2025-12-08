#!/usr/bin/env python3
"""
IP Lookup Module - ARIN/RDAP queries for IP ownership information
Includes ASN lookup and country detection
"""

import asyncio
import aiohttp
import logging
from typing import Optional, Dict
from functools import lru_cache
import time
import re

logger = logging.getLogger(__name__)

# RDAP endpoints for different RIRs
RDAP_ENDPOINTS = {
    'arin': 'https://rdap.arin.net/registry/ip/',
    'ripe': 'https://rdap.db.ripe.net/ip/',
    'apnic': 'https://rdap.apnic.net/ip/',
    'lacnic': 'https://rdap.lacnic.net/rdap/ip/',
    'afrinic': 'https://rdap.afrinic.net/rdap/ip/',
}

# Bootstrap endpoint that redirects to correct RIR
RDAP_BOOTSTRAP = 'https://rdap.org/ip/'

# ASN lookup endpoint
ASN_LOOKUP_URL = 'https://rdap.org/autnum/'

# IP-API for geolocation (free tier: 45 requests/minute)
IPAPI_URL = 'http://ip-api.com/json/'


class IPLookup:
    """Async IP lookup using RDAP protocol"""

    def __init__(self, cache_ttl: int = 3600):
        self.cache: Dict[str, tuple] = {}  # ip -> (timestamp, data)
        self.cache_ttl = cache_ttl

    def _get_cached(self, ip: str) -> Optional[Dict]:
        """Get cached result if not expired"""
        if ip in self.cache:
            timestamp, data = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return data
            del self.cache[ip]
        return None

    def _set_cache(self, ip: str, data: Dict):
        """Cache lookup result"""
        self.cache[ip] = (time.time(), data)

    async def lookup(self, ip: str) -> Dict:
        """Look up IP ownership information"""
        # Check cache first
        cached = self._get_cached(ip)
        if cached:
            return cached

        result = {
            'ip': ip,
            'network': None,
            'name': None,
            'organization': None,
            'country': None,
            'abuse_contact': None,
            'description': None,
            'cidr': None,
            'rir': None,
            'raw': None,
            'error': None
        }

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                # Use bootstrap endpoint - it redirects to correct RIR
                url = f"{RDAP_BOOTSTRAP}{ip}"

                async with session.get(url, allow_redirects=True) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = self._parse_rdap_response(ip, data)
                    else:
                        result['error'] = f"RDAP lookup failed: HTTP {response.status}"

        except asyncio.TimeoutError:
            result['error'] = "Lookup timed out"
        except aiohttp.ClientError as e:
            result['error'] = f"Network error: {str(e)}"
        except Exception as e:
            logger.error(f"IP lookup error for {ip}: {e}")
            result['error'] = str(e)

        # Cache result (even errors, to prevent hammering)
        self._set_cache(ip, result)
        return result

    def _parse_rdap_response(self, ip: str, data: Dict) -> Dict:
        """Parse RDAP JSON response"""
        result = {
            'ip': ip,
            'network': None,
            'name': data.get('name'),
            'organization': None,
            'country': data.get('country'),
            'abuse_contact': None,
            'description': None,
            'cidr': None,
            'rir': None,
            'raw': data,
            'error': None
        }

        # Extract network/CIDR
        if 'startAddress' in data and 'endAddress' in data:
            result['network'] = f"{data['startAddress']} - {data['endAddress']}"

        # Get CIDR from cidr0_cidrs if available
        cidrs = data.get('cidr0_cidrs', [])
        if cidrs:
            cidr_strs = [f"{c.get('v4prefix', c.get('v6prefix', ''))}/{c.get('length', '')}" for c in cidrs]
            result['cidr'] = ', '.join(cidr_strs)

        # Extract handle/name
        result['name'] = data.get('name') or data.get('handle')

        # Get RIR from port43 or links
        port43 = data.get('port43', '')
        if 'arin' in port43:
            result['rir'] = 'ARIN'
        elif 'ripe' in port43:
            result['rir'] = 'RIPE'
        elif 'apnic' in port43:
            result['rir'] = 'APNIC'
        elif 'lacnic' in port43:
            result['rir'] = 'LACNIC'
        elif 'afrinic' in port43:
            result['rir'] = 'AFRINIC'

        # Extract entities (org, abuse contact)
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])

            # Get organization
            if 'registrant' in roles or 'administrative' in roles:
                vcard = self._parse_vcard(entity.get('vcardArray', []))
                if vcard.get('fn'):
                    result['organization'] = vcard.get('fn')
                if vcard.get('org'):
                    result['organization'] = vcard.get('org')

            # Get abuse contact
            if 'abuse' in roles:
                vcard = self._parse_vcard(entity.get('vcardArray', []))
                if vcard.get('email'):
                    result['abuse_contact'] = vcard.get('email')

            # Recurse into nested entities
            for nested in entity.get('entities', []):
                nested_roles = nested.get('roles', [])
                if 'abuse' in nested_roles:
                    vcard = self._parse_vcard(nested.get('vcardArray', []))
                    if vcard.get('email'):
                        result['abuse_contact'] = vcard.get('email')

        # Get remarks/description
        remarks = data.get('remarks', [])
        if remarks:
            descriptions = []
            for remark in remarks:
                desc = remark.get('description', [])
                if desc:
                    descriptions.extend(desc)
            if descriptions:
                result['description'] = ' | '.join(descriptions[:3])  # Limit length

        return result

    def _parse_vcard(self, vcard_array) -> Dict:
        """Parse vCard array format used in RDAP"""
        result = {'fn': None, 'org': None, 'email': None, 'tel': None, 'adr': None}

        if not vcard_array or len(vcard_array) < 2:
            return result

        # vCard format: ['vcard', [[prop_name, {}, type, value], ...]]
        try:
            props = vcard_array[1]
            for prop in props:
                if len(prop) >= 4:
                    prop_name = prop[0].lower()
                    value = prop[3]

                    if prop_name == 'fn':
                        result['fn'] = value
                    elif prop_name == 'org':
                        result['org'] = value if isinstance(value, str) else value[0] if value else None
                    elif prop_name == 'email':
                        result['email'] = value
                    elif prop_name == 'tel':
                        result['tel'] = value
                    elif prop_name == 'adr':
                        if isinstance(value, list):
                            result['adr'] = ', '.join(str(v) for v in value if v)
        except (IndexError, TypeError, KeyError):
            pass

        return result

    async def bulk_lookup(self, ips: list, max_concurrent: int = 5) -> Dict[str, Dict]:
        """Look up multiple IPs with concurrency limit"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_lookup(ip):
            async with semaphore:
                return ip, await self.lookup(ip)

        results = await asyncio.gather(*[limited_lookup(ip) for ip in ips])
        return dict(results)

    async def quick_lookup(self, ip: str) -> Dict:
        """Quick IP lookup using ip-api.com (faster, includes ASN and geo)"""
        # Strip CIDR if present
        clean_ip = ip.split('/')[0]

        # Check cache
        cache_key = f"quick_{clean_ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        result = {
            'ip': clean_ip,
            'country': None,
            'country_code': None,
            'region': None,
            'city': None,
            'isp': None,
            'org': None,
            'asn': None,
            'asn_name': None,
            'error': None
        }

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                # ip-api.com with ASN fields
                url = f"{IPAPI_URL}{clean_ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,asname"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success':
                            result['country'] = data.get('country')
                            result['country_code'] = data.get('countryCode')
                            result['region'] = data.get('regionName')
                            result['city'] = data.get('city')
                            result['isp'] = data.get('isp')
                            result['org'] = data.get('org')
                            # Parse ASN from "AS12345 Name" format
                            as_info = data.get('as', '')
                            if as_info:
                                match = re.match(r'AS(\d+)\s*(.*)', as_info)
                                if match:
                                    result['asn'] = f"AS{match.group(1)}"
                                    result['asn_name'] = match.group(2).strip() or data.get('asname')
                                else:
                                    result['asn'] = as_info
                            result['asn_name'] = result['asn_name'] or data.get('asname')
                        else:
                            result['error'] = data.get('message', 'Lookup failed')
                    else:
                        result['error'] = f"HTTP {response.status}"

        except asyncio.TimeoutError:
            result['error'] = "Lookup timed out"
        except Exception as e:
            logger.error(f"Quick IP lookup error for {ip}: {e}")
            result['error'] = str(e)

        self._set_cache(cache_key, result)
        return result

    async def bulk_quick_lookup(self, ips: list, max_concurrent: int = 10) -> Dict[str, Dict]:
        """Bulk quick lookup with rate limiting"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_lookup(ip):
            async with semaphore:
                # Rate limit to avoid hitting ip-api limits
                await asyncio.sleep(0.05)
                return ip, await self.quick_lookup(ip)

        results = await asyncio.gather(*[limited_lookup(ip) for ip in ips])
        return dict(results)


# Global instance
_ip_lookup = None

def get_ip_lookup() -> IPLookup:
    """Get or create global IP lookup instance"""
    global _ip_lookup
    if _ip_lookup is None:
        _ip_lookup = IPLookup()
    return _ip_lookup


async def lookup_ip(ip: str) -> Dict:
    """Convenience function for single IP lookup"""
    return await get_ip_lookup().lookup(ip)


async def quick_lookup_ip(ip: str) -> Dict:
    """Convenience function for quick IP lookup (geo + ASN)"""
    return await get_ip_lookup().quick_lookup(ip)
