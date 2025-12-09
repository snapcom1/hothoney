#!/usr/bin/env python3
"""
REST API for SIP Honeypot Web UI
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from functools import wraps
from aiohttp import web
import aiohttp_cors
import json

from database import Database, BlocklistManager, HoneypotLogger, UserManager, SettingsManager
from juniper_export import export_blocklist, JuniperExporter
from ip_lookup import get_ip_lookup, lookup_ip, quick_lookup_ip
from abuse_reporter import AbuseReporter
from public_blocklists import PublicBlocklistManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def json_response(data, status=200):
    """Helper for JSON responses"""
    return web.json_response(data, status=status)


def auth_required(admin_only=False):
    """Decorator for authenticated endpoints"""
    def decorator(func):
        @wraps(func)
        async def wrapper(self, request):
            # Get token from header or cookie
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            if not token:
                token = request.cookies.get('session_token')

            if not token:
                return json_response({'error': 'Authentication required'}, status=401)

            user = await self.user_manager.validate_session(token)
            if not user:
                return json_response({'error': 'Invalid or expired session'}, status=401)

            if admin_only and user['role'] != 'admin':
                return json_response({'error': 'Admin access required'}, status=403)

            request['user'] = user
            return await func(self, request)
        return wrapper
    return decorator


class HoneypotAPI:
    """REST API handler"""

    # Lockout policy settings
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes in seconds

    def __init__(self, db: Database, sip_protocol_holder: dict = None):
        self.db = db
        self.blocklist = BlocklistManager(db)
        self.abuse_reporter = AbuseReporter(db)
        self.honeypot_logger = HoneypotLogger(db, self.blocklist, self.abuse_reporter)
        self.user_manager = UserManager(db)
        self.settings_manager = SettingsManager(db)
        self.public_blocklist_mgr = PublicBlocklistManager(db, self.blocklist)
        self.sip_protocol_holder = sip_protocol_holder if sip_protocol_holder is not None else {}
        self.app = web.Application()
        # Track failed login attempts: {ip: {'count': int, 'lockout_until': timestamp}}
        self.login_attempts = {}
        self._setup_routes()
        self._setup_cors()

    def _setup_routes(self):
        """Setup API routes"""
        # Auth
        self.app.router.add_post('/api/auth/login', self.login)
        self.app.router.add_post('/api/auth/logout', self.logout)
        self.app.router.add_get('/api/auth/me', self.get_current_user)

        # Dashboard
        self.app.router.add_get('/api/stats', self.get_stats)
        self.app.router.add_get('/api/stats/dest-countries', self.get_dest_country_stats)
        self.app.router.add_get('/api/active-sessions', self.get_active_sessions)

        # Blocklist
        self.app.router.add_get('/api/blocklist', self.get_blocklist)
        self.app.router.add_post('/api/blocklist', self.add_to_blocklist)
        self.app.router.add_delete('/api/blocklist/{ip}', self.remove_from_blocklist)
        self.app.router.add_post('/api/blocklist/bulk', self.bulk_add_blocklist)

        # Whitelist
        self.app.router.add_get('/api/whitelist', self.get_whitelist)
        self.app.router.add_post('/api/whitelist', self.add_to_whitelist)
        self.app.router.add_delete('/api/whitelist/{ip}', self.remove_from_whitelist)

        # Logs
        self.app.router.add_get('/api/logs', self.get_logs)

        # Export
        self.app.router.add_get('/api/export/juniper', self.export_juniper)
        self.app.router.add_get('/api/export/download', self.download_export)

        # Public endpoints (no auth required)
        self.app.router.add_get('/api/public/blocklist', self.public_blocklist)
        self.app.router.add_get('/api/public/blocklist.txt', self.public_blocklist_txt)
        self.app.router.add_get('/api/public/blocklist-ipv4.txt', self.public_blocklist_ipv4)
        self.app.router.add_get('/api/public/blocklist-ipv6.txt', self.public_blocklist_ipv6)
        self.app.router.add_get('/api/public/juniper-feed', self.public_juniper_feed)
        self.app.router.add_get('/api/public/juniper-prefixlist', self.public_juniper_prefixlist)
        self.app.router.add_get('/api/public/stats', self.public_stats)

        # IP Lookup (ARIN/RDAP) - use {ip:.*} to handle IPv6 with CIDR notation
        self.app.router.add_get('/api/ip/{ip:.*}/lookup', self.ip_lookup)
        self.app.router.add_get('/api/public/ip/{ip:.*}/lookup', self.public_ip_lookup)

        # Analytics
        self.app.router.add_get('/api/analytics/countries', self.get_country_analytics)
        self.app.router.add_get('/api/analytics/asn', self.get_asn_analytics)
        self.app.router.add_post('/api/analytics/refresh-geo', self.refresh_geo_data)

        # Abuse Reporting
        self.app.router.add_get('/api/abuse/status', self.get_abuse_status)
        self.app.router.add_post('/api/abuse/report/{ip:.*}', self.send_abuse_report)
        self.app.router.add_get('/api/abuse/history', self.get_abuse_history)
        self.app.router.add_get('/api/abuse/history/{id}', self.get_abuse_report_detail)
        self.app.router.add_get('/api/abuse/check/{ip:.*}', self.check_abuse_contact)

        # Abuse Email Blocklist
        self.app.router.add_get('/api/abuse/email-blocklist', self.get_email_blocklist)
        self.app.router.add_post('/api/abuse/email-blocklist', self.add_email_block)
        self.app.router.add_delete('/api/abuse/email-blocklist/{email:.*}', self.remove_email_block)

        # Users (admin only)
        self.app.router.add_get('/api/users', self.get_users)
        self.app.router.add_post('/api/users', self.create_user)
        self.app.router.add_put('/api/users/{id}', self.update_user)
        self.app.router.add_delete('/api/users/{id}', self.delete_user)

        # Settings (admin only)
        self.app.router.add_get('/api/settings', self.get_settings)
        self.app.router.add_put('/api/settings', self.update_settings)
        self.app.router.add_post('/api/settings/test-smtp', self.test_smtp)

        # Public Blocklists (APIBAN, etc)
        self.app.router.add_get('/api/public-blocklists', self.get_public_blocklists)
        self.app.router.add_put('/api/public-blocklists/{list_id}', self.update_public_blocklist)
        self.app.router.add_post('/api/public-blocklists/{list_id}/sync', self.sync_public_blocklist)

        # Static files (frontend) - use absolute path relative to this file
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.frontend_dir = os.path.join(base_dir, 'frontend')
        self.app.router.add_static('/static', os.path.join(self.frontend_dir, 'static'), name='static')
        self.app.router.add_get('/', self.serve_index)
        self.app.router.add_get('/{path:.*}', self.serve_frontend)

    def _setup_cors(self):
        """Setup CORS for API"""
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })

        for route in list(self.app.router.routes()):
            if route.resource is not None:
                try:
                    cors.add(route)
                except ValueError:
                    pass

    # Auth endpoints
    def _get_client_ip(self, request):
        """Get client IP, checking X-Forwarded-For for proxied requests"""
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.remote

    def _check_lockout(self, ip):
        """Check if IP is locked out. Returns (is_locked, remaining_seconds)"""
        if ip not in self.login_attempts:
            return False, 0

        attempt_info = self.login_attempts[ip]
        now = datetime.utcnow().timestamp()

        if attempt_info.get('lockout_until', 0) > now:
            remaining = int(attempt_info['lockout_until'] - now)
            return True, remaining

        # Lockout expired, reset if it was locked
        if attempt_info.get('lockout_until', 0) > 0 and attempt_info['lockout_until'] <= now:
            self.login_attempts[ip] = {'count': 0, 'lockout_until': 0}

        return False, 0

    def _record_failed_attempt(self, ip):
        """Record a failed login attempt. Returns (is_now_locked, attempts_remaining)"""
        now = datetime.utcnow().timestamp()

        if ip not in self.login_attempts:
            self.login_attempts[ip] = {'count': 0, 'lockout_until': 0}

        self.login_attempts[ip]['count'] += 1
        attempts = self.login_attempts[ip]['count']

        if attempts >= self.MAX_LOGIN_ATTEMPTS:
            self.login_attempts[ip]['lockout_until'] = now + self.LOCKOUT_DURATION
            logger.warning(f"IP {ip} locked out after {attempts} failed login attempts")
            return True, 0

        return False, self.MAX_LOGIN_ATTEMPTS - attempts

    def _clear_login_attempts(self, ip):
        """Clear login attempts on successful login"""
        if ip in self.login_attempts:
            del self.login_attempts[ip]

    async def login(self, request):
        """User login with lockout policy"""
        client_ip = self._get_client_ip(request)

        # Check if IP is locked out
        is_locked, remaining = self._check_lockout(client_ip)
        if is_locked:
            minutes = remaining // 60
            seconds = remaining % 60
            return json_response({
                'error': f'Too many failed attempts. Try again in {minutes}m {seconds}s',
                'locked': True,
                'retry_after': remaining
            }, status=429)

        try:
            data = await request.json()
        except:
            return json_response({'error': 'Invalid JSON'}, status=400)

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return json_response({'error': 'Username and password required'}, status=400)

        user = await self.user_manager.authenticate(username, password)
        if not user:
            # Record failed attempt
            is_now_locked, attempts_remaining = self._record_failed_attempt(client_ip)
            if is_now_locked:
                return json_response({
                    'error': f'Too many failed attempts. Account locked for {self.LOCKOUT_DURATION // 60} minutes',
                    'locked': True,
                    'retry_after': self.LOCKOUT_DURATION
                }, status=429)
            return json_response({
                'error': f'Invalid credentials. {attempts_remaining} attempts remaining',
                'attempts_remaining': attempts_remaining
            }, status=401)

        # Successful login - clear any failed attempts
        self._clear_login_attempts(client_ip)

        token = await self.user_manager.create_session(
            user['id'],
            ip=request.remote,
            user_agent=request.headers.get('User-Agent')
        )

        response = json_response({
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        })
        response.set_cookie('session_token', token, httponly=True, max_age=86400)
        return response

    @auth_required()
    async def logout(self, request):
        """User logout"""
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            token = request.cookies.get('session_token')

        if token:
            await self.user_manager.delete_session(token)

        response = json_response({'message': 'Logged out'})
        response.del_cookie('session_token')
        return response

    @auth_required()
    async def get_current_user(self, request):
        """Get current user info"""
        user = request['user']
        return json_response({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        })

    # Dashboard
    @auth_required()
    async def get_stats(self, request):
        """Get dashboard statistics"""
        stats = await self.honeypot_logger.get_stats()

        # Add active session time to time_wasted for real-time display
        protocol = self.sip_protocol_holder.get('protocol')
        if protocol:
            active_time = sum(
                info.get('total_elapsed', 0)
                for info in protocol.tarpit_session_info.values()
            )
            stats['time_wasted'] = stats.get('time_wasted', 0) + active_time
            stats['active_sessions'] = len(protocol.tarpit_session_info)

        return json_response(stats)

    @auth_required()
    async def get_dest_country_stats(self, request):
        """Get destination country statistics from call attempts"""
        import re

        # Phone country codes (sorted by length desc for matching)
        phone_codes = [
            ('1', 'US', 'USA/Canada'), ('7', 'RU', 'Russia'),
            ('20', 'EG', 'Egypt'), ('27', 'ZA', 'South Africa'),
            ('30', 'GR', 'Greece'), ('31', 'NL', 'Netherlands'),
            ('32', 'BE', 'Belgium'), ('33', 'FR', 'France'),
            ('34', 'ES', 'Spain'), ('36', 'HU', 'Hungary'),
            ('39', 'IT', 'Italy'), ('40', 'RO', 'Romania'),
            ('41', 'CH', 'Switzerland'), ('43', 'AT', 'Austria'),
            ('44', 'GB', 'UK'), ('45', 'DK', 'Denmark'),
            ('46', 'SE', 'Sweden'), ('47', 'NO', 'Norway'),
            ('48', 'PL', 'Poland'), ('49', 'DE', 'Germany'),
            ('51', 'PE', 'Peru'), ('52', 'MX', 'Mexico'),
            ('53', 'CU', 'Cuba'), ('54', 'AR', 'Argentina'),
            ('55', 'BR', 'Brazil'), ('56', 'CL', 'Chile'),
            ('57', 'CO', 'Colombia'), ('58', 'VE', 'Venezuela'),
            ('60', 'MY', 'Malaysia'), ('61', 'AU', 'Australia'),
            ('62', 'ID', 'Indonesia'), ('63', 'PH', 'Philippines'),
            ('64', 'NZ', 'New Zealand'), ('65', 'SG', 'Singapore'),
            ('66', 'TH', 'Thailand'), ('81', 'JP', 'Japan'),
            ('82', 'KR', 'South Korea'), ('84', 'VN', 'Vietnam'),
            ('86', 'CN', 'China'), ('90', 'TR', 'Turkey'),
            ('91', 'IN', 'India'), ('92', 'PK', 'Pakistan'),
            ('93', 'AF', 'Afghanistan'), ('94', 'LK', 'Sri Lanka'),
            ('95', 'MM', 'Myanmar'), ('98', 'IR', 'Iran'),
            ('212', 'MA', 'Morocco'), ('213', 'DZ', 'Algeria'),
            ('216', 'TN', 'Tunisia'), ('218', 'LY', 'Libya'),
            ('234', 'NG', 'Nigeria'), ('254', 'KE', 'Kenya'),
            ('255', 'TZ', 'Tanzania'), ('256', 'UG', 'Uganda'),
            ('351', 'PT', 'Portugal'), ('353', 'IE', 'Ireland'),
            ('358', 'FI', 'Finland'), ('370', 'LT', 'Lithuania'),
            ('371', 'LV', 'Latvia'), ('372', 'EE', 'Estonia'),
            ('380', 'UA', 'Ukraine'), ('381', 'RS', 'Serbia'),
            ('420', 'CZ', 'Czech Republic'), ('421', 'SK', 'Slovakia'),
            ('852', 'HK', 'Hong Kong'), ('886', 'TW', 'Taiwan'),
            ('966', 'SA', 'Saudi Arabia'), ('971', 'AE', 'UAE'),
            ('972', 'IL', 'Israel'), ('974', 'QA', 'Qatar'),
        ]
        phone_codes.sort(key=lambda x: len(x[0]), reverse=True)

        # Get recent INVITE logs
        logs = await self.honeypot_logger.get_logs(limit=1000, method_filter='INVITE')

        country_counts = {}
        for log in logs:
            uri = log.get('uri', '')
            # Extract phone number
            match = re.search(r'sip:?\+?(\d+)[@\s]', uri, re.I)
            if match:
                number = match.group(1)
                if len(number) >= 7:
                    for prefix, code, name in phone_codes:
                        if number.startswith(prefix):
                            key = (code, name)
                            country_counts[key] = country_counts.get(key, 0) + 1
                            break

        # Sort by count and return top 10
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        result = [
            {'code': code, 'name': name, 'count': count}
            for (code, name), count in sorted_countries
        ]

        return json_response({'countries': result})

    @auth_required()
    async def get_active_sessions(self, request):
        """Get active tarpit/RTP sessions"""
        protocol = self.sip_protocol_holder.get('protocol')
        if not protocol:
            return json_response({'sessions': [], 'count': 0})

        sessions = []
        now = datetime.now(timezone.utc)
        for call_id, info in protocol.tarpit_session_info.items():
            # Calculate duration server-side to avoid browser/server clock mismatch
            try:
                start_time = datetime.fromisoformat(info['start_time'].replace('Z', '+00:00'))
                duration_sec = int((now - start_time).total_seconds())
            except:
                duration_sec = 0

            session = {
                'call_id': call_id[:16] + '...' if len(call_id) > 16 else call_id,
                'ip': info['ip'],
                'port': info['port'],
                'target': info['target'],
                'phase': info['phase'],
                'ring_count': info['ring_count'],
                'total_rings': info['total_rings'],
                'start_time': info['start_time'],
                'answered_time': info['answered_time'],
                'call_duration_planned': info['call_duration_planned'],
                'call_elapsed': info['call_elapsed'],
                'duration': duration_sec
            }
            sessions.append(session)

        # Sort by start time (newest first)
        sessions.sort(key=lambda x: x['start_time'], reverse=True)

        return json_response({
            'sessions': sessions,
            'count': len(sessions)
        })

    # Blocklist endpoints
    @auth_required()
    async def get_blocklist(self, request):
        """Get blocked IPs"""
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))
        active_only = request.query.get('active', 'true').lower() == 'true'
        source_filter = request.query.get('source', '')  # 'internal', 'external', or ''

        ips = await self.blocklist.get_blocked_ips(active_only, limit, offset, source_filter)
        total = await self.blocklist.get_blocked_ip_count(active_only, source_filter)

        # Convert datetime objects to strings
        for ip in ips:
            for key in ['first_seen', 'last_seen']:
                if ip.get(key) and isinstance(ip[key], datetime):
                    ip[key] = ip[key].isoformat()

        return json_response({
            'ips': ips,
            'total': total,
            'limit': limit,
            'offset': offset
        })

    @auth_required(admin_only=True)
    async def add_to_blocklist(self, request):
        """Add IP to blocklist"""
        try:
            data = await request.json()
        except:
            return json_response({'error': 'Invalid JSON'}, status=400)

        ip = data.get('ip')
        if not ip:
            return json_response({'error': 'IP address required'}, status=400)

        reason = data.get('reason', 'Manually added')
        notes = data.get('notes')
        user = request['user']

        success = await self.blocklist.add_ip(
            ip, reason=reason, auto=False,
            added_by=user['username'], notes=notes
        )

        if success:
            return json_response({'message': f'IP {ip} added to blocklist'})
        else:
            return json_response({'error': 'Failed to add IP (may be whitelisted)'}, status=400)

    @auth_required(admin_only=True)
    async def remove_from_blocklist(self, request):
        """Remove IP from blocklist"""
        ip = request.match_info['ip']
        success = await self.blocklist.remove_ip(ip)

        if success:
            return json_response({'message': f'IP {ip} removed from blocklist'})
        else:
            return json_response({'error': 'IP not found'}, status=404)

    @auth_required(admin_only=True)
    async def bulk_add_blocklist(self, request):
        """Add multiple IPs to blocklist"""
        try:
            data = await request.json()
        except:
            return json_response({'error': 'Invalid JSON'}, status=400)

        ips = data.get('ips', [])
        reason = data.get('reason', 'Bulk import')
        user = request['user']

        added = 0
        failed = 0
        for ip in ips:
            if await self.blocklist.add_ip(ip, reason=reason, auto=False, added_by=user['username']):
                added += 1
            else:
                failed += 1

        return json_response({
            'message': f'Added {added} IPs, {failed} failed',
            'added': added,
            'failed': failed
        })

    # Whitelist endpoints
    @auth_required()
    async def get_whitelist(self, request):
        """Get whitelist"""
        whitelist = await self.blocklist.get_whitelist()

        for entry in whitelist:
            if entry.get('created_at') and isinstance(entry['created_at'], datetime):
                entry['created_at'] = entry['created_at'].isoformat()

        return json_response({'whitelist': whitelist})

    @auth_required(admin_only=True)
    async def add_to_whitelist(self, request):
        """Add IP to whitelist"""
        try:
            data = await request.json()
        except:
            return json_response({'error': 'Invalid JSON'}, status=400)

        ip = data.get('ip')
        if not ip:
            return json_response({'error': 'IP address required'}, status=400)

        description = data.get('description')
        user = request['user']

        success = await self.blocklist.add_whitelist(ip, description, user['username'])

        if success:
            return json_response({'message': f'IP {ip} added to whitelist'})
        else:
            return json_response({'error': 'Failed to add IP'}, status=400)

    @auth_required(admin_only=True)
    async def remove_from_whitelist(self, request):
        """Remove IP from whitelist"""
        ip = request.match_info['ip']
        success = await self.blocklist.remove_whitelist(ip)

        if success:
            return json_response({'message': f'IP {ip} removed from whitelist'})
        else:
            return json_response({'error': 'IP not found'}, status=404)

    # Logs endpoints
    @auth_required()
    async def get_logs(self, request):
        """Get honeypot logs"""
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))
        ip_filter = request.query.get('ip')
        method_filter = request.query.get('method')

        logs = await self.honeypot_logger.get_logs(limit, offset, ip_filter, method_filter)

        # Convert datetime and parse JSON fields
        for log in logs:
            if log.get('timestamp') and isinstance(log['timestamp'], datetime):
                log['timestamp'] = log['timestamp'].isoformat()
            for field in ['headers', 'credentials']:
                if log.get(field) and isinstance(log[field], str):
                    try:
                        log[field] = json.loads(log[field])
                    except:
                        pass

        return json_response({'logs': logs, 'limit': limit, 'offset': offset})

    # Export endpoints
    @auth_required()
    async def export_juniper(self, request):
        """Export blocklist in Juniper format"""
        format_type = request.query.get('format', 'full')
        prefix_name = request.query.get('prefix_name', 'HONEYPOT-BLOCKLIST')
        filter_name = request.query.get('filter_name', 'HONEYPOT-BLOCK')

        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)

        try:
            output = export_blocklist(ips, format_type, prefix_name, filter_name)
        except ValueError as e:
            return json_response({'error': str(e)}, status=400)

        return json_response({
            'format': format_type,
            'ip_count': len(ips),
            'config': output
        })

    @auth_required()
    async def download_export(self, request):
        """Download blocklist as file"""
        format_type = request.query.get('format', 'full')
        prefix_name = request.query.get('prefix_name', 'HONEYPOT-BLOCKLIST')
        filter_name = request.query.get('filter_name', 'HONEYPOT-BLOCK')

        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)
        output = export_blocklist(ips, format_type, prefix_name, filter_name)

        # Determine filename and content type
        extensions = {
            'xml': ('xml', 'application/xml'),
            'json': ('json', 'application/json'),
            'simple': ('txt', 'text/plain'),
        }
        ext, content_type = extensions.get(format_type, ('conf', 'text/plain'))
        filename = f"honeypot-blocklist-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.{ext}"

        return web.Response(
            text=output,
            content_type=content_type,
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )

    # User management endpoints
    @auth_required(admin_only=True)
    async def get_users(self, request):
        """Get all users"""
        users = await self.user_manager.get_users()

        for user in users:
            for field in ['created_at', 'last_login']:
                if user.get(field) and isinstance(user[field], datetime):
                    user[field] = user[field].isoformat()

        return json_response({'users': users})

    @auth_required(admin_only=True)
    async def create_user(self, request):
        """Create new user"""
        try:
            data = await request.json()
        except:
            return json_response({'error': 'Invalid JSON'}, status=400)

        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        role = data.get('role', 'viewer')

        if not username or not password:
            return json_response({'error': 'Username and password required'}, status=400)

        if role not in ['admin', 'viewer']:
            return json_response({'error': 'Invalid role'}, status=400)

        user_id = await self.user_manager.create_user(username, password, email, role)

        if user_id:
            return json_response({'message': 'User created', 'id': user_id})
        else:
            return json_response({'error': 'Failed to create user'}, status=400)

    @auth_required(admin_only=True)
    async def update_user(self, request):
        """Update user"""
        user_id = int(request.match_info['id'])
        try:
            data = await request.json()
        except:
            return json_response({'error': 'Invalid JSON'}, status=400)

        success = await self.user_manager.update_user(user_id, **data)

        if success:
            return json_response({'message': 'User updated'})
        else:
            return json_response({'error': 'Failed to update user'}, status=400)

    @auth_required(admin_only=True)
    async def delete_user(self, request):
        """Delete user"""
        user_id = int(request.match_info['id'])
        current_user = request['user']

        if user_id == current_user['id']:
            return json_response({'error': 'Cannot delete yourself'}, status=400)

        success = await self.user_manager.delete_user(user_id)

        if success:
            return json_response({'message': 'User deleted'})
        else:
            return json_response({'error': 'Failed to delete user'}, status=404)

    # Public endpoints (no auth required)
    def _split_ips_by_version(self, ips):
        """Split IPs into IPv4 and IPv6 lists"""
        ipv4 = []
        ipv6 = []
        for ip in ips:
            addr = ip['ip_address'] if isinstance(ip, dict) else ip
            if ':' in addr:
                ipv6.append(addr)
            else:
                ipv4.append(addr)
        return ipv4, ipv6

    async def public_blocklist(self, request):
        """Public JSON blocklist"""
        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)
        ipv4, ipv6 = self._split_ips_by_version(ips)
        return json_response({
            'count': len(ips),
            'ipv4_count': len(ipv4),
            'ipv6_count': len(ipv6),
            'ips': [ip['ip_address'] for ip in ips],
            'ipv4': ipv4,
            'ipv6': ipv6,
            'updated': datetime.utcnow().isoformat()
        })

    async def public_blocklist_txt(self, request):
        """Public plain text blocklist (one IP per line) - all IPs"""
        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)
        ipv4, ipv6 = self._split_ips_by_version(ips)
        ip_list = '\n'.join(ip['ip_address'] for ip in ips)
        return web.Response(
            text=f"# SIP Honeypot Blocklist - hothoney.snapcom.com\n# Updated: {datetime.utcnow().isoformat()}\n# Total: {len(ips)} (IPv4: {len(ipv4)}, IPv6: {len(ipv6)})\n\n{ip_list}\n",
            content_type='text/plain'
        )

    async def public_blocklist_ipv4(self, request):
        """Public plain text blocklist - IPv4 only"""
        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)
        ipv4, _ = self._split_ips_by_version(ips)
        ip_list = '\n'.join(ipv4)
        return web.Response(
            text=f"# SIP Honeypot Blocklist (IPv4) - hothoney.snapcom.com\n# Updated: {datetime.utcnow().isoformat()}\n# Count: {len(ipv4)}\n\n{ip_list}\n",
            content_type='text/plain'
        )

    async def public_blocklist_ipv6(self, request):
        """Public plain text blocklist - IPv6 only"""
        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)
        _, ipv6 = self._split_ips_by_version(ips)
        ip_list = '\n'.join(ipv6)
        return web.Response(
            text=f"# SIP Honeypot Blocklist (IPv6) - hothoney.snapcom.com\n# Updated: {datetime.utcnow().isoformat()}\n# Count: {len(ipv6)}\n\n{ip_list}\n",
            content_type='text/plain'
        )

    async def public_juniper_feed(self, request):
        """Juniper SRX dynamic address feed format - clean IP list with prefix"""
        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)
        ipv4, ipv6 = self._split_ips_by_version(ips)

        # Juniper format: IP/prefix, one per line, no comments
        # If IP already has prefix, use it; otherwise IPv4 gets /32, IPv6 gets /128
        lines = []
        for ip in ipv4:
            if '/' in ip:
                lines.append(ip)
            else:
                lines.append(f"{ip}/32")
        for ip in ipv6:
            if '/' in ip:
                lines.append(ip)
            else:
                lines.append(f"{ip}/128")

        return web.Response(
            text='\n'.join(lines) + '\n',
            content_type='text/plain'
        )

    async def public_juniper_prefixlist(self, request):
        """Juniper prefix-list configuration format for firewall filters"""
        ips = await self.blocklist.get_blocked_ips(active_only=True, limit=10000)
        ipv4, ipv6 = self._split_ips_by_version(ips)

        # Get optional prefix-list name from query param, default to HONEYPOT-BLOCKLIST
        list_name = request.query.get('name', 'HONEYPOT-BLOCKLIST')

        lines = ["policy-options {"]

        # IPv4 prefix-list
        lines.append(f"    prefix-list {list_name}-V4 {{")
        for ip in ipv4:
            if '/' in ip:
                lines.append(f"        {ip};")
            else:
                lines.append(f"        {ip}/32;")
        lines.append("    }")

        # IPv6 prefix-list
        lines.append(f"    prefix-list {list_name}-V6 {{")
        for ip in ipv6:
            if '/' in ip:
                lines.append(f"        {ip};")
            else:
                lines.append(f"        {ip}/128;")
        lines.append("    }")

        lines.append("}")

        return web.Response(
            text='\n'.join(lines) + '\n',
            content_type='text/plain'
        )

    async def public_stats(self, request):
        """Public statistics"""
        stats = await self.honeypot_logger.get_stats()
        return json_response({
            'total_attacks': stats.get('total_logs', 0),
            'attacks_24h': stats.get('logs_24h', 0),
            'unique_attackers': stats.get('unique_ips', 0),
            'blocked_ips': stats.get('blocked_ips', 0),
            'updated': datetime.utcnow().isoformat()
        })

    # IP Lookup endpoints (ARIN/RDAP)
    @auth_required()
    async def ip_lookup(self, request):
        """Look up IP ownership info (authenticated)"""
        ip = request.match_info['ip']
        try:
            result = await lookup_ip(ip)
            # Remove raw RDAP data for cleaner response
            if result.get('raw'):
                del result['raw']
            return json_response(result)
        except Exception as e:
            logger.error(f"IP lookup error for {ip}: {e}")
            return json_response({'error': str(e), 'ip': ip}, status=500)

    async def public_ip_lookup(self, request):
        """Public IP lookup (no auth required)"""
        ip = request.match_info['ip']
        try:
            result = await lookup_ip(ip)
            # Return limited info for public endpoint
            return json_response({
                'ip': result.get('ip'),
                'network': result.get('network'),
                'name': result.get('name'),
                'organization': result.get('organization'),
                'country': result.get('country'),
                'cidr': result.get('cidr'),
                'rir': result.get('rir'),
                'error': result.get('error')
            })
        except Exception as e:
            logger.error(f"Public IP lookup error for {ip}: {e}")
            return json_response({'error': str(e), 'ip': ip}, status=500)

    # Analytics endpoints
    @auth_required()
    async def get_country_analytics(self, request):
        """Get attack statistics by country"""
        try:
            stats = await self.honeypot_logger.get_country_stats()
            return json_response({
                'countries': stats,
                'updated': datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.error(f"Country analytics error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required()
    async def get_asn_analytics(self, request):
        """Get attack statistics by ASN"""
        try:
            stats = await self.honeypot_logger.get_asn_stats()
            return json_response({
                'asns': stats,
                'updated': datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.error(f"ASN analytics error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def refresh_geo_data(self, request):
        """Refresh geo data for IPs without cached data"""
        try:
            # Get uncached IPs
            uncached_ips = await self.honeypot_logger.get_uncached_ips(limit=50)

            if not uncached_ips:
                return json_response({'message': 'All IPs have geo data cached', 'processed': 0})

            processed = 0
            for ip in uncached_ips:
                try:
                    # Get geo data
                    geo_data = await quick_lookup_ip(ip)
                    if not geo_data.get('error'):
                        await self.honeypot_logger.save_ip_geo(ip, geo_data)
                        processed += 1
                except Exception as e:
                    logger.error(f"Failed to get geo for {ip}: {e}")

            return json_response({
                'message': f'Processed {processed} IPs',
                'processed': processed,
                'remaining': len(uncached_ips) - processed
            })
        except Exception as e:
            logger.error(f"Refresh geo data error: {e}")
            return json_response({'error': str(e)}, status=500)

    # Abuse Reporting endpoints (read endpoints available to all, write endpoints admin only)
    @auth_required()
    async def get_abuse_status(self, request):
        """Get abuse reporting configuration status and stats"""
        try:
            is_configured = self.abuse_reporter.is_configured()
            stats = await self.abuse_reporter.get_report_stats() if is_configured else None

            return json_response({
                'configured': is_configured,
                'smtp_host': os.environ.get('SMTP_HOST', '') if is_configured else None,
                'stats': stats
            })
        except Exception as e:
            logger.error(f"Get abuse status error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def check_abuse_contact(self, request):
        """Check abuse contact for an IP without sending report"""
        ip = request.match_info.get('ip', '')
        if not ip:
            return json_response({'error': 'IP address required'}, status=400)

        try:
            ip_info = await lookup_ip(ip)
            if not ip_info or ip_info.get('error'):
                return json_response({
                    'ip': ip,
                    'has_contact': False,
                    'error': ip_info.get('error', 'Lookup failed')
                })

            abuse_email = ip_info.get('abuse_contact')
            can_send, reason = await self.abuse_reporter.can_send_report(ip)
            attack_summary = await self.abuse_reporter.get_attack_summary(ip)

            return json_response({
                'ip': ip,
                'has_contact': bool(abuse_email),
                'abuse_email': abuse_email,
                'organization': ip_info.get('organization'),
                'network': ip_info.get('network'),
                'can_send': can_send,
                'cooldown_reason': reason,
                'attack_count': attack_summary['total_attacks']
            })
        except Exception as e:
            logger.error(f"Check abuse contact error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def send_abuse_report(self, request):
        """Send abuse report for an IP"""
        ip = request.match_info.get('ip', '')
        if not ip:
            return json_response({'error': 'IP address required'}, status=400)

        try:
            # Check if manual override requested
            try:
                data = await request.json()
                force = data.get('force', False)
            except:
                force = False

            # Reload settings before sending to ensure latest config
            await self.abuse_reporter.reload_settings()

            result = await self.abuse_reporter.send_report(ip, manual=force)
            logger.info(f"Abuse report result for {ip}: {result}")
            status = 200 if result['success'] else 400
            return json_response(result, status=status)
        except Exception as e:
            logger.error(f"Send abuse report error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required()
    async def get_abuse_history(self, request):
        """Get abuse report history"""
        try:
            limit = int(request.query.get('limit', 50))
            offset = int(request.query.get('offset', 0))

            history = await self.abuse_reporter.get_report_history(limit, offset)
            # Convert datetime objects to strings
            for report in history:
                for key in ['sent_at', 'first_seen', 'last_seen']:
                    if report.get(key):
                        report[key] = report[key].isoformat()

            return json_response({'reports': history})
        except Exception as e:
            logger.error(f"Get abuse history error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required()
    async def get_abuse_report_detail(self, request):
        """Get a single abuse report by ID including the email body"""
        try:
            report_id = int(request.match_info['id'])
            report = await self.abuse_reporter.get_report_by_id(report_id)

            if not report:
                return json_response({'error': 'Report not found'}, status=404)

            # Convert datetime objects to strings
            for key in ['sent_at', 'first_seen', 'last_seen']:
                if report.get(key):
                    report[key] = report[key].isoformat()

            return json_response({'report': report})
        except ValueError:
            return json_response({'error': 'Invalid report ID'}, status=400)
        except Exception as e:
            logger.error(f"Get abuse report detail error: {e}")
            return json_response({'error': str(e)}, status=500)

    # Abuse email blocklist endpoints
    @auth_required(admin_only=True)
    async def get_email_blocklist(self, request):
        """Get list of blocked abuse emails"""
        try:
            blocklist = await self.abuse_reporter.get_email_blocklist()
            # Convert datetime objects
            for item in blocklist:
                if item.get('created_at'):
                    item['created_at'] = item['created_at'].isoformat()
            return json_response({'blocklist': blocklist})
        except Exception as e:
            logger.error(f"Get email blocklist error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def add_email_block(self, request):
        """Add an email to the abuse blocklist"""
        try:
            data = await request.json()
            email = data.get('email', '').strip()
            reason = data.get('reason', '')

            if not email:
                return json_response({'error': 'Email is required'}, status=400)

            user = request.get('user', {})
            username = user.get('username', 'unknown')

            success = await self.abuse_reporter.add_email_block(email, reason, username)
            if success:
                return json_response({'success': True, 'message': f'{email} added to blocklist'})
            else:
                return json_response({'error': 'Failed to add email (may already exist)'}, status=400)
        except Exception as e:
            logger.error(f"Add email block error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def remove_email_block(self, request):
        """Remove an email from the abuse blocklist"""
        try:
            email = request.match_info['email']
            success = await self.abuse_reporter.remove_email_block(email)
            if success:
                return json_response({'success': True, 'message': f'{email} removed from blocklist'})
            else:
                return json_response({'error': 'Email not found in blocklist'}, status=404)
        except Exception as e:
            logger.error(f"Remove email block error: {e}")
            return json_response({'error': str(e)}, status=500)

    # Settings endpoints (admin only)
    @auth_required(admin_only=True)
    async def get_settings(self, request):
        """Get all settings"""
        try:
            settings = await self.settings_manager.get_settings(include_sensitive=False)
            schema = self.settings_manager.SETTINGS_SCHEMA
            return json_response({
                'settings': settings,
                'schema': {k: {'type': v['type'], 'description': v['description']}
                          for k, v in schema.items()}
            })
        except Exception as e:
            logger.error(f"Get settings error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def update_settings(self, request):
        """Update settings"""
        try:
            data = await request.json()
            settings = data.get('settings', {})

            if not settings:
                return json_response({'error': 'No settings provided'}, status=400)

            user = request.get('user', {})
            username = user.get('username', 'unknown')

            results = await self.settings_manager.set_settings(settings, updated_by=username)

            # Reload abuse reporter settings
            await self.abuse_reporter.reload_settings()

            # Reload honeypot logger settings (throttle and credential rate limit)
            await self.honeypot_logger.reload_throttle_settings()
            await self.honeypot_logger.reload_credential_ratelimit_settings()

            return json_response({
                'success': True,
                'results': results,
                'message': 'Settings updated successfully'
            })
        except Exception as e:
            logger.error(f"Update settings error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def test_smtp(self, request):
        """Test SMTP connection"""
        try:
            result = await self.settings_manager.test_smtp()
            status = 200 if result.get('success') else 400
            return json_response(result, status=status)
        except Exception as e:
            logger.error(f"Test SMTP error: {e}")
            return json_response({'error': str(e)}, status=500)

    # Public Blocklist endpoints
    @auth_required(admin_only=True)
    async def get_public_blocklists(self, request):
        """Get all public blocklist configurations"""
        try:
            configs = await self.public_blocklist_mgr.get_all_configs()
            return json_response({'lists': configs})
        except Exception as e:
            logger.error(f"Get public blocklists error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def update_public_blocklist(self, request):
        """Update a public blocklist configuration"""
        list_id = request.match_info['list_id']
        try:
            data = await request.json()
            enabled = data.get('enabled', False)
            api_key = data.get('api_key', '')

            await self.public_blocklist_mgr.save_config(list_id, enabled, api_key)

            return json_response({
                'success': True,
                'message': f'Configuration for {list_id} updated'
            })
        except ValueError as e:
            return json_response({'error': str(e)}, status=400)
        except Exception as e:
            logger.error(f"Update public blocklist error: {e}")
            return json_response({'error': str(e)}, status=500)

    @auth_required(admin_only=True)
    async def sync_public_blocklist(self, request):
        """Sync a public blocklist (fetch new IPs)"""
        list_id = request.match_info['list_id']
        try:
            if list_id == 'apiban':
                result = await self.public_blocklist_mgr.sync_apiban()
            else:
                return json_response({'error': f'Unknown blocklist: {list_id}'}, status=400)

            status = 200 if result.get('success') else 400
            return json_response(result, status=status)
        except Exception as e:
            logger.error(f"Sync public blocklist error: {e}")
            return json_response({'error': str(e)}, status=500)

    # Frontend serving
    async def serve_index(self, request):
        """Serve frontend index.html"""
        try:
            index_path = os.path.join(self.frontend_dir, 'index.html')
            with open(index_path, 'r') as f:
                return web.Response(text=f.read(), content_type='text/html')
        except FileNotFoundError:
            return web.Response(text="Frontend not found", status=404)

    async def serve_frontend(self, request):
        """Serve frontend files"""
        path = request.match_info.get('path', 'index.html')
        # Security: prevent directory traversal
        if '..' in path:
            return web.Response(text="Forbidden", status=403)

        file_path = os.path.join(self.frontend_dir, path)
        try:
            with open(file_path, 'r') as f:
                # Determine content type
                content_type = 'text/html'
                if path.endswith('.js'):
                    content_type = 'application/javascript'
                elif path.endswith('.css'):
                    content_type = 'text/css'
                elif path.endswith('.json'):
                    content_type = 'application/json'
                return web.Response(text=f.read(), content_type=content_type)
        except FileNotFoundError:
            # Return index.html for SPA routing
            try:
                index_path = os.path.join(self.frontend_dir, 'index.html')
                with open(index_path, 'r') as f:
                    return web.Response(text=f.read(), content_type='text/html')
            except:
                return web.Response(text="Not found", status=404)


async def create_api(db: Database) -> web.Application:
    """Create API application"""
    api = HoneypotAPI(db)
    return api.app


async def run_api(host: str = '0.0.0.0', port: int = 8081, db: Database = None):
    """Run API server"""
    api = HoneypotAPI(db)
    # Initialize abuse reporter database table
    await api.abuse_reporter.init_db()
    await api.abuse_reporter.reload_settings()
    # Initialize public blocklist tables
    await api.public_blocklist_mgr.init_db()
    runner = web.AppRunner(api.app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info(f"API server started on http://{host}:{port}")

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await runner.cleanup()


if __name__ == '__main__':
    # For testing
    async def main():
        db = Database()
        await db.connect()
        await db.init_tables()
        await db.create_default_admin()
        await run_api(db=db)

    asyncio.run(main())
