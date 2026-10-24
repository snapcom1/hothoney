#!/usr/bin/env python3
"""
Fake Provisioning Server
Emulates Polycom, Yealink, Grandstream, and NetSapiens provisioning endpoints
"""

import asyncio
import logging
import re
import random
import string
from datetime import datetime
from aiohttp import web
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fake server domains for provisioning responses
FAKE_SIP_SERVERS = [
    'sip1.voip-provider.net',
    'pbx.cloudcomm.io',
    'proxy.voiceservices.com',
    'sip.unified-comms.net',
    'core.siptrunk.io',
    'media.voip-connect.com',
]

FAKE_PROXY_SERVERS = [
    'proxy1.voip-provider.net',
    'outbound.cloudcomm.io',
    'nat.voiceservices.com',
    'edge.siptrunk.io',
]


class ProvisioningHoneypot:
    """HTTP Provisioning Honeypot Server"""

    PHP_SHELL_PATHS = [
        'shell.php', 'cmd.php', 'c99.php', 'r57.php', 'b374k.php',
        'wso.php', 'webshell.php', 'backdoor.php', 'hack.php',
        'up.php', 'upload.php', 'filemanager.php', 'files.php',
        'exec.php', 'eval.php', 'command.php', 'terminal.php',
        'console.php', 'phpinfo.php', 'info.php', 'test.php',
        'wp-content/uploads/shell.php', 'wp-content/plugins/shell.php',
        'wp-includes/shell.php', 'images/shell.php', 'tmp/shell.php',
        'alfa.php', 'alfaloader.php', 'mini.php', 'adminer.php',
        'phpMyAdmin/index.php', 'phpmyadmin/index.php', 'pma/index.php',
        'myadmin/index.php', 'db/index.php',
    ]

    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.app = web.Application(middlewares=[self.logging_middleware])
        self._setup_routes()

    def _extract_mac(self, request) -> str:
        """Extract MAC address from request path"""
        path = request.path.lower()
        mac = request.match_info.get('mac', '')

        # Try to find MAC in path if not in match_info
        if not mac:
            # Look for 12 hex chars pattern
            match = re.search(r'([0-9a-f]{12})', path)
            if match:
                mac = match.group(1)

        # Clean up MAC - remove colons/dashes and lowercase
        mac = re.sub(r'[:\-]', '', mac).lower()

        # If still no MAC, generate one based on request
        if not mac or len(mac) != 12:
            mac = hashlib.md5(path.encode()).hexdigest()[:12]

        return mac.upper()

    def _format_mac(self, mac: str, separator: str = ':') -> str:
        """Format MAC address with separator"""
        mac = mac.upper()
        return separator.join(mac[i:i+2] for i in range(0, 12, 2))

    def _generate_fake_credentials(self, mac: str) -> dict:
        """Generate deterministic but realistic-looking fake SIP credentials based on MAC"""
        # Use MAC to seed so same MAC always gets same creds
        seed = int(mac, 16) % (2**32)
        rng = random.Random(seed)

        # Generate extension (3-4 digits)
        extension = str(rng.randint(100, 9999))

        # Generate password (8-12 chars, alphanumeric)
        password_chars = string.ascii_letters + string.digits
        password = ''.join(rng.choice(password_chars) for _ in range(rng.randint(8, 12)))

        # Generate auth user (sometimes different from extension)
        if rng.random() > 0.5:
            auth_user = f"{extension}_{mac[-4:]}"
        else:
            auth_user = extension

        # Pick servers deterministically
        sip_server = FAKE_SIP_SERVERS[seed % len(FAKE_SIP_SERVERS)]
        proxy_server = FAKE_PROXY_SERVERS[seed % len(FAKE_PROXY_SERVERS)]

        # Generate display name
        names = ['John', 'Jane', 'Mike', 'Sarah', 'David', 'Lisa', 'James', 'Emily', 'Robert', 'Amy']
        display_name = f"{rng.choice(names)} {extension}"

        return {
            'extension': extension,
            'password': password,
            'auth_user': auth_user,
            'display_name': display_name,
            'sip_server': sip_server,
            'proxy_server': proxy_server,
            'mac': mac,
            'mac_formatted': self._format_mac(mac),
        }

    async def _log_credentials_sent(self, request, creds: dict, config_type: str):
        """Log when fake credentials are sent to an attacker"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        logger.warning(
            f"FAKE CREDENTIALS SENT - Type: {config_type}, MAC: {creds['mac']}, "
            f"Ext: {creds['extension']}, User: {creds['auth_user']}, Pass: {creds['password']}, "
            f"Server: {creds['sip_server']}, To: {source_ip}"
        )

        if self.log_callback:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_ip,
                'source_port': 0,
                'method': 'CREDENTIALS_SENT',
                'uri': request.path,
                'path': request.path,
                'user_agent': request.headers.get('User-Agent', 'unknown'),
                'protocol': 'HTTP',
                'honeypot_type': 'provisioning',
                'config_type': config_type,
                'credentials_sent': {
                    'mac': creds['mac'],
                    'mac_formatted': creds['mac_formatted'],
                    'extension': creds['extension'],
                    'auth_user': creds['auth_user'],
                    'password': creds['password'],
                    'display_name': creds['display_name'],
                    'sip_server': creds['sip_server'],
                    'proxy_server': creds['proxy_server'],
                }
            }
            asyncio.create_task(self.log_callback(log_entry))

    def _setup_routes(self):
        """Setup all fake provisioning endpoints"""
        # NOTE: More specific routes MUST come before generic catch-all patterns

        # Yealink endpoints (must be before generic /{mac}.cfg)
        self.app.router.add_get('/y000000000000.cfg', self.yealink_config)
        self.app.router.add_get('/y{mac}.cfg', self.yealink_config)
        self.app.router.add_get('/tmp/{mac}.cfg', self.yealink_config)
        self.app.router.add_get('/Yealink/config/{mac}.cfg', self.yealink_config)
        self.app.router.add_get('/{mac}.boot', self.yealink_boot)

        # NetSapiens cfg endpoints (e.g., /cfg/44dbd2ab5806.cfg-text)
        self.app.router.add_get('/cfg/{mac}.cfg-text', self.netsapiens_cfg_text)
        self.app.router.add_get('/cfg/{mac}.cfg', self.netsapiens_cfg_text)
        self.app.router.add_get('/cfg/{mac}', self.netsapiens_cfg_text)

        # Grandstream endpoints (must be before generic patterns)
        self.app.router.add_get('/cfg{mac}', self.grandstream_config)
        self.app.router.add_get('/cfg{mac}.xml', self.grandstream_config)
        self.app.router.add_get('/gs_config.txt', self.grandstream_config)

        # Polycom endpoints (generic patterns last)
        self.app.router.add_get('/000000000000.cfg', self.polycom_config)
        self.app.router.add_get('/000000000000-phone.cfg', self.polycom_config)
        self.app.router.add_get('/000000000000-web.cfg', self.polycom_config)
        self.app.router.add_get('/sip.cfg', self.polycom_sip_cfg)
        self.app.router.add_get('/phone1.cfg', self.polycom_sip_cfg)
        self.app.router.add_get('/Config/reg-basic.cfg', self.polycom_config)
        self.app.router.add_get('/Config/reg-advanced.cfg', self.polycom_config)
        self.app.router.add_get('/{mac}.cfg', self.polycom_config)
        self.app.router.add_get('/{mac}-phone.cfg', self.polycom_config)

        # NetSapiens / NDP endpoints (matching your existing system)
        self.app.router.add_get('/ndp/adminlogin.php', self.netsapiens_admin_login)
        self.app.router.add_post('/ndp/adminlogin.php', self.netsapiens_admin_login_post)
        self.app.router.add_get('/ndp/', self.netsapiens_ndp)
        self.app.router.add_get('/ndp/device.php', self.netsapiens_device)
        self.app.router.add_post('/ndp/device.php', self.netsapiens_device_post)
        self.app.router.add_get('/ndp/config.php', self.netsapiens_config)
        self.app.router.add_get('/portal/', self.netsapiens_portal)
        self.app.router.add_get('/portal/login.php', self.netsapiens_portal_login)
        self.app.router.add_post('/portal/login.php', self.netsapiens_portal_login_post)

        # SiPbx endpoints (Snapcom core servers)
        self.app.router.add_get('/SiPbx/', self.sipbx_index)
        self.app.router.add_get('/SiPbx/login', self.sipbx_login)
        self.app.router.add_post('/SiPbx/login', self.sipbx_login_post)
        self.app.router.add_get('/SiPbx/adminlogin.php', self.sipbx_admin_login)
        self.app.router.add_post('/SiPbx/adminlogin.php', self.sipbx_admin_login_post)
        # Fake authenticated dashboard pages
        self.app.router.add_get('/SiPbx/dashboard', self.sipbx_dashboard)
        self.app.router.add_get('/SiPbx/dashboard/', self.sipbx_dashboard)
        self.app.router.add_get('/SiPbx/dashboard/users', self.sipbx_dashboard_users)
        self.app.router.add_get('/SiPbx/dashboard/trunks', self.sipbx_dashboard_trunks)
        self.app.router.add_get('/SiPbx/dashboard/cdr', self.sipbx_dashboard_cdr)
        self.app.router.add_get('/SiPbx/dashboard/settings', self.sipbx_dashboard_settings)
        self.app.router.add_post('/SiPbx/dashboard/settings', self.sipbx_dashboard_settings_post)
        self.app.router.add_get('/SiPbx/dashboard/billing', self.sipbx_dashboard_billing)
        # NDP fake dashboard
        self.app.router.add_get('/ndp/dashboard', self.ndp_dashboard)
        self.app.router.add_get('/ndp/dashboard/', self.ndp_dashboard)
        self.app.router.add_get('/ndp/dashboard/devices', self.ndp_dashboard_devices)
        self.app.router.add_get('/ndp/dashboard/users', self.ndp_dashboard_users)
        self.app.router.add_post('/ndp/dashboard/users', self.ndp_dashboard_users_post)
        self.app.router.add_get('/ndp/dashboard/config', self.ndp_dashboard_config)
        self.app.router.add_post('/ndp/dashboard/config', self.ndp_dashboard_config_post)
        self.app.router.add_get('/SiPbx/api/{path:.*}', self.sipbx_api)
        self.app.router.add_post('/SiPbx/api/{path:.*}', self.sipbx_api)
        self.app.router.add_get('/SiPbx/admin', self.sipbx_admin)
        self.app.router.add_get('/SiPbx/admin/', self.sipbx_admin)
        self.app.router.add_get('/SiPbx/provision/{path:.*}', self.sipbx_provision)
        self.app.router.add_get('/SiPbx/{path:.*}', self.sipbx_catch)

        # Generic provisioning
        self.app.router.add_get('/prov/{path:.*}', self.generic_provision)
        self.app.router.add_get('/provisioning/{path:.*}', self.generic_provision)
        self.app.router.add_get('/config/{path:.*}', self.generic_provision)

        # PHP shell honeypot - common webshell paths
        for shell_path in self.PHP_SHELL_PATHS:
            self.app.router.add_get(f'/{shell_path}', self.php_shell_page)
            self.app.router.add_post(f'/{shell_path}', self.php_shell_execute)
        # Catch .php requests with cmd/c/exec params
        self.app.router.add_get('/{path:.*\\.php}', self.php_catch)
        self.app.router.add_post('/{path:.*\\.php}', self.php_catch)

        # Catch-all for scanning attempts
        self.app.router.add_get('/{path:.*}', self.catch_all)
        self.app.router.add_post('/{path:.*}', self.catch_all)

    @web.middleware
    async def logging_middleware(self, request, handler):
        """Log all requests"""
        source_ip = request.remote
        # Check for X-Forwarded-For in case of reverse proxy
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': source_ip,
            'source_port': 0,
            'method': request.method,
            'uri': str(request.url),
            'path': request.path,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'headers': dict(request.headers),
            'query_string': request.query_string,
            'protocol': 'HTTP',
            'honeypot_type': 'provisioning'
        }

        # Try to read body for POST requests
        if request.method == 'POST':
            try:
                body = await request.text()
                log_entry['body'] = body[:2000]  # Truncate
            except:
                pass

        if self.log_callback:
            asyncio.create_task(self.log_callback(log_entry))

        logger.info(f"HTTP {request.method} {request.path} from {source_ip}")

        try:
            return await handler(request)
        except web.HTTPException as e:
            return e

    async def polycom_config(self, request):
        """Fake Polycom configuration file with realistic fake credentials"""
        mac = self._extract_mac(request)
        creds = self._generate_fake_credentials(mac)

        config = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!-- Polycom Configuration for {creds['mac_formatted']} -->
<PHONE_CONFIG>
<DEVICE_INFO
    device.set="1"
    device.prov.serverName="{creds['sip_server']}"
    device.prov.serverType="FTP"
/>
<REGISTRATION
    reg.1.displayName="{creds['display_name']}"
    reg.1.address="{creds['extension']}"
    reg.1.label="{creds['extension']}"
    reg.1.type="private"
    reg.1.auth.userId="{creds['auth_user']}"
    reg.1.auth.password="{creds['password']}"
    reg.1.server.1.address="{creds['sip_server']}"
    reg.1.server.1.port="5060"
    reg.1.server.1.transport="UDPOnly"
    reg.1.server.1.expires="3600"
    reg.1.server.2.address="{creds['proxy_server']}"
    reg.1.server.2.port="5060"
/>
<VOIP_CONFIG
    voIpProt.server.1.address="{creds['sip_server']}"
    voIpProt.server.1.port="5060"
    voIpProt.SIP.outboundProxy.address="{creds['proxy_server']}"
    voIpProt.SIP.outboundProxy.port="5060"
/>
<CALL_SETTINGS
    call.autoOffHook.enabled="1"
    call.autoAnswer.SIP="0"
/>
</PHONE_CONFIG>
"""
        await self._log_credentials_sent(request, creds, 'polycom')
        return web.Response(text=config, content_type='text/xml')

    async def polycom_sip_cfg(self, request):
        """Fake Polycom SIP config"""
        mac = self._extract_mac(request)
        creds = self._generate_fake_credentials(mac)

        config = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sip>
    <outboundProxy voIpProt.SIP.outboundProxy.address="{creds['proxy_server']}"/>
    <server voIpProt.server.1.address="{creds['sip_server']}"/>
    <reg reg.1.auth.userId="{creds['auth_user']}" reg.1.auth.password="{creds['password']}"/>
</sip>
"""
        await self._log_credentials_sent(request, creds, 'polycom_sip')
        return web.Response(text=config, content_type='text/xml')

    async def yealink_config(self, request):
        """Fake Yealink configuration file with realistic fake credentials"""
        mac = self._extract_mac(request)
        creds = self._generate_fake_credentials(mac)

        config = f"""#!version:1.0.0.1
## Yealink Configuration for {creds['mac_formatted']}
## Generated: {datetime.utcnow().isoformat()}

###### Account Settings ######
account.1.enable = 1
account.1.label = {creds['extension']}
account.1.display_name = {creds['display_name']}
account.1.auth_name = {creds['auth_user']}
account.1.user_name = {creds['extension']}
account.1.password = {creds['password']}
account.1.sip_server.1.address = {creds['sip_server']}
account.1.sip_server.1.port = 5060
account.1.sip_server.1.transport_type = 0
account.1.sip_server.1.expires = 3600
account.1.outbound_proxy_enable = 1
account.1.outbound_proxy.1.address = {creds['proxy_server']}
account.1.outbound_proxy.1.port = 5060

###### Phone Settings ######
phone_setting.ring_type = Ring1.wav
phone_setting.backlight_time = 30
auto_provision.mode = 6
auto_provision.server.url = http://{creds['sip_server']}/provision/

###### Network Settings ######
network.dhcp_enable = 1
network.vlan.internet_port_enable = 0
"""
        await self._log_credentials_sent(request, creds, 'yealink')
        return web.Response(text=config, content_type='text/plain')

    async def yealink_boot(self, request):
        """Fake Yealink boot file"""
        mac = self._extract_mac(request)
        config = f"""#!version:1.0.0.1
## Yealink Boot Config
include:config/{mac.lower()}.cfg
overwrite_mode = 1
"""
        return web.Response(text=config, content_type='text/plain')

    async def grandstream_config(self, request):
        """Fake Grandstream configuration with realistic fake credentials"""
        mac = self._extract_mac(request)
        creds = self._generate_fake_credentials(mac)

        # Grandstream uses P-codes for configuration
        config = f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- Grandstream Configuration for {creds['mac_formatted']} -->
<gs_provision version="1">
<config version="1">
<!-- Account 1 Settings -->
<P270>{creds['extension']}</P270>
<P271>{creds['auth_user']}</P271>
<P272>{creds['password']}</P272>
<P47>{creds['sip_server']}</P47>
<P48>5060</P48>
<P2312>{creds['proxy_server']}</P2312>
<P2313>5060</P2313>
<P3>{creds['display_name']}</P3>
<P35>100</P35>
<!-- Registration Settings -->
<P81>1</P81>
<P82>3600</P82>
<!-- Audio Settings -->
<P57>0</P57>
<P58>2</P58>
<!-- Provisioning -->
<P192>http://{creds['sip_server']}/gs/cfg{{MAC}}</P192>
<P237>1</P237>
</config>
</gs_provision>
"""
        await self._log_credentials_sent(request, creds, 'grandstream')
        return web.Response(text=config, content_type='text/xml')

    async def netsapiens_cfg_text(self, request):
        """Fake NetSapiens cfg-text provisioning format"""
        mac = self._extract_mac(request)
        creds = self._generate_fake_credentials(mac)

        # NetSapiens uses a simple key=value format
        config = f"""# NetSapiens Device Configuration
# MAC: {creds['mac_formatted']}
# Generated: {datetime.utcnow().isoformat()}

# SIP Account Settings
sip_account_1_enabled=yes
sip_account_1_username={creds['extension']}
sip_account_1_auth_name={creds['auth_user']}
sip_account_1_password={creds['password']}
sip_account_1_display_name={creds['display_name']}
sip_account_1_registrar={creds['sip_server']}
sip_account_1_registrar_port=5060
sip_account_1_proxy={creds['proxy_server']}
sip_account_1_proxy_port=5060
sip_account_1_transport=udp
sip_account_1_register_expires=3600

# Voicemail
voicemail_number=*97
voicemail_enabled=yes

# Network Settings
network_dhcp=yes
network_vlan_enabled=no

# Provisioning
provision_server=http://{creds['sip_server']}/cfg/
provision_interval=3600

# Phone Settings
phone_language=English
phone_timezone=America/Chicago
phone_date_format=M/D/Y
phone_time_format=12hr

# Audio Settings
audio_codec_1=G.711u
audio_codec_2=G.711a
audio_codec_3=G.729

# Features
feature_call_waiting=yes
feature_dnd=no
feature_forwarding=yes
"""
        await self._log_credentials_sent(request, creds, 'netsapiens')
        return web.Response(text=config, content_type='text/plain')

    async def netsapiens_admin_login(self, request):
        """Fake NetSapiens admin login page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>NDP Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
        .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 30px; font-size: 24px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #666; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .footer { text-align: center; margin-top: 20px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Device Provisioning Admin</h1>
        <form method="POST" action="/ndp/adminlogin.php">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="footer">NetSapiens Device Portal v4.2</div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def netsapiens_admin_login_post(self, request):
        """Capture login attempts with exciting responses"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        username = ''
        password = ''
        try:
            data = await request.post()
            username = data.get('username', '')
            password = data.get('password', '')
            logger.warning(f"CAPTURED CREDENTIALS - NDP Admin: {username}:{password} from {source_ip}")

            # Log credential capture specifically
            if self.log_callback:
                cred_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'CREDENTIAL_CAPTURE',
                    'uri': '/ndp/adminlogin.php',
                    'credentials': {
                        'username': username,
                        'password': password,
                        'type': 'ndp_admin'
                    },
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(cred_entry))
        except:
            pass

        # Always "let them in" to the fake dashboard
        if username and password:
            logger.warning(f"HONEYPOT LOGIN SUCCESS - NDP: {username} from {source_ip} - redirecting to fake dashboard")
            if self.log_callback:
                login_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'HONEYPOT_LOGIN',
                    'uri': '/ndp/adminlogin.php',
                    'credentials': {
                        'username': username,
                        'password': password,
                        'type': 'ndp_admin_login_success'
                    },
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(login_entry))
            raise web.HTTPFound('/ndp/dashboard')

        # Exciting "almost worked" responses
        responses = [
            ('Authentication Failed', 'Invalid username or password. This attempt has been logged.', 'error'),
            ('Account Suspended', 'This administrator account has been suspended. Contact support.', 'warning'),
            ('Session Conflict', 'Another admin session is active. Only one session allowed per account.', 'warning'),
            ('Database Timeout', 'Authentication server timeout. Please try again.', 'warning'),
            ('IP Restricted', f'Access from IP {source_ip} requires VPN. Connect to corporate VPN first.', 'info'),
            ('Password Expired', 'Password has expired. Contact system administrator for reset.', 'warning'),
            ('License Error', 'Admin license limit reached. Upgrade required for additional admin accounts.', 'error'),
        ]

        title, message, alert_type = random.choice(responses)
        colors = {'error': ('#ffe6e6', '#cc0000'), 'warning': ('#fff3cd', '#856404'), 'info': ('#cce5ff', '#004085')}
        bg_color, text_color = colors.get(alert_type, colors['error'])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>NDP Admin - {title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }}
        .login-container {{ max-width: 400px; margin: 80px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; margin-bottom: 20px; font-size: 24px; }}
        .alert {{ background: {bg_color}; color: {text_color}; padding: 15px; border-radius: 4px; margin-bottom: 20px; border-left: 4px solid {text_color}; }}
        .alert h4 {{ margin: 0 0 5px 0; font-size: 14px; }}
        .alert p {{ margin: 0; font-size: 13px; }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; color: #666; }}
        input[type="text"], input[type="password"] {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #0056b3; }}
        .footer {{ text-align: center; margin-top: 20px; color: #999; font-size: 12px; }}
        .log-notice {{ text-align: center; margin-top: 15px; padding: 8px; background: #f8f9fa; border-radius: 4px; font-size: 11px; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Device Provisioning Admin</h1>
        <div class="alert">
            <h4>{title}</h4>
            <p>{message}</p>
        </div>
        <form method="POST" action="/ndp/adminlogin.php">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" value="{username}" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Retry Login</button>
        </form>
        <div class="log-notice">
            Attempt logged: {source_ip} @ {datetime.utcnow().strftime('%H:%M:%S')} UTC
        </div>
        <div class="footer">NetSapiens Device Portal v4.2.1</div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def netsapiens_ndp(self, request):
        """Redirect to admin login"""
        raise web.HTTPFound('/ndp/adminlogin.php')

    async def netsapiens_device(self, request):
        """Fake device registration page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Device Registration</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }
        .container { max-width: 600px; margin: 50px auto; background: white; padding: 40px; border-radius: 8px; }
        h1 { color: #333; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { padding: 12px 24px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Device Registration</h1>
        <form method="POST" action="/ndp/device.php">
            <div class="form-group">
                <label>MAC Address</label>
                <input type="text" name="mac" placeholder="AA:BB:CC:DD:EE:FF" required>
            </div>
            <div class="form-group">
                <label>Device Type</label>
                <select name="device_type">
                    <option>Polycom VVX 400</option>
                    <option>Polycom VVX 500</option>
                    <option>Yealink T46S</option>
                    <option>Yealink T48S</option>
                    <option>Grandstream GXP2170</option>
                </select>
            </div>
            <div class="form-group">
                <label>Extension</label>
                <input type="text" name="extension" required>
            </div>
            <div class="form-group">
                <label>SIP Password</label>
                <input type="password" name="sip_password" required>
            </div>
            <button type="submit">Register Device</button>
        </form>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def netsapiens_device_post(self, request):
        """Capture device registration attempts"""
        try:
            data = await request.post()
            logger.warning(f"CAPTURED DEVICE REG - MAC: {data.get('mac')}, Ext: {data.get('extension')}, Pass: {data.get('sip_password')}")

            if self.log_callback:
                cred_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': request.remote,
                    'source_port': 0,
                    'method': 'CREDENTIAL_CAPTURE',
                    'uri': '/ndp/device.php',
                    'credentials': {
                        'mac': data.get('mac', ''),
                        'extension': data.get('extension', ''),
                        'sip_password': data.get('sip_password', ''),
                        'device_type': data.get('device_type', ''),
                        'type': 'device_registration'
                    },
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(cred_entry))
        except:
            pass

        return web.Response(text="<html><body><h1>Registration Failed</h1><p>Device not authorized.</p></body></html>", content_type='text/html')

    async def netsapiens_config(self, request):
        """Fake config endpoint"""
        return web.Response(text="Invalid request", status=403)

    async def netsapiens_portal(self, request):
        """Redirect to portal login"""
        raise web.HTTPFound('/portal/login.php')

    async def netsapiens_portal_login(self, request):
        """User portal login"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>User Portal Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; padding: 20px; min-height: 100vh; }
        .login-container { max-width: 400px; margin: 80px auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
        h1 { color: #333; margin-bottom: 10px; }
        .subtitle { color: #666; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #666; font-weight: 500; }
        input { width: 100%; padding: 14px; border: 2px solid #e0e0e0; border-radius: 8px; box-sizing: border-box; font-size: 16px; }
        input:focus { border-color: #667eea; outline: none; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; }
        button:hover { opacity: 0.9; }
        .footer { text-align: center; margin-top: 20px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>User Portal</h1>
        <p class="subtitle">Access your phone settings and voicemail</p>
        <form method="POST" action="/portal/login.php">
            <div class="form-group">
                <label>Phone Number or Extension</label>
                <input type="text" name="username" placeholder="e.g., 1001 or 5551234567" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">Powered by NetSapiens NDP</div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def netsapiens_portal_login_post(self, request):
        """Capture portal login attempts"""
        try:
            data = await request.post()
            username = data.get('username', '')
            password = data.get('password', '')
            logger.warning(f"CAPTURED CREDENTIALS - Portal: {username}:{password}")

            if self.log_callback:
                cred_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': request.remote,
                    'source_port': 0,
                    'method': 'CREDENTIAL_CAPTURE',
                    'uri': '/portal/login.php',
                    'credentials': {
                        'username': username,
                        'password': password,
                        'type': 'user_portal'
                    },
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(cred_entry))
        except:
            pass

        html = """<!DOCTYPE html>
<html>
<head><title>Login Failed</title></head>
<body style="font-family: Arial; padding: 50px; text-align: center;">
<h1>Login Failed</h1>
<p>Invalid username or password. <a href="/portal/login.php">Try again</a></p>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    # SiPbx endpoints (Snapcom impersonation)
    async def sipbx_index(self, request):
        """SiPbx main page - redirect to login"""
        raise web.HTTPFound('/SiPbx/login')

    async def sipbx_login(self, request):
        """SiPbx login page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>SiPbx - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-box { background: #16213e; padding: 40px; border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.5); width: 100%; max-width: 400px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #e94560; font-size: 32px; letter-spacing: 2px; }
        .logo p { color: #a0a0a0; font-size: 14px; margin-top: 5px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #a0a0a0; margin-bottom: 8px; font-size: 14px; }
        .form-group input { width: 100%; padding: 14px 16px; background: #0f0f23; border: 2px solid #2a2a4a; border-radius: 8px; color: #fff; font-size: 16px; transition: border-color 0.3s; }
        .form-group input:focus { outline: none; border-color: #e94560; }
        .form-group input::placeholder { color: #505070; }
        .btn-login { width: 100%; padding: 14px; background: linear-gradient(135deg, #e94560, #c23a51); border: none; border-radius: 8px; color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        .btn-login:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(233, 69, 96, 0.3); }
        .footer { text-align: center; margin-top: 30px; color: #505070; font-size: 12px; }
        .server-info { text-align: center; margin-top: 15px; padding: 10px; background: #0f0f23; border-radius: 8px; }
        .server-info span { color: #4ade80; font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <h1>SiPbx</h1>
            <p>Unified Communications Platform</p>
        </div>
        <form method="POST" action="/SiPbx/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Enter your username" required autocomplete="off">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn-login">Sign In</button>
        </form>
        <div class="server-info">
            <span>core1-stl.snapcom.com</span>
        </div>
        <div class="footer">
            &copy; 2024 SiPbx v5.0.0 | Snapcom
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_login_post(self, request):
        """Capture SiPbx login attempts"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        try:
            data = await request.post()
            username = data.get('username', '')
            password = data.get('password', '')
            logger.warning(f"CAPTURED CREDENTIALS - SiPbx: {username}:{password} from {source_ip}")

            if self.log_callback:
                cred_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'CREDENTIAL_CAPTURE',
                    'uri': '/SiPbx/login',
                    'credentials': {
                        'username': username,
                        'password': password,
                        'type': 'sipbx_admin'
                    },
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(cred_entry))
        except:
            pass

        # Return login failed
        html = """<!DOCTYPE html>
<html>
<head>
    <title>SiPbx - Login Failed</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-box { background: #16213e; padding: 40px; border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.5); width: 100%; max-width: 400px; }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #e94560; font-size: 32px; letter-spacing: 2px; }
        .error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #a0a0a0; margin-bottom: 8px; font-size: 14px; }
        .form-group input { width: 100%; padding: 14px 16px; background: #0f0f23; border: 2px solid #2a2a4a; border-radius: 8px; color: #fff; font-size: 16px; }
        .form-group input:focus { outline: none; border-color: #e94560; }
        .btn-login { width: 100%; padding: 14px; background: linear-gradient(135deg, #e94560, #c23a51); border: none; border-radius: 8px; color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; }
        .footer { text-align: center; margin-top: 30px; color: #505070; font-size: 12px; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <h1>SiPbx</h1>
        </div>
        <div class="error">Invalid username or password</div>
        <form method="POST" action="/SiPbx/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autocomplete="off">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn-login">Sign In</button>
        </form>
        <div class="footer">&copy; 2024 SiPbx v5.0.0</div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_admin_login(self, request):
        """SiPbx admin login page - enticing design"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>SiPbx Admin Console</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { width: 100%; max-width: 420px; }
        .login-box { background: rgba(22, 33, 62, 0.95); padding: 40px; border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.5), 0 0 100px rgba(233, 69, 96, 0.1); border: 1px solid rgba(233, 69, 96, 0.2); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { color: #e94560; font-size: 36px; letter-spacing: 3px; text-shadow: 0 0 20px rgba(233, 69, 96, 0.5); }
        .logo .admin-badge { display: inline-block; background: linear-gradient(135deg, #e94560, #ff6b6b); color: white; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; letter-spacing: 1px; margin-top: 10px; }
        .logo p { color: #a0a0a0; font-size: 14px; margin-top: 8px; }
        .security-notice { background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.3); color: #fbbf24; padding: 12px; border-radius: 8px; margin-bottom: 25px; font-size: 12px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #a0a0a0; margin-bottom: 8px; font-size: 14px; font-weight: 500; }
        .form-group input { width: 100%; padding: 14px 16px; background: #0f0f23; border: 2px solid #2a2a4a; border-radius: 8px; color: #fff; font-size: 16px; transition: all 0.3s; }
        .form-group input:focus { outline: none; border-color: #e94560; box-shadow: 0 0 20px rgba(233, 69, 96, 0.2); }
        .form-group input::placeholder { color: #505070; }
        .btn-login { width: 100%; padding: 14px; background: linear-gradient(135deg, #e94560, #c23a51); border: none; border-radius: 8px; color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; text-transform: uppercase; letter-spacing: 1px; }
        .btn-login:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(233, 69, 96, 0.4); }
        .server-info { display: flex; justify-content: space-between; margin-top: 25px; padding: 15px; background: #0f0f23; border-radius: 8px; }
        .server-info .item { text-align: center; }
        .server-info .label { color: #505070; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; }
        .server-info .value { color: #4ade80; font-family: monospace; font-size: 12px; margin-top: 4px; }
        .footer { text-align: center; margin-top: 20px; color: #505070; font-size: 11px; }
        .pulse { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-box">
            <div class="logo">
                <h1>SiPbx</h1>
                <span class="admin-badge">ADMIN CONSOLE</span>
                <p>System Administration Portal</p>
            </div>
            <div class="security-notice">
                <span class="pulse">&#128274;</span> Secure Connection Required - All access is logged
            </div>
            <form method="POST" action="/SiPbx/adminlogin.php">
                <div class="form-group">
                    <label>Administrator Username</label>
                    <input type="text" name="username" placeholder="admin" required autocomplete="off">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="Enter admin password" required>
                </div>
                <button type="submit" class="btn-login">Authenticate</button>
            </form>
            <div class="server-info">
                <div class="item">
                    <div class="label">Server</div>
                    <div class="value">core1-stl</div>
                </div>
                <div class="item">
                    <div class="label">Status</div>
                    <div class="value" style="color: #4ade80;">● Online</div>
                </div>
                <div class="item">
                    <div class="label">Version</div>
                    <div class="value">v5.2.1</div>
                </div>
            </div>
            <div class="footer">
                &copy; 2024 Snapcom SiPbx | Enterprise VoIP Platform
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_admin_login_post(self, request):
        """Capture SiPbx admin login attempts - sometimes let them 'in' to fake dashboard"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        username = ''
        password = ''
        try:
            data = await request.post()
            username = data.get('username', '')
            password = data.get('password', '')
            logger.warning(f"CAPTURED ADMIN CREDS - SiPbx Admin: {username}:{password} from {source_ip}")

            if self.log_callback:
                cred_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'CREDENTIAL_CAPTURE',
                    'uri': '/SiPbx/adminlogin.php',
                    'credentials': {
                        'username': username,
                        'password': password,
                        'type': 'sipbx_admin_console'
                    },
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(cred_entry))
        except:
            pass

        # Always "let them in" to the fake dashboard
        if username and password:
            logger.warning(f"HONEYPOT LOGIN SUCCESS - SiPbx: {username} from {source_ip} - redirecting to fake dashboard")
            if self.log_callback:
                login_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'HONEYPOT_LOGIN',
                    'uri': '/SiPbx/adminlogin.php',
                    'credentials': {
                        'username': username,
                        'password': password,
                        'type': 'sipbx_admin_login_success'
                    },
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(login_entry))
            # Redirect to fake dashboard
            raise web.HTTPFound('/SiPbx/dashboard')

        # Show exciting "almost worked" responses to keep them trying
        responses = [
            ('Account locked', 'Too many failed attempts. Account temporarily locked. Try again in 5 minutes.', '#ef4444'),
            ('Authentication Failed', 'Invalid credentials. Attempt logged.', '#ef4444'),
            ('Session Expired', 'Your session token has expired. Please try again.', '#f59e0b'),
            ('2FA Required', 'Two-factor authentication required for this account. Check your authenticator app.', '#3b82f6'),
            ('IP Not Whitelisted', f'Access from {source_ip} is not authorized. Contact system administrator.', '#f59e0b'),
            ('Maintenance Mode', 'Admin console is currently in maintenance mode. Please try again later.', '#8b5cf6'),
        ]

        title, message, color = random.choice(responses)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SiPbx Admin - {title}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .login-box {{ background: rgba(22, 33, 62, 0.95); padding: 40px; border-radius: 16px; box-shadow: 0 25px 50px rgba(0,0,0,0.5); width: 100%; max-width: 420px; border: 1px solid rgba(233, 69, 96, 0.2); }}
        .logo {{ text-align: center; margin-bottom: 20px; }}
        .logo h1 {{ color: #e94560; font-size: 32px; letter-spacing: 2px; }}
        .alert {{ background: {color}22; border: 1px solid {color}; color: {color}; padding: 16px; border-radius: 8px; margin-bottom: 25px; text-align: center; }}
        .alert h3 {{ margin-bottom: 8px; font-size: 16px; }}
        .alert p {{ font-size: 13px; opacity: 0.9; }}
        .form-group {{ margin-bottom: 20px; }}
        .form-group label {{ display: block; color: #a0a0a0; margin-bottom: 8px; font-size: 14px; }}
        .form-group input {{ width: 100%; padding: 14px 16px; background: #0f0f23; border: 2px solid #2a2a4a; border-radius: 8px; color: #fff; font-size: 16px; }}
        .form-group input:focus {{ outline: none; border-color: #e94560; }}
        .btn-login {{ width: 100%; padding: 14px; background: linear-gradient(135deg, #e94560, #c23a51); border: none; border-radius: 8px; color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; }}
        .btn-login:hover {{ opacity: 0.9; }}
        .footer {{ text-align: center; margin-top: 25px; color: #505070; font-size: 11px; }}
        .attempt-info {{ text-align: center; margin-top: 15px; padding: 10px; background: #0f0f23; border-radius: 8px; font-size: 11px; color: #505070; }}
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <h1>SiPbx</h1>
        </div>
        <div class="alert">
            <h3>{title}</h3>
            <p>{message}</p>
        </div>
        <form method="POST" action="/SiPbx/adminlogin.php">
            <div class="form-group">
                <label>Administrator Username</label>
                <input type="text" name="username" value="{username}" required autocomplete="off">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn-login">Retry Authentication</button>
        </form>
        <div class="attempt-info">
            Last attempt from {source_ip} logged at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
        </div>
        <div class="footer">&copy; 2024 Snapcom SiPbx v5.2.1</div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_admin(self, request):
        """SiPbx admin - require auth"""
        raise web.HTTPFound('/SiPbx/adminlogin.php')

    async def sipbx_api(self, request):
        """SiPbx API endpoint - capture API probing"""
        path = request.match_info.get('path', '')

        # Log API probe
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        logger.info(f"SiPbx API probe from {source_ip}: /SiPbx/api/{path}")

        # Return API error response
        return web.json_response({
            'error': 'Unauthorized',
            'code': 401,
            'message': 'Authentication required',
            'server': 'SiPbx/5.0.0'
        }, status=401)

    async def sipbx_provision(self, request):
        """SiPbx provisioning endpoint"""
        path = request.match_info.get('path', '')

        # Return fake provisioning config
        config = f"""<?xml version="1.0" encoding="UTF-8"?>
<sipbx-provision version="5.0">
    <server>core1-stl.snapcom.com</server>
    <device>{path}</device>
    <error>Device not registered</error>
</sipbx-provision>
"""
        return web.Response(text=config, content_type='text/xml', status=404)

    async def sipbx_catch(self, request):
        """Catch-all for other SiPbx paths"""
        path = request.match_info.get('path', '')

        # Redirect unknown paths to login
        if not path or path in ['index', 'home', 'dashboard']:
            raise web.HTTPFound('/SiPbx/login')

        return web.Response(text="Not Found", status=404)

    # ============== FAKE DASHBOARD HANDLERS ==============

    def _dashboard_base_style(self):
        """Common dashboard styles"""
        return """
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; }
        .sidebar { position: fixed; left: 0; top: 0; width: 250px; height: 100vh; background: #16213e; padding: 20px 0; border-right: 1px solid #2a2a4a; }
        .sidebar h2 { color: #e94560; padding: 0 20px 20px; font-size: 22px; border-bottom: 1px solid #2a2a4a; margin-bottom: 20px; }
        .sidebar nav a { display: block; padding: 12px 20px; color: #a0a0a0; text-decoration: none; border-left: 3px solid transparent; transition: all 0.2s; }
        .sidebar nav a:hover, .sidebar nav a.active { background: rgba(233, 69, 96, 0.1); color: #e94560; border-left-color: #e94560; }
        .sidebar nav a .icon { margin-right: 10px; }
        .main { margin-left: 250px; padding: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #2a2a4a; }
        .header h1 { font-size: 24px; color: #fff; }
        .header .user-info { color: #a0a0a0; font-size: 14px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #16213e; padding: 25px; border-radius: 12px; border: 1px solid #2a2a4a; }
        .stat-card .label { color: #a0a0a0; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }
        .stat-card .value { font-size: 32px; font-weight: 600; color: #fff; margin-top: 8px; }
        .stat-card .change { font-size: 12px; margin-top: 5px; }
        .stat-card .change.up { color: #4ade80; }
        .stat-card .change.down { color: #ef4444; }
        .card { background: #16213e; border-radius: 12px; border: 1px solid #2a2a4a; margin-bottom: 20px; }
        .card-header { padding: 20px; border-bottom: 1px solid #2a2a4a; font-weight: 600; display: flex; justify-content: space-between; align-items: center; }
        .card-body { padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #2a2a4a; }
        th { color: #a0a0a0; font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
        tr:hover { background: rgba(233, 69, 96, 0.05); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
        .badge-success { background: rgba(74, 222, 128, 0.2); color: #4ade80; }
        .badge-warning { background: rgba(251, 191, 36, 0.2); color: #fbbf24; }
        .badge-danger { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s; }
        .btn-primary { background: #e94560; color: white; }
        .btn-primary:hover { background: #d13a54; }
        .btn-secondary { background: #2a2a4a; color: #e0e0e0; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #a0a0a0; font-size: 14px; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 12px; background: #0f0f23; border: 1px solid #2a2a4a; border-radius: 6px; color: #fff; font-size: 14px; }
        .form-group input:focus, .form-group select:focus { outline: none; border-color: #e94560; }
        """

    async def _log_dashboard_action(self, request, action, details=None):
        """Log any dashboard action"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        logger.warning(f"DASHBOARD ACTION - {action} from {source_ip}: {details}")

        if self.log_callback:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_ip,
                'source_port': 0,
                'method': 'DASHBOARD_ACTION',
                'uri': request.path,
                'action': action,
                'details': details,
                'user_agent': request.headers.get('User-Agent', ''),
                'protocol': 'HTTP',
                'honeypot_type': 'provisioning'
            }
            asyncio.create_task(self.log_callback(entry))

    async def sipbx_dashboard(self, request):
        """Fake SiPbx admin dashboard"""
        await self._log_dashboard_action(request, 'VIEW_DASHBOARD', {'page': 'main'})

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SiPbx Admin Dashboard</title>
    <style>{self._dashboard_base_style()}</style>
</head>
<body>
    <div class="sidebar">
        <h2>SiPbx Admin</h2>
        <nav>
            <a href="/SiPbx/dashboard" class="active"><span class="icon">📊</span> Dashboard</a>
            <a href="/SiPbx/dashboard/users"><span class="icon">👥</span> Users & Extensions</a>
            <a href="/SiPbx/dashboard/trunks"><span class="icon">📞</span> SIP Trunks</a>
            <a href="/SiPbx/dashboard/cdr"><span class="icon">📋</span> Call Records</a>
            <a href="/SiPbx/dashboard/billing"><span class="icon">💳</span> Billing</a>
            <a href="/SiPbx/dashboard/settings"><span class="icon">⚙️</span> System Settings</a>
            <a href="/SiPbx/adminlogin.php" style="margin-top: 30px; color: #ef4444;"><span class="icon">🚪</span> Logout</a>
        </nav>
    </div>
    <div class="main">
        <div class="header">
            <h1>System Dashboard</h1>
            <div class="user-info">Logged in as: admin | Server: core1-stl.snapcom.com</div>
        </div>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Active Extensions</div>
                <div class="value">2,847</div>
                <div class="change up">↑ 12% from last month</div>
            </div>
            <div class="stat-card">
                <div class="label">Active Calls</div>
                <div class="value">156</div>
                <div class="change up">↑ 23 in last hour</div>
            </div>
            <div class="stat-card">
                <div class="label">SIP Trunks</div>
                <div class="value">24</div>
                <div class="change">All operational</div>
            </div>
            <div class="stat-card">
                <div class="label">Monthly Revenue</div>
                <div class="value">$48,392</div>
                <div class="change up">↑ 8% from last month</div>
            </div>
        </div>
        <div class="card">
            <div class="card-header">Recent Activity</div>
            <div class="card-body">
                <table>
                    <thead><tr><th>Time</th><th>Event</th><th>User</th><th>Details</th></tr></thead>
                    <tbody>
                        <tr><td>2 min ago</td><td>Extension Created</td><td>admin</td><td>Ext 1847 - John Smith</td></tr>
                        <tr><td>15 min ago</td><td>Trunk Modified</td><td>admin</td><td>Updated outbound routes</td></tr>
                        <tr><td>1 hour ago</td><td>Bulk Import</td><td>system</td><td>Imported 50 DIDs</td></tr>
                        <tr><td>3 hours ago</td><td>Config Backup</td><td>cron</td><td>Daily backup completed</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_dashboard_users(self, request):
        """Fake users list with enticing data"""
        await self._log_dashboard_action(request, 'VIEW_USERS', {'page': 'users_list'})

        # Generate fake users
        fake_users = [
            ('1001', 'John Smith', 'jsmith', 'Acme Corp', 'active', '$45.00'),
            ('1002', 'Sarah Johnson', 'sjohnson', 'Acme Corp', 'active', '$45.00'),
            ('1003', 'Mike Williams', 'mwilliams', 'TechStart Inc', 'active', '$35.00'),
            ('1004', 'Emily Davis', 'edavis', 'TechStart Inc', 'active', '$35.00'),
            ('1005', 'Robert Brown', 'rbrown', 'Global Services', 'suspended', '$55.00'),
            ('1006', 'Lisa Anderson', 'landerson', 'Global Services', 'active', '$55.00'),
            ('1007', 'David Wilson', 'dwilson', 'Smith & Co', 'active', '$40.00'),
            ('1008', 'Jennifer Taylor', 'jtaylor', 'Smith & Co', 'active', '$40.00'),
        ]

        rows = ""
        for ext, name, user, company, status, rate in fake_users:
            badge = 'badge-success' if status == 'active' else 'badge-danger'
            rows += f"<tr><td>{ext}</td><td>{name}</td><td>{user}</td><td>{company}</td><td><span class='badge {badge}'>{status}</span></td><td>{rate}</td><td><button class='btn btn-secondary'>Edit</button></td></tr>"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Users & Extensions - SiPbx</title>
    <style>{self._dashboard_base_style()}</style>
</head>
<body>
    <div class="sidebar">
        <h2>SiPbx Admin</h2>
        <nav>
            <a href="/SiPbx/dashboard"><span class="icon">📊</span> Dashboard</a>
            <a href="/SiPbx/dashboard/users" class="active"><span class="icon">👥</span> Users & Extensions</a>
            <a href="/SiPbx/dashboard/trunks"><span class="icon">📞</span> SIP Trunks</a>
            <a href="/SiPbx/dashboard/cdr"><span class="icon">📋</span> Call Records</a>
            <a href="/SiPbx/dashboard/billing"><span class="icon">💳</span> Billing</a>
            <a href="/SiPbx/dashboard/settings"><span class="icon">⚙️</span> System Settings</a>
        </nav>
    </div>
    <div class="main">
        <div class="header">
            <h1>Users & Extensions</h1>
            <button class="btn btn-primary">+ Add User</button>
        </div>
        <div class="card">
            <div class="card-header">
                <span>All Users (2,847 total)</span>
                <input type="text" placeholder="Search users..." style="padding: 8px 12px; background: #0f0f23; border: 1px solid #2a2a4a; border-radius: 6px; color: #fff;">
            </div>
            <div class="card-body">
                <table>
                    <thead><tr><th>Extension</th><th>Name</th><th>Username</th><th>Company</th><th>Status</th><th>Rate</th><th>Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_dashboard_trunks(self, request):
        """Fake SIP trunks page"""
        await self._log_dashboard_action(request, 'VIEW_TRUNKS', {'page': 'sip_trunks'})

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SIP Trunks - SiPbx</title>
    <style>{self._dashboard_base_style()}</style>
</head>
<body>
    <div class="sidebar">
        <h2>SiPbx Admin</h2>
        <nav>
            <a href="/SiPbx/dashboard"><span class="icon">📊</span> Dashboard</a>
            <a href="/SiPbx/dashboard/users"><span class="icon">👥</span> Users & Extensions</a>
            <a href="/SiPbx/dashboard/trunks" class="active"><span class="icon">📞</span> SIP Trunks</a>
            <a href="/SiPbx/dashboard/cdr"><span class="icon">📋</span> Call Records</a>
            <a href="/SiPbx/dashboard/billing"><span class="icon">💳</span> Billing</a>
            <a href="/SiPbx/dashboard/settings"><span class="icon">⚙️</span> System Settings</a>
        </nav>
    </div>
    <div class="main">
        <div class="header">
            <h1>SIP Trunks</h1>
            <button class="btn btn-primary">+ Add Trunk</button>
        </div>
        <div class="card">
            <div class="card-body">
                <table>
                    <thead><tr><th>Trunk Name</th><th>Provider</th><th>Host</th><th>Username</th><th>Channels</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td>Primary Outbound</td><td>Bandwidth</td><td>sip.bandwidth.com</td><td>snapcom_prod</td><td>100</td><td><span class="badge badge-success">Online</span></td></tr>
                        <tr><td>Backup Outbound</td><td>Telnyx</td><td>sip.telnyx.com</td><td>snap_backup</td><td>50</td><td><span class="badge badge-success">Online</span></td></tr>
                        <tr><td>International</td><td>VoIP.ms</td><td>chicago.voip.ms</td><td>snapcom_intl</td><td>25</td><td><span class="badge badge-success">Online</span></td></tr>
                        <tr><td>Toll-Free Inbound</td><td>Bandwidth</td><td>sip.bandwidth.com</td><td>snap_tollfree</td><td>200</td><td><span class="badge badge-success">Online</span></td></tr>
                        <tr><td>E911 Trunk</td><td>Intrado</td><td>e911.intrado.com</td><td>snap_e911</td><td>10</td><td><span class="badge badge-warning">Standby</span></td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_dashboard_cdr(self, request):
        """Fake call detail records"""
        await self._log_dashboard_action(request, 'VIEW_CDR', {'page': 'call_records'})

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Call Records - SiPbx</title>
    <style>{self._dashboard_base_style()}</style>
</head>
<body>
    <div class="sidebar">
        <h2>SiPbx Admin</h2>
        <nav>
            <a href="/SiPbx/dashboard"><span class="icon">📊</span> Dashboard</a>
            <a href="/SiPbx/dashboard/users"><span class="icon">👥</span> Users & Extensions</a>
            <a href="/SiPbx/dashboard/trunks"><span class="icon">📞</span> SIP Trunks</a>
            <a href="/SiPbx/dashboard/cdr" class="active"><span class="icon">📋</span> Call Records</a>
            <a href="/SiPbx/dashboard/billing"><span class="icon">💳</span> Billing</a>
            <a href="/SiPbx/dashboard/settings"><span class="icon">⚙️</span> System Settings</a>
        </nav>
    </div>
    <div class="main">
        <div class="header">
            <h1>Call Detail Records</h1>
            <button class="btn btn-primary">Export CSV</button>
        </div>
        <div class="card">
            <div class="card-header">
                <span>Recent Calls (showing last 100)</span>
                <div>
                    <input type="date" style="padding: 8px; background: #0f0f23; border: 1px solid #2a2a4a; border-radius: 6px; color: #fff;">
                    <button class="btn btn-secondary">Filter</button>
                </div>
            </div>
            <div class="card-body">
                <table>
                    <thead><tr><th>Time</th><th>From</th><th>To</th><th>Duration</th><th>Cost</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td>10:45:23</td><td>1001 (John Smith)</td><td>+1-555-123-4567</td><td>4:32</td><td>$0.12</td><td><span class="badge badge-success">Completed</span></td></tr>
                        <tr><td>10:42:11</td><td>+1-800-555-1234</td><td>1002 (Sarah Johnson)</td><td>12:45</td><td>$0.00</td><td><span class="badge badge-success">Completed</span></td></tr>
                        <tr><td>10:38:55</td><td>1003 (Mike Williams)</td><td>+44-20-7946-0958</td><td>8:21</td><td>$2.45</td><td><span class="badge badge-success">Completed</span></td></tr>
                        <tr><td>10:35:02</td><td>1001 (John Smith)</td><td>1005 (Robert Brown)</td><td>0:45</td><td>$0.00</td><td><span class="badge badge-danger">Failed</span></td></tr>
                        <tr><td>10:32:18</td><td>+1-312-555-9876</td><td>1004 (Emily Davis)</td><td>3:12</td><td>$0.00</td><td><span class="badge badge-success">Completed</span></td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_dashboard_billing(self, request):
        """Fake billing page with credit card form"""
        await self._log_dashboard_action(request, 'VIEW_BILLING', {'page': 'billing'})

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Billing - SiPbx</title>
    <style>{self._dashboard_base_style()}</style>
</head>
<body>
    <div class="sidebar">
        <h2>SiPbx Admin</h2>
        <nav>
            <a href="/SiPbx/dashboard"><span class="icon">📊</span> Dashboard</a>
            <a href="/SiPbx/dashboard/users"><span class="icon">👥</span> Users & Extensions</a>
            <a href="/SiPbx/dashboard/trunks"><span class="icon">📞</span> SIP Trunks</a>
            <a href="/SiPbx/dashboard/cdr"><span class="icon">📋</span> Call Records</a>
            <a href="/SiPbx/dashboard/billing" class="active"><span class="icon">💳</span> Billing</a>
            <a href="/SiPbx/dashboard/settings"><span class="icon">⚙️</span> System Settings</a>
        </nav>
    </div>
    <div class="main">
        <div class="header">
            <h1>Billing & Payments</h1>
        </div>
        <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="stat-card">
                <div class="label">Current Balance</div>
                <div class="value">$1,247.83</div>
            </div>
            <div class="stat-card">
                <div class="label">This Month Usage</div>
                <div class="value">$892.45</div>
            </div>
            <div class="stat-card">
                <div class="label">Payment Due</div>
                <div class="value" style="color: #fbbf24;">Feb 28, 2026</div>
            </div>
        </div>
        <div class="card">
            <div class="card-header">Payment Method</div>
            <div class="card-body">
                <form method="POST" action="/SiPbx/dashboard/settings">
                    <div class="form-group">
                        <label>Card Number</label>
                        <input type="text" name="card_number" placeholder="4242 4242 4242 4242">
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div class="form-group">
                            <label>Expiry Date</label>
                            <input type="text" name="card_expiry" placeholder="MM/YY">
                        </div>
                        <div class="form-group">
                            <label>CVV</label>
                            <input type="text" name="card_cvv" placeholder="123">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Billing Address</label>
                        <input type="text" name="billing_address" placeholder="123 Main St, City, State ZIP">
                    </div>
                    <button type="submit" class="btn btn-primary">Update Payment Method</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_dashboard_settings(self, request):
        """Fake system settings"""
        await self._log_dashboard_action(request, 'VIEW_SETTINGS', {'page': 'system_settings'})

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>System Settings - SiPbx</title>
    <style>{self._dashboard_base_style()}</style>
</head>
<body>
    <div class="sidebar">
        <h2>SiPbx Admin</h2>
        <nav>
            <a href="/SiPbx/dashboard"><span class="icon">📊</span> Dashboard</a>
            <a href="/SiPbx/dashboard/users"><span class="icon">👥</span> Users & Extensions</a>
            <a href="/SiPbx/dashboard/trunks"><span class="icon">📞</span> SIP Trunks</a>
            <a href="/SiPbx/dashboard/cdr"><span class="icon">📋</span> Call Records</a>
            <a href="/SiPbx/dashboard/billing"><span class="icon">💳</span> Billing</a>
            <a href="/SiPbx/dashboard/settings" class="active"><span class="icon">⚙️</span> System Settings</a>
        </nav>
    </div>
    <div class="main">
        <div class="header">
            <h1>System Settings</h1>
        </div>
        <div class="card">
            <div class="card-header">SIP Server Configuration</div>
            <div class="card-body">
                <form method="POST" action="/SiPbx/dashboard/settings">
                    <div class="form-group">
                        <label>SIP Domain</label>
                        <input type="text" name="sip_domain" value="sip.snapcom.com">
                    </div>
                    <div class="form-group">
                        <label>External IP</label>
                        <input type="text" name="external_ip" value="198.51.100.50">
                    </div>
                    <div class="form-group">
                        <label>RTP Port Range</label>
                        <input type="text" name="rtp_ports" value="10000-20000">
                    </div>
                    <div class="form-group">
                        <label>STUN Server</label>
                        <input type="text" name="stun_server" value="stun.snapcom.com:3478">
                    </div>
                    <button type="submit" class="btn btn-primary">Save Configuration</button>
                </form>
            </div>
        </div>
        <div class="card">
            <div class="card-header">Admin Credentials</div>
            <div class="card-body">
                <form method="POST" action="/SiPbx/dashboard/settings">
                    <div class="form-group">
                        <label>Current Password</label>
                        <input type="password" name="current_password">
                    </div>
                    <div class="form-group">
                        <label>New Password</label>
                        <input type="password" name="new_password">
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password</label>
                        <input type="password" name="confirm_password">
                    </div>
                    <button type="submit" class="btn btn-primary">Change Password</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def sipbx_dashboard_settings_post(self, request):
        """Capture any settings form submission"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        try:
            data = await request.post()
            form_data = {k: v for k, v in data.items()}
            logger.warning(f"CAPTURED FORM DATA - SiPbx Settings from {source_ip}: {form_data}")

            if self.log_callback:
                entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'FORM_SUBMISSION',
                    'uri': '/SiPbx/dashboard/settings',
                    'form_data': form_data,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(entry))
        except:
            pass

        # Show success message to encourage more interaction
        html = """<!DOCTYPE html>
<html><head><title>Settings Saved</title>
<style>body{font-family:Arial;background:#1a1a2e;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
.msg{background:#16213e;padding:40px;border-radius:12px;text-align:center;border:1px solid #4ade80;}
h2{color:#4ade80;margin-bottom:15px;}</style></head>
<body><div class="msg"><h2>✓ Settings Saved Successfully</h2><p>Your changes have been applied.</p><br><a href="/SiPbx/dashboard" style="color:#e94560;">Return to Dashboard</a></div></body></html>
"""
        return web.Response(text=html, content_type='text/html')

    # NDP Dashboard handlers
    async def ndp_dashboard(self, request):
        """Fake NDP admin dashboard"""
        await self._log_dashboard_action(request, 'VIEW_DASHBOARD', {'page': 'ndp_main'})

        html = """<!DOCTYPE html>
<html>
<head>
    <title>NDP Admin Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 20px; }
        .nav { background: #34495e; padding: 0 30px; }
        .nav a { display: inline-block; padding: 15px 20px; color: #ecf0f1; text-decoration: none; }
        .nav a:hover, .nav a.active { background: #2c3e50; }
        .main { padding: 30px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-box { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-box h3 { color: #7f8c8d; font-size: 14px; margin-bottom: 10px; }
        .stat-box .num { font-size: 32px; font-weight: bold; color: #2c3e50; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .card-header { padding: 20px; border-bottom: 1px solid #eee; font-weight: bold; }
        .card-body { padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; }
        .badge { padding: 5px 10px; border-radius: 20px; font-size: 12px; }
        .badge-online { background: #d4edda; color: #155724; }
        .badge-offline { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="header">
        <h1>NetSapiens Device Portal - Admin</h1>
        <div>admin@company.com | <a href="/ndp/adminlogin.php" style="color:#e74c3c;">Logout</a></div>
    </div>
    <div class="nav">
        <a href="/ndp/dashboard" class="active">Dashboard</a>
        <a href="/ndp/dashboard/devices">Devices</a>
        <a href="/ndp/dashboard/users">Users</a>
        <a href="/ndp/dashboard/config">Configuration</a>
    </div>
    <div class="main">
        <div class="stats">
            <div class="stat-box"><h3>Total Devices</h3><div class="num">1,847</div></div>
            <div class="stat-box"><h3>Online Now</h3><div class="num" style="color:#27ae60;">1,623</div></div>
            <div class="stat-box"><h3>Pending Provision</h3><div class="num" style="color:#f39c12;">48</div></div>
            <div class="stat-box"><h3>Failed Devices</h3><div class="num" style="color:#e74c3c;">12</div></div>
        </div>
        <div class="card">
            <div class="card-header">Recent Device Activity</div>
            <div class="card-body">
                <table>
                    <tr><th>Time</th><th>MAC Address</th><th>Model</th><th>Action</th><th>Status</th></tr>
                    <tr><td>2 min ago</td><td>00:15:65:A1:B2:C3</td><td>Polycom VVX 500</td><td>Provisioned</td><td><span class="badge badge-online">Online</span></td></tr>
                    <tr><td>8 min ago</td><td>00:04:F2:D4:E5:F6</td><td>Yealink T46S</td><td>Config Update</td><td><span class="badge badge-online">Online</span></td></tr>
                    <tr><td>15 min ago</td><td>00:0B:82:G7:H8:I9</td><td>Grandstream GXP2170</td><td>Registered</td><td><span class="badge badge-online">Online</span></td></tr>
                    <tr><td>1 hour ago</td><td>00:15:65:J0:K1:L2</td><td>Polycom VVX 400</td><td>Firmware Update</td><td><span class="badge badge-offline">Rebooting</span></td></tr>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def ndp_dashboard_devices(self, request):
        """Fake NDP devices list"""
        await self._log_dashboard_action(request, 'VIEW_DEVICES', {'page': 'ndp_devices'})

        html = """<!DOCTYPE html>
<html>
<head>
    <title>Devices - NDP Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 15px 30px; }
        .nav { background: #34495e; padding: 0 30px; }
        .nav a { display: inline-block; padding: 15px 20px; color: #ecf0f1; text-decoration: none; }
        .nav a:hover, .nav a.active { background: #2c3e50; }
        .main { padding: 30px; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .card-header { padding: 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
        .card-body { padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #3498db; color: white; }
        .btn-sm { padding: 5px 10px; font-size: 12px; }
        .badge { padding: 5px 10px; border-radius: 20px; font-size: 12px; }
        .badge-online { background: #d4edda; color: #155724; }
    </style>
</head>
<body>
    <div class="header"><h1>NetSapiens Device Portal - Admin</h1></div>
    <div class="nav">
        <a href="/ndp/dashboard">Dashboard</a>
        <a href="/ndp/dashboard/devices" class="active">Devices</a>
        <a href="/ndp/dashboard/users">Users</a>
        <a href="/ndp/dashboard/config">Configuration</a>
    </div>
    <div class="main">
        <div class="card">
            <div class="card-header">
                <h3>All Devices (1,847)</h3>
                <button class="btn btn-primary">+ Add Device</button>
            </div>
            <div class="card-body">
                <table>
                    <tr><th>MAC Address</th><th>Model</th><th>Extension</th><th>User</th><th>IP Address</th><th>Status</th><th>Actions</th></tr>
                    <tr><td>00:15:65:A1:B2:C3</td><td>Polycom VVX 500</td><td>1001</td><td>John Smith</td><td>192.168.1.101</td><td><span class="badge badge-online">Online</span></td><td><button class="btn btn-sm">Edit</button> <button class="btn btn-sm">Reprovision</button></td></tr>
                    <tr><td>00:04:F2:D4:E5:F6</td><td>Yealink T46S</td><td>1002</td><td>Sarah Johnson</td><td>192.168.1.102</td><td><span class="badge badge-online">Online</span></td><td><button class="btn btn-sm">Edit</button> <button class="btn btn-sm">Reprovision</button></td></tr>
                    <tr><td>00:0B:82:G7:H8:I9</td><td>Grandstream GXP2170</td><td>1003</td><td>Mike Williams</td><td>192.168.1.103</td><td><span class="badge badge-online">Online</span></td><td><button class="btn btn-sm">Edit</button> <button class="btn btn-sm">Reprovision</button></td></tr>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def ndp_dashboard_users(self, request):
        """Fake NDP users management"""
        await self._log_dashboard_action(request, 'VIEW_USERS', {'page': 'ndp_users'})

        html = """<!DOCTYPE html>
<html>
<head>
    <title>Users - NDP Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 15px 30px; }
        .nav { background: #34495e; padding: 0 30px; }
        .nav a { display: inline-block; padding: 15px 20px; color: #ecf0f1; text-decoration: none; }
        .nav a:hover, .nav a.active { background: #2c3e50; }
        .main { padding: 30px; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .card-header { padding: 20px; border-bottom: 1px solid #eee; }
        .card-body { padding: 20px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #3498db; color: white; }
    </style>
</head>
<body>
    <div class="header"><h1>NetSapiens Device Portal - Admin</h1></div>
    <div class="nav">
        <a href="/ndp/dashboard">Dashboard</a>
        <a href="/ndp/dashboard/devices">Devices</a>
        <a href="/ndp/dashboard/users" class="active">Users</a>
        <a href="/ndp/dashboard/config">Configuration</a>
    </div>
    <div class="main">
        <div class="card">
            <div class="card-header"><h3>Add New User</h3></div>
            <div class="card-body">
                <form method="POST" action="/ndp/dashboard/users">
                    <div class="form-group">
                        <label>Extension</label>
                        <input type="text" name="extension" placeholder="1001">
                    </div>
                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" name="full_name" placeholder="John Smith">
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" placeholder="john@company.com">
                    </div>
                    <div class="form-group">
                        <label>SIP Password</label>
                        <input type="text" name="sip_password" placeholder="Enter SIP password">
                    </div>
                    <div class="form-group">
                        <label>Voicemail PIN</label>
                        <input type="text" name="voicemail_pin" placeholder="1234">
                    </div>
                    <button type="submit" class="btn btn-primary">Create User</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def ndp_dashboard_users_post(self, request):
        """Capture NDP user creation form"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        try:
            data = await request.post()
            form_data = {k: v for k, v in data.items()}
            logger.warning(f"CAPTURED USER CREATION - NDP from {source_ip}: {form_data}")

            if self.log_callback:
                entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'FORM_SUBMISSION',
                    'uri': '/ndp/dashboard/users',
                    'form_data': form_data,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(entry))
        except:
            pass

        return web.Response(text="<html><body><h2>User Created Successfully!</h2><a href='/ndp/dashboard/users'>Add Another</a></body></html>", content_type='text/html')

    async def ndp_dashboard_config(self, request):
        """Fake NDP configuration page"""
        await self._log_dashboard_action(request, 'VIEW_CONFIG', {'page': 'ndp_config'})

        html = """<!DOCTYPE html>
<html>
<head>
    <title>Configuration - NDP Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 15px 30px; }
        .nav { background: #34495e; padding: 0 30px; }
        .nav a { display: inline-block; padding: 15px 20px; color: #ecf0f1; text-decoration: none; }
        .nav a:hover, .nav a.active { background: #2c3e50; }
        .main { padding: 30px; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .card-header { padding: 20px; border-bottom: 1px solid #eee; }
        .card-body { padding: 20px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #3498db; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
    </style>
</head>
<body>
    <div class="header"><h1>NetSapiens Device Portal - Admin</h1></div>
    <div class="nav">
        <a href="/ndp/dashboard">Dashboard</a>
        <a href="/ndp/dashboard/devices">Devices</a>
        <a href="/ndp/dashboard/users">Users</a>
        <a href="/ndp/dashboard/config" class="active">Configuration</a>
    </div>
    <div class="main">
        <div class="card">
            <div class="card-header"><h3>Provisioning Server Settings</h3></div>
            <div class="card-body">
                <form method="POST" action="/ndp/dashboard/config">
                    <div class="form-group">
                        <label>Provisioning Server URL</label>
                        <input type="text" name="prov_server" value="https://prov.company.com">
                    </div>
                    <div class="form-group">
                        <label>SIP Registrar</label>
                        <input type="text" name="sip_registrar" value="sip.company.com">
                    </div>
                    <div class="form-group">
                        <label>SIP Proxy</label>
                        <input type="text" name="sip_proxy" value="proxy.company.com">
                    </div>
                    <div class="form-group">
                        <label>Admin Email</label>
                        <input type="email" name="admin_email" value="admin@company.com">
                    </div>
                    <div class="form-group">
                        <label>API Key</label>
                        <input type="text" name="api_key" placeholder="Enter new API key to change">
                    </div>
                    <button type="submit" class="btn btn-primary">Save Configuration</button>
                </form>
            </div>
        </div>
        <div class="card">
            <div class="card-header"><h3>Database Export</h3></div>
            <div class="card-body">
                <p style="margin-bottom:15px;">Export all device configurations and user data.</p>
                <button class="btn btn-primary">Export All Data (CSV)</button>
                <button class="btn btn-danger" style="margin-left:10px;">Reset Database</button>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')

    async def ndp_dashboard_config_post(self, request):
        """Capture NDP config changes"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        try:
            data = await request.post()
            form_data = {k: v for k, v in data.items()}
            logger.warning(f"CAPTURED CONFIG DATA - NDP from {source_ip}: {form_data}")

            if self.log_callback:
                entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': source_ip,
                    'source_port': 0,
                    'method': 'FORM_SUBMISSION',
                    'uri': '/ndp/dashboard/config',
                    'form_data': form_data,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(entry))
        except:
            pass

        return web.Response(text="<html><body><h2>Configuration Saved!</h2><a href='/ndp/dashboard'>Return to Dashboard</a></body></html>", content_type='text/html')

    # ==================== PHP SHELL HONEYPOT ====================

    async def _log_shell_action(self, request, action, details=None):
        """Log PHP shell honeypot activity"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        logger.warning(f"PHP SHELL HONEYPOT - {action} from {source_ip}: {details}")

        if self.log_callback:
            creds = {}
            if details:
                if details.get('command'):
                    creds['command'] = details['command']
                if details.get('filename'):
                    creds['filename'] = details['filename']
                if details.get('size'):
                    creds['upload_size'] = details['size']
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_ip,
                'source_port': 0,
                'method': action,
                'uri': request.path,
                'credentials': creds,
                'user_agent': request.headers.get('User-Agent', ''),
                'protocol': 'HTTP',
                'honeypot_type': 'webshell'
            }
            asyncio.create_task(self.log_callback(entry))

    def _fake_shell_output(self, cmd):
        """Generate realistic fake output for shell commands"""
        cmd = cmd.strip()
        parts = cmd.split()
        if not parts:
            return ''
        base = parts[0]

        hostname = 'web-prod-03'
        fake_ip = f'10.0.{random.randint(1,254)}.{random.randint(2,254)}'

        outputs = {
            'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
            'whoami': 'www-data',
            'hostname': hostname,
            'pwd': '/var/www/html',
            'uname': 'Linux web-prod-03 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux',
        }

        if base in outputs and len(parts) == 1:
            return outputs[base]
        if base == 'uname':
            return outputs['uname']

        if base == 'ls':
            target = parts[-1] if len(parts) > 1 and not parts[-1].startswith('-') else '.'
            listings = {
                '.': 'admin.php\nconfig.php\ncss\nimages\ninclude\nindex.php\njs\nuploads\nwp-admin\nwp-content\nwp-includes',
                '/tmp': f'php{random.randint(1000,9999)}.tmp\nsess_{hashlib.md5(str(random.random()).encode()).hexdigest()[:16]}\nsystemd-private-xxx',
                '/etc': 'apache2\ncron.d\ncrontab\nhostname\nhosts\nld.so.conf\nmy.cnf\nnginx\npasswd\nphp\nresolv.conf\nshadow\nssl',
                '/var/www': 'html\nlogs\nvhosts',
                '/var/www/html': 'admin.php\nconfig.php\ncss\nimages\ninclude\nindex.php\njs\nuploads\nwp-admin\nwp-content\nwp-includes',
                'uploads': f'2023\n2024\nbackup.sql.gz\nrevslider.zip\nshell.php.bak',
            }
            if '-la' in cmd or '-al' in cmd:
                items = listings.get(target, listings['.']).split('\n')
                result = f'total {len(items) * 4}\ndrwxr-xr-x  {len(items)} www-data www-data 4096 Oct 15 14:23 .\ndrwxr-xr-x  3 root     root     4096 Aug  1 09:15 ..\n'
                for item in items:
                    size = random.randint(100, 65536)
                    month = random.choice(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])
                    day = random.randint(1, 28)
                    perm = 'drwxr-xr-x' if '.' not in item or item.startswith('.') else '-rw-r--r--'
                    result += f'{perm}  1 www-data www-data {size:>5} {month} {day:>2} {random.randint(0,23):02d}:{random.randint(0,59):02d} {item}\n'
                return result.strip()
            return listings.get(target, listings['.'])

        if base == 'cat':
            target = parts[1] if len(parts) > 1 else ''
            if 'passwd' in target:
                return ('root:x:0:0:root:/root:/bin/bash\n'
                    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
                    'bin:x:2:2:bin:/bin:/usr/sbin/nologin\n'
                    'sys:x:3:3:sys:/dev:/usr/sbin/nologin\n'
                    'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
                    'mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n'
                    'sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n'
                    'admin:x:1000:1000:Admin User:/home/admin:/bin/bash')
            if 'shadow' in target:
                return 'cat: /etc/shadow: Permission denied'
            if 'config.php' in target or 'wp-config' in target:
                db_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                auth_key = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
                nl = '\n'
                return (f"<?php{nl}"
                    f"define('DB_NAME', 'wordpress_prod');{nl}"
                    f"define('DB_USER', 'wp_admin');{nl}"
                    f"define('DB_PASSWORD', '{db_pass}');{nl}"
                    f"define('DB_HOST', 'localhost');{nl}"
                    f"define('DB_CHARSET', 'utf8mb4');{nl}"
                    f"$table_prefix = 'wp_';{nl}"
                    f"define('AUTH_KEY', '{auth_key}');{nl}"
                    f"define('WP_DEBUG', false);{nl}"
                    f"?>")
            if '.htaccess' in target:
                return 'RewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]'
            if 'my.cnf' in target or 'mysql' in target:
                return '[mysqld]\ndatadir=/var/lib/mysql\nsocket=/var/lib/mysql/mysql.sock\nuser=mysql\nmax_connections=500\ninnodb_buffer_pool_size=2G'
            return f'cat: {target}: No such file or directory' if target else ''

        if base == 'ps':
            return ('USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n'
                'root         1  0.0  0.1 169436 11200 ?        Ss   Oct01   0:13 /sbin/init\n'
                'root       423  0.0  0.1  72304  6144 ?        Ss   Oct01   0:02 /usr/sbin/sshd -D\n'
                'mysql      891  0.3  4.2 1842396 348160 ?      Ssl  Oct01  45:12 /usr/sbin/mysqld\n'
                f'root       912  0.0  0.2 144520 17408 ?        Ss   Oct01   0:08 /usr/sbin/apache2 -k start\n'
                f'www-data  1034  0.0  0.1 144960  9216 ?        S    Oct01   2:14 /usr/sbin/apache2 -k start\n'
                f'www-data  1035  0.0  0.1 144960  9100 ?        S    Oct01   2:08 /usr/sbin/apache2 -k start\n'
                f'www-data  {random.randint(10000,30000)}  0.0  0.0  2608  1536 ?        S    {random.randint(10,23):02d}:{random.randint(0,59):02d}   0:00 sh -c /usr/bin/php')

        if base in ('ifconfig', 'ip'):
            return (f'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n'
                f'        inet {fake_ip}  netmask 255.255.255.0  broadcast 10.0.1.255\n'
                f'        inet6 fe80::42:acff:fe11:1  prefixlen 64  scopeid 0x20<link>\n'
                f'        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\n'
                f'        RX packets 2847563  bytes 1893452781 (1.7 GiB)\n'
                f'        TX packets 1923847  bytes 892374651 (827.2 MiB)\n\n'
                f'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n'
                f'        inet 127.0.0.1  netmask 255.0.0.0\n'
                f'        loop  txqueuelen 1000  (Local Loopback)')

        if base == 'netstat':
            return (f'Active Internet connections (servers and established)\n'
                f'Proto Recv-Q Send-Q Local Address           Foreign Address         State\n'
                f'tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n'
                f'tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n'
                f'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n'
                f'tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n'
                f'tcp        0      0 {fake_ip}:443      185.220.101.{random.randint(1,254)}:{random.randint(40000,60000)}   ESTABLISHED\n'
                f'tcp        0      0 {fake_ip}:80       {random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}:{random.randint(40000,60000)}   ESTABLISHED')

        if base == 'df':
            return ('Filesystem      Size  Used Avail Use% Mounted on\n'
                '/dev/sda1        50G   23G   25G  48% /\n'
                'tmpfs           2.0G     0  2.0G   0% /dev/shm\n'
                '/dev/sda2       200G  142G   48G  75% /var/www')

        if base == 'free':
            return ('              total        used        free      shared  buff/cache   available\n'
                'Mem:        8167940     3245612     1892340      142568     3029988     4562120\n'
                'Swap:       2097148      524288     1572860')

        if base in ('wget', 'curl'):
            url = parts[1] if len(parts) > 1 else 'http://example.com'
            if base == 'wget':
                fname = url.split('/')[-1] if '/' in url else 'index.html'
                return (f'--{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}--  {url}\n'
                    f'Resolving {url.split("//")[-1].split("/")[0]}... {random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}\n'
                    f'Connecting to {url.split("//")[-1].split("/")[0]}... connected.\n'
                    f'HTTP request sent, awaiting response... 200 OK\n'
                    f'Length: {random.randint(1000,500000)} ({random.randint(1,500)}K) [application/octet-stream]\n'
                    f'Saving to: \'{fname}\'\n\n'
                    f'{fname}          100%[==================>] {random.randint(1,500)}K  {random.randint(100,999)}KB/s    in 0.{random.randint(1,9)}s\n\n'
                    f'{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} (523 KB/s) - \'{fname}\' saved')
            return f'{{"status":"ok","ip":"{fake_ip}"}}'

        if base == 'find':
            return (f'./uploads/2024/shell.php.bak\n'
                f'./wp-content/cache/object/tmp.php\n'
                f'./include/config.php\n'
                f'./admin.php')

        if base in ('chmod', 'chown', 'mv', 'cp', 'mkdir', 'touch'):
            return ''

        if base == 'echo':
            rest = cmd[5:].strip()
            return rest.strip('"').strip("'")

        if base == 'python' or base == 'python3' or base == 'perl' or base == 'ruby':
            return f'/bin/sh: 1: {base}: not found'

        if base == 'nc' or base == 'ncat':
            return f'/bin/sh: 1: {base}: not found'

        if base == 'gcc' or base == 'cc':
            return f'/bin/sh: 1: {base}: not found'

        if base == 'sudo':
            return f'www-data is not in the sudoers file. This incident will be reported.'

        if base == 'su':
            return 'su: Authentication failure'

        if base == 'mysql':
            if '-p' in cmd or '--password' in cmd:
                return 'ERROR 1045 (28000): Access denied for user \'www-data\'@\'localhost\' (using password: YES)'
            return ('Welcome to the MariaDB monitor. Commands end with ; or \\g.\n'
                'Your MariaDB connection id is 847\n'
                'Server version: 10.11.6-MariaDB-0ubuntu0.23.04.1 Ubuntu 23.04\n\n'
                'MariaDB [(none)]> ')

        if base == 'env' or base == 'printenv':
            return (f'HOSTNAME={hostname}\n'
                f'APACHE_RUN_USER=www-data\n'
                f'APACHE_RUN_GROUP=www-data\n'
                f'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
                f'PWD=/var/www/html\n'
                f'LANG=C.UTF-8\n'
                f'APACHE_LOG_DIR=/var/log/apache2\n'
                f'DB_HOST=127.0.0.1\n'
                f'DB_NAME=wordpress_prod\n'
                f'DB_USER=wp_admin\n'
                f'DB_PASS={"".join(random.choices(string.ascii_letters + string.digits, k=16))}')

        if base == 'cd':
            return ''

        if cmd.startswith('/bin/') or cmd.startswith('/usr/'):
            base_cmd = cmd.split('/')[-1].split()[0]
            return self._fake_shell_output(cmd.replace(cmd.split()[0], base_cmd, 1))

        return f'/bin/sh: 1: {base}: not found'

    def _php_shell_html(self, request, output='', cmd=''):
        """Generate the fake PHP shell page"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        escaped_output = output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        escaped_cmd = cmd.replace('"', '&quot;')

        if cmd:
            output_content = '<span class="prompt">www-data@web-prod-03:/var/www/html$</span> <span class="cmd-text">' + escaped_cmd + '</span>\n' + escaped_output
        else:
            output_content = '# b374k shell ready\n# Type a command and press Execute\n'

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>b374k 3.2 - shell</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #1a1a1a; color: #00ff00; font-family: 'Courier New', monospace; font-size: 13px; }}
        .header {{ background: #0d0d0d; padding: 8px 15px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; }}
        .header .title {{ color: #ff6600; font-weight: bold; font-size: 14px; }}
        .header .info {{ color: #888; font-size: 11px; }}
        .nav {{ background: #111; padding: 5px 15px; border-bottom: 1px solid #333; }}
        .nav a {{ color: #00aaff; text-decoration: none; margin-right: 15px; font-size: 12px; }}
        .nav a:hover {{ color: #fff; }}
        .nav a.active {{ color: #ff6600; }}
        .sysinfo {{ background: #0d0d0d; padding: 10px 15px; border-bottom: 1px solid #222; font-size: 11px; color: #666; }}
        .sysinfo span {{ color: #999; }}
        .main {{ padding: 15px; }}
        .cmd-box {{ background: #0d0d0d; border: 1px solid #333; border-radius: 3px; padding: 15px; margin-bottom: 15px; }}
        .cmd-row {{ display: flex; align-items: center; gap: 10px; }}
        .cmd-label {{ color: #ff6600; white-space: nowrap; }}
        .cmd-input {{ flex: 1; background: #000; border: 1px solid #444; color: #00ff00; padding: 8px 12px; font-family: 'Courier New', monospace; font-size: 13px; border-radius: 2px; }}
        .cmd-input:focus {{ outline: none; border-color: #00aaff; }}
        .cmd-btn {{ background: #333; color: #00ff00; border: 1px solid #555; padding: 8px 20px; cursor: pointer; font-family: 'Courier New', monospace; border-radius: 2px; }}
        .cmd-btn:hover {{ background: #444; }}
        .output {{ background: #000; border: 1px solid #333; padding: 15px; min-height: 300px; max-height: 500px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; font-size: 12px; line-height: 1.5; border-radius: 3px; }}
        .output .prompt {{ color: #ff6600; }}
        .output .cmd-text {{ color: #fff; }}
        .upload-box {{ background: #0d0d0d; border: 1px solid #333; border-radius: 3px; padding: 15px; margin-top: 15px; }}
        .upload-box h3 {{ color: #ff6600; font-size: 12px; margin-bottom: 10px; }}
        .upload-row {{ display: flex; align-items: center; gap: 10px; }}
        input[type="file"] {{ color: #888; font-size: 12px; }}
        .footer {{ text-align: center; padding: 10px; color: #333; font-size: 10px; border-top: 1px solid #222; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <span class="title">b374k 3.2.3</span>
        <span class="info">Safe mode: OFF | PHP {random.choice(['7.4.33','8.1.27','8.2.12'])} | {random.choice(['Apache/2.4.57','nginx/1.24.0'])}</span>
    </div>
    <div class="nav">
        <a href="#" class="active">Command</a>
        <a href="#">File Manager</a>
        <a href="#">Upload</a>
        <a href="#">Database</a>
        <a href="#">Network</a>
        <a href="#">Info</a>
    </div>
    <div class="sysinfo">
        Server: <span>Linux web-prod-03 5.15.0-91-generic x86_64</span> |
        User: <span>www-data (33)</span> |
        CWD: <span>/var/www/html</span> |
        Free: <span>{random.randint(20,45)}G / 50G</span>
    </div>
    <div class="main">
        <form method="POST" action="{request.path}">
            <div class="cmd-box">
                <div class="cmd-row">
                    <span class="cmd-label">www-data@web-prod-03:/var/www/html$</span>
                    <input type="text" name="cmd" class="cmd-input" value="{escaped_cmd}" placeholder="Enter command..." autofocus autocomplete="off">
                    <button type="submit" class="cmd-btn">Execute</button>
                </div>
            </div>
        </form>
        <div class="output">{output_content}</div>
        <form method="POST" action="{request.path}" enctype="multipart/form-data">
            <div class="upload-box">
                <h3>File Upload</h3>
                <div class="upload-row">
                    <input type="file" name="upload_file">
                    <input type="hidden" name="upload_dir" value="/var/www/html/uploads/">
                    <button type="submit" name="action" value="upload" class="cmd-btn">Upload</button>
                </div>
            </div>
        </form>
    </div>
    <div class="footer">b374k shell | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
    <script>document.querySelector('.cmd-input').focus();document.querySelector('.cmd-input').select();</script>
</body>
</html>"""

    async def php_shell_page(self, request):
        """Serve the fake PHP shell page"""
        cmd = request.query.get('cmd', '') or request.query.get('c', '') or request.query.get('exec', '')

        await self._log_shell_action(request, 'SHELL_ACCESS', {
            'path': request.path,
            'query_cmd': cmd or None,
            'query': dict(request.query)
        })

        if cmd:
            output = self._fake_shell_output(cmd)
            await self._log_shell_action(request, 'SHELL_COMMAND', {
                'command': cmd,
                'path': request.path
            })
            # If request accepts JSON or has no Accept header (likely automated)
            if 'json' in request.headers.get('Accept', '') or 'curl' in request.headers.get('User-Agent', '').lower():
                return web.Response(text=output + '\n', content_type='text/plain')
            return web.Response(text=self._php_shell_html(request, output, cmd), content_type='text/html')

        return web.Response(text=self._php_shell_html(request), content_type='text/html')

    async def php_shell_execute(self, request):
        """Handle command execution and file uploads from the fake shell"""
        source_ip = request.remote
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            source_ip = forwarded.split(',')[0].strip()

        try:
            # Check for multipart (file upload)
            if request.content_type and 'multipart' in request.content_type:
                reader = await request.multipart()
                upload_filename = None
                upload_size = 0
                upload_dir = '/var/www/html/uploads/'
                cmd = ''

                async for part in reader:
                    if part.name == 'upload_file' and part.filename:
                        upload_filename = part.filename
                        data = await part.read()
                        upload_size = len(data)
                    elif part.name == 'upload_dir':
                        upload_dir = (await part.read()).decode()
                    elif part.name == 'cmd':
                        cmd = (await part.read()).decode()
                    elif part.name == 'action':
                        await part.read()

                if upload_filename:
                    await self._log_shell_action(request, 'SHELL_UPLOAD', {
                        'filename': upload_filename,
                        'size': upload_size,
                        'upload_dir': upload_dir,
                    })
                    output = f'File uploaded successfully: {upload_dir}{upload_filename} ({upload_size} bytes)'
                    return web.Response(text=self._php_shell_html(request, output, f'upload {upload_filename}'), content_type='text/html')

            # Regular form POST (command execution)
            data = await request.post()
            cmd = data.get('cmd', '') or data.get('c', '') or data.get('exec', '')
        except Exception:
            cmd = ''
            try:
                body = await request.text()
                if body:
                    await self._log_shell_action(request, 'SHELL_RAW_POST', {
                        'body': body[:2000],
                        'content_type': request.content_type
                    })
            except Exception:
                pass

        if cmd:
            await self._log_shell_action(request, 'SHELL_COMMAND', {
                'command': cmd,
                'path': request.path
            })
            output = self._fake_shell_output(cmd)

            # For automated tools, return plain text
            if 'curl' in request.headers.get('User-Agent', '').lower() or request.content_type == 'application/x-www-form-urlencoded' and 'Accept' not in request.headers:
                # Check if this looks like an automated request
                if not request.headers.get('Referer', ''):
                    return web.Response(text=output + '\n', content_type='text/plain')

            return web.Response(text=self._php_shell_html(request, output, cmd), content_type='text/html')

        return web.Response(text=self._php_shell_html(request), content_type='text/html')

    async def php_catch(self, request):
        """Catch any .php request with cmd/exec params"""
        cmd = request.query.get('cmd', '') or request.query.get('c', '') or request.query.get('exec', '') or request.query.get('command', '')

        if cmd:
            await self._log_shell_action(request, 'PHP_CMD_INJECTION', {
                'path': request.path,
                'command': cmd,
                'query': dict(request.query)
            })
            output = self._fake_shell_output(cmd)
            return web.Response(text=output + '\n', content_type='text/plain')

        if request.method == 'POST':
            try:
                data = await request.post()
                cmd = data.get('cmd', '') or data.get('c', '') or data.get('exec', '')
                if cmd:
                    await self._log_shell_action(request, 'PHP_CMD_INJECTION', {
                        'path': request.path,
                        'command': cmd,
                    })
                    output = self._fake_shell_output(cmd)
                    return web.Response(text=output + '\n', content_type='text/plain')
            except Exception:
                pass

        # No cmd param - return a generic PHP-looking response
        return web.Response(text='', status=200, content_type='text/html')

    async def generic_provision(self, request):
        """Generic provisioning catch-all"""
        path = request.match_info.get('path', '')
        return web.Response(text=f"<!-- Provisioning endpoint: {path} -->\n<error>Device not found</error>", content_type='text/xml', status=404)

    async def catch_all(self, request):
        """Catch all other requests"""
        return web.Response(text="Not Found", status=404)


async def run_provisioning_honeypot(host: str = '0.0.0.0', port: int = 8080, log_callback=None):
    """Run the provisioning honeypot server"""
    honeypot = ProvisioningHoneypot(log_callback=log_callback)
    runner = web.AppRunner(honeypot.app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info(f"Provisioning Honeypot started on http://{host}:{port}")

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(run_provisioning_honeypot())
