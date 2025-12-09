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
        logger.info(f"Serving Polycom config for MAC {mac} with ext {creds['extension']}")
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
        logger.info(f"Serving Yealink config for MAC {mac} with ext {creds['extension']}")
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
        logger.info(f"Serving Grandstream config for MAC {mac} with ext {creds['extension']}")
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
        logger.info(f"Serving NetSapiens cfg-text for MAC {mac} with ext {creds['extension']}")
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
        """Capture login attempts"""
        try:
            data = await request.post()
            username = data.get('username', '')
            password = data.get('password', '')
            logger.warning(f"CAPTURED CREDENTIALS - NDP Admin: {username}:{password}")

            # Log credential capture specifically
            if self.log_callback:
                cred_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': request.remote,
                    'source_port': 0,
                    'method': 'CREDENTIAL_CAPTURE',
                    'uri': '/ndp/adminlogin.php',
                    'credentials': {
                        'username': username,
                        'password': password,
                        'type': 'ndp_admin'
                    },
                    'protocol': 'HTTP',
                    'honeypot_type': 'provisioning'
                }
                asyncio.create_task(self.log_callback(cred_entry))
        except:
            pass

        # Always show "invalid credentials" to keep them trying
        html = """<!DOCTYPE html>
<html>
<head>
    <title>NDP Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
        .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 30px; font-size: 24px; }
        .error { background: #ffe6e6; color: #cc0000; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
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
        <div class="error">Invalid username or password</div>
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

    async def sipbx_admin(self, request):
        """SiPbx admin - require auth"""
        raise web.HTTPFound('/SiPbx/login')

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
