#!/usr/bin/env python3
"""
Fake Provisioning Server
Emulates Polycom, Yealink, Grandstream, and NetSapiens provisioning endpoints
"""

import asyncio
import logging
import re
from datetime import datetime
from aiohttp import web
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProvisioningHoneypot:
    """HTTP Provisioning Honeypot Server"""

    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.app = web.Application(middlewares=[self.logging_middleware])
        self._setup_routes()

    def _setup_routes(self):
        """Setup all fake provisioning endpoints"""
        # Polycom endpoints
        self.app.router.add_get('/000000000000.cfg', self.polycom_config)
        self.app.router.add_get('/000000000000-phone.cfg', self.polycom_config)
        self.app.router.add_get('/000000000000-web.cfg', self.polycom_config)
        self.app.router.add_get('/{mac}.cfg', self.polycom_config)
        self.app.router.add_get('/{mac}-phone.cfg', self.polycom_config)
        self.app.router.add_get('/sip.cfg', self.polycom_sip_cfg)
        self.app.router.add_get('/phone1.cfg', self.polycom_sip_cfg)
        self.app.router.add_get('/Config/reg-basic.cfg', self.polycom_config)
        self.app.router.add_get('/Config/reg-advanced.cfg', self.polycom_config)

        # Yealink endpoints
        self.app.router.add_get('/y000000000000.cfg', self.yealink_config)
        self.app.router.add_get('/{mac}.boot', self.yealink_boot)
        self.app.router.add_get('/y{mac}.cfg', self.yealink_config)
        self.app.router.add_get('/tmp/{mac}.cfg', self.yealink_config)
        self.app.router.add_get('/Yealink/config/{mac}.cfg', self.yealink_config)

        # Grandstream endpoints
        self.app.router.add_get('/cfg{mac}', self.grandstream_config)
        self.app.router.add_get('/cfg{mac}.xml', self.grandstream_config)
        self.app.router.add_get('/gs_config.txt', self.grandstream_config)

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
        """Fake Polycom configuration file"""
        mac = request.match_info.get('mac', '000000000000')
        config = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<PHONE_CONFIG>
<REGISTRATION
    reg.1.displayName="Extension 100"
    reg.1.address="100"
    reg.1.label="100"
    reg.1.type="private"
    reg.1.auth.userId="100"
    reg.1.auth.password="HONEYPOT_TRAP"
    reg.1.server.1.address="pbx.example.com"
    reg.1.server.1.port="5060"
/>
<VOIP_CONFIG
    voIpProt.server.1.address="pbx.example.com"
    voIpProt.server.1.port="5060"
/>
</PHONE_CONFIG>
"""
        return web.Response(text=config, content_type='text/xml')

    async def polycom_sip_cfg(self, request):
        """Fake Polycom SIP config"""
        config = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sip>
    <outboundProxy voIpProt.SIP.outboundProxy.address="proxy.example.com"/>
    <server voIpProt.server.1.address="pbx.example.com"/>
</sip>
"""
        return web.Response(text=config, content_type='text/xml')

    async def yealink_config(self, request):
        """Fake Yealink configuration file"""
        config = """#!version:1.0.0.1
account.1.enable = 1
account.1.label = Extension 100
account.1.display_name = Extension 100
account.1.auth_name = 100
account.1.user_name = 100
account.1.password = HONEYPOT_TRAP
account.1.sip_server.1.address = pbx.example.com
account.1.sip_server.1.port = 5060
account.1.outbound_proxy.1.address = proxy.example.com
"""
        return web.Response(text=config, content_type='text/plain')

    async def yealink_boot(self, request):
        """Fake Yealink boot file"""
        return web.Response(text="include:config/<MAC>.cfg", content_type='text/plain')

    async def grandstream_config(self, request):
        """Fake Grandstream configuration"""
        # Grandstream uses encoded format, but we'll provide XML for trap
        config = """<?xml version="1.0" encoding="UTF-8"?>
<gs_provision version="1">
<config version="1">
<P270>100</P270>
<P271>100</P271>
<P272>HONEYPOT_TRAP</P272>
<P47>pbx.example.com</P47>
<P2312>proxy.example.com</P2312>
</config>
</gs_provision>
"""
        return web.Response(text=config, content_type='text/xml')

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
