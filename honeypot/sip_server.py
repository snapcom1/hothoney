#!/usr/bin/env python3
"""
SIP Honeypot Server
Emulates SIP endpoints to capture malicious registration/invite attempts
Includes tarpit functionality to waste attacker resources
"""

import asyncio
import logging
import random
import re
import socket
import struct
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Callable
from dataclasses import dataclass
import hashlib
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SIPMessage:
    method: str
    uri: str
    headers: dict
    body: str
    raw: str


class RTPFartSender:
    """Send hilarious fart sounds via RTP to waste attacker bandwidth"""

    # G.711 u-law encoding table
    ULAW_MAX = 0x1FFF
    ULAW_BIAS = 33

    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sequence = random.randint(0, 65535)
        self.timestamp = random.randint(0, 0xFFFFFFFF)
        self.ssrc = random.randint(0, 0xFFFFFFFF)
        self.running = False

    def _linear_to_ulaw(self, sample: int) -> int:
        """Convert 16-bit linear PCM to 8-bit u-law"""
        sign = (sample >> 8) & 0x80
        if sign:
            sample = -sample
        sample = min(sample, self.ULAW_MAX)
        sample += self.ULAW_BIAS

        # Find segment
        exponent = 7
        for exp in range(7, -1, -1):
            if sample >= (1 << (exp + 3)):
                exponent = exp
                break

        mantissa = (sample >> (exponent + 3)) & 0x0F
        ulaw_byte = ~(sign | (exponent << 4) | mantissa) & 0xFF
        return ulaw_byte

    def _generate_fart_samples(self, duration_ms: int = 500) -> bytes:
        """Generate a synthetic fart sound - low frequency bursts with noise"""
        sample_rate = 8000  # G.711 uses 8kHz
        num_samples = int(sample_rate * duration_ms / 1000)
        samples = []

        # Fart parameters - low rumbling frequency with noise
        base_freq = random.uniform(50, 150)  # Low rumble

        for i in range(num_samples):
            t = i / sample_rate
            # Mix of low frequency sine wave + noise for realistic fart sound
            # Amplitude envelope - louder at start, trails off
            envelope = math.exp(-t * 3) * 0.8 + 0.2
            # Low frequency rumble
            rumble = math.sin(2 * math.pi * base_freq * t)
            # Add harmonics
            rumble += 0.5 * math.sin(2 * math.pi * base_freq * 2 * t)
            rumble += 0.3 * math.sin(2 * math.pi * base_freq * 3 * t)
            # Add some noise/raspiness
            noise = random.uniform(-1, 1) * 0.4
            # Frequency variation (wobble)
            wobble = math.sin(2 * math.pi * 8 * t) * 0.3

            sample = int(((rumble + noise) * envelope + wobble * envelope) * 16000)
            sample = max(-32768, min(32767, sample))
            samples.append(self._linear_to_ulaw(sample))

        return bytes(samples)

    def _create_rtp_packet(self, payload: bytes) -> bytes:
        """Create an RTP packet with the given payload"""
        # RTP header: V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU)
        version = 2
        padding = 0
        extension = 0
        cc = 0
        marker = 0
        payload_type = 0  # PCMU (G.711 u-law)

        first_byte = (version << 6) | (padding << 5) | (extension << 4) | cc
        second_byte = (marker << 7) | payload_type

        header = struct.pack('!BBHII',
            first_byte,
            second_byte,
            self.sequence & 0xFFFF,
            self.timestamp & 0xFFFFFFFF,
            self.ssrc
        )

        self.sequence = (self.sequence + 1) & 0xFFFF
        self.timestamp = (self.timestamp + len(payload)) & 0xFFFFFFFF

        return header + payload

    async def send_farts(self, duration_sec: int):
        """Send fart sounds for the specified duration"""
        self.running = True
        start_time = time.time()

        # Pre-generate several fart sounds for variety
        fart_sounds = [self._generate_fart_samples(random.randint(200, 800)) for _ in range(5)]

        try:
            while self.running and (time.time() - start_time) < duration_sec:
                # Pick a random fart sound
                fart = random.choice(fart_sounds)

                # Send it in 160-byte chunks (20ms of audio at 8kHz)
                chunk_size = 160
                for i in range(0, len(fart), chunk_size):
                    if not self.running:
                        break
                    chunk = fart[i:i + chunk_size]
                    if len(chunk) < chunk_size:
                        chunk = chunk + bytes(chunk_size - len(chunk))  # Pad with silence

                    packet = self._create_rtp_packet(chunk)
                    try:
                        self.sock.sendto(packet, (self.target_ip, self.target_port))
                    except Exception:
                        pass  # Ignore send errors

                    await asyncio.sleep(0.02)  # 20ms per packet

                # Random pause between farts (0.5-3 seconds)
                await asyncio.sleep(random.uniform(0.5, 3.0))

        except asyncio.CancelledError:
            pass
        finally:
            self.running = False

    def stop(self):
        """Stop sending RTP"""
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


def parse_sdp_media_address(sdp_body: str) -> Tuple[Optional[str], Optional[int]]:
    """Extract RTP media address from SDP body"""
    if not sdp_body:
        return None, None

    ip_addr = None
    port = None

    # Look for c= line (connection info)
    c_match = re.search(r'c=IN IP4 (\d+\.\d+\.\d+\.\d+)', sdp_body)
    if c_match:
        ip_addr = c_match.group(1)

    # Look for m=audio line
    m_match = re.search(r'm=audio (\d+)', sdp_body)
    if m_match:
        port = int(m_match.group(1))

    return ip_addr, port


class SIPHoneypot:
    """UDP SIP Honeypot Server - Impersonates Snapcom SiPbx"""

    # Common SIP methods we want to trap
    TRAPPED_METHODS = ['REGISTER', 'INVITE', 'OPTIONS', 'ACK', 'BYE', 'CANCEL', 'SUBSCRIBE', 'NOTIFY']

    # Server identity - impersonate Snapcom SiPbx
    SERVER_NAMES = ['core1-stl.snapcom.com', 'core2-stl.snapcom.com']
    SERVER_AGENT = 'SiPbx/5.0.0'
    REALM = 'snapcom.com'

    def __init__(self, host: str = '0.0.0.0', port: int = 5060, db_handler=None,
                 tarpit_config: Dict = None, is_blocked_callback: Callable = None,
                 throttle_config: Dict = None):
        self.host = host
        self.port = port
        self.db_handler = db_handler
        self.transport = None
        self.fake_extensions = self._generate_fake_extensions()
        self.server_name = self.SERVER_NAMES[0]
        # Tarpit configuration
        self.tarpit_config = tarpit_config or {
            'enabled': False,
            'delay_ms': 20000,
            'ringing_count': 30,
            'blocklist_only': True
        }
        self.is_blocked_callback = is_blocked_callback
        # Track active tarpits to prevent duplicates
        self.active_tarpits: Dict[str, asyncio.Task] = {}
        # Throttle configuration
        self.throttle_config = throttle_config or {
            'enabled': True,
            'requests_per_minute': 30
        }
        # Track request counts per IP for throttling
        self._request_counts: Dict[str, list] = {}  # ip -> list of timestamps
        self._throttle_stats: Dict[str, int] = {}  # ip -> dropped count

    def _generate_fake_extensions(self) -> list:
        """Generate fake extension numbers that look realistic"""
        extensions = []
        # Common extension patterns
        for i in range(100, 200):
            extensions.append(str(i))
        for i in range(1000, 1050):
            extensions.append(str(i))
        for i in range(2000, 2020):
            extensions.append(str(i))
        # Add some named extensions
        extensions.extend(['sales', 'support', 'admin', 'voicemail', 'operator', 'reception'])
        return extensions

    def _generate_bloat_headers(self) -> str:
        """Generate extra headers to bloat response size and waste attacker bandwidth/CPU"""
        # Realistic-looking but useless headers that parsers still have to process
        bloat = []

        # Extended server capabilities (looks legitimate)
        bloat.append('Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, SUBSCRIBE, NOTIFY, REFER, INFO, MESSAGE, UPDATE, PRACK, PUBLISH, NEGOTIATE, COMET, CONNECT, SERVICE, UNSUBSCRIBE, PATCH, LINK, UNLINK')
        bloat.append('Supported: replaces, timer, path, outbound, gruu, tdialog, 100rel, histinfo, resource-priority, sdp-anat, sec-agree, record-aware, geolocation, call-completion, diversion, intercom, from-change, norefersub, extended-refer, target-dialog, info-package, recipient-list-invite, recipient-list-subscribe')
        bloat.append('Accept: application/sdp, application/dtmf-relay, text/plain, application/simple-message-summary, application/dialog-info+xml, application/conference-info+xml, application/reginfo+xml, application/watcherinfo+xml, message/sipfrag, application/csta+xml, application/poc-settings+xml, application/vnd.3gpp.sms, application/vnd.etsi.pstn+xml, application/vnd.omalocserv-xml, multipart/mixed, multipart/alternative')
        bloat.append('Accept-Encoding: identity, gzip, deflate, compress, br, zstd, sdch, lz4, snappy, bzip2')
        bloat.append('Accept-Language: en-US, en-GB, en-AU, en-CA, en-NZ, en-IE, en-ZA, en, es-ES, es-MX, es-AR, es, fr-FR, fr-CA, fr, de-DE, de-AT, de, it, pt-BR, pt-PT, pt, zh-CN, zh-TW, zh, ja, ko, ru, ar, hi, th, vi, nl, pl, sv, da, no, fi')

        # Generate unique session data
        session_id = hashlib.sha256(f"{datetime.now()}{self.server_name}{random.random()}".encode()).hexdigest()
        trace_id = hashlib.sha256(f"{datetime.now().timestamp()}{random.random()}".encode()).hexdigest()

        # Fake feature tags (3GPP/IMS style - very long)
        bloat.append('Feature-Caps: *;+sip.ice;+sip.instance="<urn:uuid:' + hashlib.md5(str(datetime.now()).encode()).hexdigest() + '>";+g.3gpp.icsi-ref="urn:urn-7:3gpp-service.ims.icsi.mmtel";+g.3gpp.cs-voice;+g.3gpp.smsip;+g.3gpp.iari-ref="urn:urn-7:3gpp-application.ims.iari.rcse.im";+g.gsma.rcs.isbot;+g.gsma.rcs.cpm.pager-large;+g.gsma.rcs.cpm.ft')
        bloat.append(f'Feature-Caps: +sip.pns;+sip.pnsreg;+sip.pnspurr="apns:voip";pns-provider="apns";pns-param="{session_id[:32]}"')

        # Session parameters with padding
        bloat.append(f'Session-ID: {session_id};remote={trace_id};local-uuid={hashlib.md5(session_id.encode()).hexdigest()}')
        bloat.append(f'Session-Expires: 1800;refresher=uac')
        bloat.append(f'Min-SE: 90')

        # Fake diagnostic headers (lots of them)
        bloat.append(f'X-Session-GUID: {session_id}')
        bloat.append(f'X-Trace-ID: {trace_id}')
        bloat.append(f'X-Span-ID: {hashlib.md5(f"{session_id}{random.random()}".encode()).hexdigest()}')
        bloat.append(f'X-Parent-Span-ID: {hashlib.md5(f"{trace_id}{random.random()}".encode()).hexdigest()}')
        bloat.append(f'X-Request-ID: {hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()}-{hashlib.md5(str(datetime.now()).encode()).hexdigest()}-{random.randint(100000,999999)}')
        bloat.append(f'X-Correlation-ID: CORR-{trace_id[:48]}-{random.randint(1000,9999)}')
        bloat.append(f'X-Transaction-ID: TXN-{session_id[:40]}-{datetime.now().strftime("%Y%m%d%H%M%S")}')
        bloat.append(f'X-Instance-ID: inst-{hashlib.md5(self.server_name.encode()).hexdigest()[:16]}')
        bloat.append(f'X-Shard-ID: shard-{random.randint(1,128):03d}-{self.REALM}')

        # Fake cluster/load balancer headers
        bloat.append(f'X-Served-By: {self.server_name}, sip-proxy-01.{self.REALM}, sip-proxy-02.{self.REALM}, sip-edge-01.{self.REALM}, sip-edge-02.{self.REALM}, sip-edge-03.{self.REALM}')
        bloat.append(f'X-Backend-Server: sip-core-{hashlib.md5(str(datetime.now().hour).encode()).hexdigest()[:8]}.internal.{self.REALM}')
        bloat.append(f'X-Load-Balancer: lb-primary-01.snapcom.com:5060;weight=100;priority=1;pool=sip-prod-pool-east')
        bloat.append(f'X-Upstream-Addr: 10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}:{random.randint(5060,5080)}')
        bloat.append(f'X-Forwarded-For: 10.0.0.{random.randint(1,254)}, 10.1.0.{random.randint(1,254)}, 172.16.{random.randint(1,254)}.{random.randint(1,254)}')
        bloat.append(f'X-Real-IP: 10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}')
        bloat.append(f'X-Cluster-Name: sip-cluster-prod-{random.choice(["east", "west", "central", "north", "south"])}')
        bloat.append(f'X-Pod-Name: sip-server-{hashlib.md5(str(random.random()).encode()).hexdigest()[:8]}')
        bloat.append(f'X-Node-Name: node-{random.randint(1,99):02d}.k8s.snapcom.internal')

        # Fake timestamps and metrics
        bloat.append(f'X-Timestamp: {datetime.utcnow().isoformat()}Z')
        bloat.append(f'X-Request-Start: {int(datetime.now().timestamp() * 1000000)}')
        bloat.append(f'X-Process-Time: {random.randint(1,50)}ms')
        bloat.append(f'X-Queue-Time: {random.randint(0,5)}ms')
        bloat.append(f'X-Response-Time: {random.randint(5,100)}ms')
        bloat.append(f'X-Rate-Limit-Remaining: {random.randint(100,1000)}')
        bloat.append(f'X-Rate-Limit-Reset: {int(datetime.now().timestamp()) + 60}')

        # Padding with legitimate-looking warnings
        bloat.append(f'Warning: 399 sip-proxy.snapcom.com "Resource utilization nominal - CPU {random.randint(10,40)}% MEM {random.randint(20,60)}%"')
        bloat.append(f'Warning: 370 sip-edge.snapcom.com "Media capability verification pending for session {session_id[:16]}"')
        bloat.append(f'Warning: 392 sip-core.snapcom.com "Transcoding resources available: G711={random.randint(50,200)} G729={random.randint(20,100)} OPUS={random.randint(30,150)}"')
        bloat.append(f'Warning: 307 registrar.snapcom.com "Registration binding refresh recommended within {random.randint(1800,3600)} seconds"')

        # Fake P-headers (common in carrier networks) - expanded
        bloat.append(f'P-Asserted-Identity: <sip:pbx@snapcom.com>, <tel:+18005551234>, <sip:+1800555{random.randint(1000,9999)}@snapcom.com>')
        bloat.append('P-Preferred-Identity: <sip:switch@snapcom.com>')
        bloat.append('P-Access-Network-Info: IEEE-802.11a;i-wlan-node-id=0a1b2c3d4e5f;network-provided;local-time-zone="America/Chicago";location-source=GPS')
        bloat.append(f'P-Charging-Vector: icid-value="{trace_id}";icid-generated-at=snapcom.com;orig-ioi=snapcom.com;term-ioi=snapcom.com;transit-ioi=carrier-peer.net')
        bloat.append(f'P-Charging-Function-Addresses: ccf="aaa://{random.randint(10,99)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}:3868";ecf="aaa://{random.randint(10,99)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}:3868"')
        bloat.append('P-Visited-Network-ID: "snapcom.com", "carrier-transit.net", "voip-peer.com", "pstn-gateway.net", "lec-interconnect.com"')
        bloat.append(f'P-Media-Authorization: {hashlib.sha256(f"{session_id}media".encode()).hexdigest()}')
        bloat.append(f'P-Early-Media: supported')
        bloat.append(f'P-Profile-Key: <sip:profile-{random.randint(1000,9999)}@snapcom.com>')
        bloat.append(f'P-User-Database: <sip:hss.snapcom.com>;type=HSS')
        bloat.append(f'P-Served-User: <sip:served@snapcom.com>;sescase=orig;regstate=reg')
        bloat.append(f'P-Associated-URI: <sip:user1@snapcom.com>, <sip:user2@snapcom.com>, <tel:+18005551234>, <sip:+18005551234@snapcom.com>')

        # Resource-Priority headers (emergency/priority calls)
        bloat.append('Resource-Priority: wps.4, dsn.flash-override, drsn.routine')
        bloat.append('Accept-Resource-Priority: wps.4, wps.3, wps.2, wps.1, wps.0, dsn.flash-override, dsn.flash, dsn.immediate, dsn.priority, dsn.routine')

        # History-Info for call diversion tracking
        bloat.append(f'History-Info: <sip:original@snapcom.com>;index=1, <sip:diverted@snapcom.com?Reason=unconditional>;index=1.1, <sip:final@snapcom.com>;index=1.1.1;rc=302')

        # Geolocation headers
        bloat.append(f'Geolocation: <cid:location-{session_id[:16]}@snapcom.com>;inserted-by="sip:switch@snapcom.com";routing-allowed=yes')
        bloat.append(f'Geolocation-Routing: yes')

        # More fake headers that look important
        bloat.append(f'Organization: Snapcom Communications Inc.')
        bloat.append(f'User-Agent: SiPbx/5.0.0 (Linux; Snapcom Enterprise PBX; Build-{random.randint(10000,99999)})')
        bloat.append(f'X-PBX-Version: 5.0.0-{random.randint(100,999)}-enterprise')
        bloat.append(f'X-License-ID: LIC-{hashlib.md5(self.REALM.encode()).hexdigest()[:16].upper()}')
        bloat.append(f'X-Tenant-ID: tenant-{random.randint(10000,99999)}')
        bloat.append(f'X-Customer-ID: cust-{hashlib.md5(str(random.random()).encode()).hexdigest()[:12]}')
        bloat.append(f'X-Account-Code: {random.randint(100000,999999)}')
        bloat.append(f'X-Call-Type: internal')
        bloat.append(f'X-Trunk-Group: trunk-grp-{random.randint(1,10)}')
        bloat.append(f'X-Route-Set: route-{random.choice(["primary", "secondary", "tertiary"])}-{random.randint(1,5)}')

        return '\r\n'.join(bloat)

    def parse_sip_message(self, data: bytes) -> Optional[SIPMessage]:
        """Parse raw SIP message into structured format"""
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')

            if not lines:
                return None

            # Parse request line
            request_line = lines[0].split(' ')
            if len(request_line) < 2:
                return None

            method = request_line[0]
            uri = request_line[1] if len(request_line) > 1 else ''

            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            body = '\r\n'.join(lines[body_start:]) if body_start > 0 else ''

            return SIPMessage(method=method, uri=uri, headers=headers, body=body, raw=text)

        except Exception as e:
            logger.error(f"Failed to parse SIP message: {e}")
            return None

    def extract_credentials(self, msg: SIPMessage) -> dict:
        """Extract authentication credentials from SIP message"""
        creds = {
            'username': None,
            'domain': None,
            'auth_user': None,
            'nonce': None,
            'response': None
        }

        # Extract from Authorization header
        auth_header = msg.headers.get('authorization', '')
        if auth_header:
            username_match = re.search(r'username="([^"]+)"', auth_header)
            if username_match:
                creds['auth_user'] = username_match.group(1)

            nonce_match = re.search(r'nonce="([^"]+)"', auth_header)
            if nonce_match:
                creds['nonce'] = nonce_match.group(1)

            response_match = re.search(r'response="([^"]+)"', auth_header)
            if response_match:
                creds['response'] = response_match.group(1)

        # Extract from From/To headers
        from_header = msg.headers.get('from', '')
        to_header = msg.headers.get('to', '')

        # Parse SIP URI from headers
        uri_pattern = r'sip:([^@]+)@([^>;]+)'
        from_match = re.search(uri_pattern, from_header)
        if from_match:
            creds['username'] = from_match.group(1)
            creds['domain'] = from_match.group(2)

        return creds

    def generate_challenge_response(self, msg: SIPMessage, addr: Tuple[str, int]) -> bytes:
        """Generate 401/407 challenge to elicit credentials"""
        call_id = msg.headers.get('call-id', 'unknown')
        from_header = msg.headers.get('from', '<sip:unknown@unknown>')
        to_header = msg.headers.get('to', '<sip:unknown@unknown>')
        via = msg.headers.get('via', f'SIP/2.0/UDP {addr[0]}:{addr[1]}')
        cseq = msg.headers.get('cseq', '1 REGISTER')

        # Generate realistic nonce
        nonce = hashlib.md5(f"{datetime.now().isoformat()}{addr[0]}".encode()).hexdigest()
        opaque = hashlib.md5(f"sipbx{self.server_name}".encode()).hexdigest()[:16]

        if msg.method == 'REGISTER':
            status = '401 Unauthorized'
            auth_header = f'WWW-Authenticate: Digest realm="{self.REALM}", nonce="{nonce}", opaque="{opaque}", algorithm=MD5, qop="auth"'
        else:
            status = '407 Proxy Authentication Required'
            auth_header = f'Proxy-Authenticate: Digest realm="{self.REALM}", nonce="{nonce}", opaque="{opaque}", algorithm=MD5, qop="auth"'

        bloat = self._generate_bloat_headers()
        response = f"""SIP/2.0 {status}\r
Via: {via}\r
From: {from_header}\r
To: {to_header};tag={hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}\r
Call-ID: {call_id}\r
CSeq: {cseq}\r
Server: {self.SERVER_AGENT}\r
{auth_header}\r
{bloat}\r
Content-Length: 0\r
\r
"""
        return response.encode('utf-8')

    def generate_ok_response(self, msg: SIPMessage, addr: Tuple[str, int]) -> bytes:
        """Generate 200 OK response"""
        call_id = msg.headers.get('call-id', 'unknown')
        from_header = msg.headers.get('from', '<sip:unknown@unknown>')
        to_header = msg.headers.get('to', '<sip:unknown@unknown>')
        via = msg.headers.get('via', f'SIP/2.0/UDP {addr[0]}:{addr[1]}')
        cseq = msg.headers.get('cseq', '1 OPTIONS')

        bloat = self._generate_bloat_headers()
        response = f"""SIP/2.0 200 OK\r
Via: {via}\r
From: {from_header}\r
To: {to_header};tag={hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}\r
Call-ID: {call_id}\r
CSeq: {cseq}\r
Server: {self.SERVER_AGENT}\r
{bloat}\r
Content-Length: 0\r
\r
"""
        return response.encode('utf-8')

    def generate_register_ok_response(self, msg: SIPMessage, addr: Tuple[str, int]) -> bytes:
        """Generate 200 OK response for REGISTER - makes attacker think registration succeeded"""
        call_id = msg.headers.get('call-id', 'unknown')
        from_header = msg.headers.get('from', '<sip:unknown@unknown>')
        to_header = msg.headers.get('to', '<sip:unknown@unknown>')
        via = msg.headers.get('via', f'SIP/2.0/UDP {addr[0]}:{addr[1]}')
        cseq = msg.headers.get('cseq', '1 REGISTER')
        contact = msg.headers.get('contact', f'<sip:{addr[0]}:{addr[1]}>')

        # Parse the contact to add expires parameter
        if ';expires=' not in contact.lower():
            contact = contact.rstrip('>') + ';expires=3600>' if contact.endswith('>') else contact + ';expires=3600'

        # Current date in SIP format
        date_str = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        bloat = self._generate_bloat_headers()
        response = f"""SIP/2.0 200 OK\r
Via: {via}\r
From: {from_header}\r
To: {to_header};tag={hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}\r
Call-ID: {call_id}\r
CSeq: {cseq}\r
Server: {self.SERVER_AGENT}\r
Contact: {contact}\r
Date: {date_str}\r
Expires: 3600\r
{bloat}\r
Content-Length: 0\r
\r
"""
        return response.encode('utf-8')

    def generate_trying_response(self, msg: SIPMessage, addr: Tuple[str, int]) -> bytes:
        """Generate 100 Trying response"""
        call_id = msg.headers.get('call-id', 'unknown')
        from_header = msg.headers.get('from', '<sip:unknown@unknown>')
        to_header = msg.headers.get('to', '<sip:unknown@unknown>')
        via = msg.headers.get('via', f'SIP/2.0/UDP {addr[0]}:{addr[1]}')
        cseq = msg.headers.get('cseq', '1 INVITE')

        response = f"""SIP/2.0 100 Trying\r
Via: {via}\r
From: {from_header}\r
To: {to_header}\r
Call-ID: {call_id}\r
CSeq: {cseq}\r
Server: {self.SERVER_AGENT}\r
Content-Length: 0\r
\r
"""
        return response.encode('utf-8')

    def generate_ringing_response(self, msg: SIPMessage, addr: Tuple[str, int], to_tag: str) -> bytes:
        """Generate 180 Ringing response"""
        call_id = msg.headers.get('call-id', 'unknown')
        from_header = msg.headers.get('from', '<sip:unknown@unknown>')
        to_header = msg.headers.get('to', '<sip:unknown@unknown>')
        via = msg.headers.get('via', f'SIP/2.0/UDP {addr[0]}:{addr[1]}')
        cseq = msg.headers.get('cseq', '1 INVITE')

        response = f"""SIP/2.0 180 Ringing\r
Via: {via}\r
From: {from_header}\r
To: {to_header};tag={to_tag}\r
Call-ID: {call_id}\r
CSeq: {cseq}\r
Server: {self.SERVER_AGENT}\r
Contact: <sip:{self.server_name}:5060>\r
Content-Length: 0\r
\r
"""
        return response.encode('utf-8')

    def generate_session_progress_response(self, msg: SIPMessage, addr: Tuple[str, int], to_tag: str) -> bytes:
        """Generate 183 Session Progress response with fake early media SDP"""
        call_id = msg.headers.get('call-id', 'unknown')
        from_header = msg.headers.get('from', '<sip:unknown@unknown>')
        to_header = msg.headers.get('to', '<sip:unknown@unknown>')
        via = msg.headers.get('via', f'SIP/2.0/UDP {addr[0]}:{addr[1]}')
        cseq = msg.headers.get('cseq', '1 INVITE')

        # Fake SDP for early media (makes scanner wait for audio)
        sdp = f"""v=0\r
o=SiPbx 1234567890 1234567890 IN IP4 {self.server_name}\r
s=SIP Call\r
c=IN IP4 {self.server_name}\r
t=0 0\r
m=audio 10000 RTP/AVP 0 8 101\r
a=rtpmap:0 PCMU/8000\r
a=rtpmap:8 PCMA/8000\r
a=rtpmap:101 telephone-event/8000\r
a=sendrecv\r
"""
        sdp_bytes = sdp.encode('utf-8')

        response = f"""SIP/2.0 183 Session Progress\r
Via: {via}\r
From: {from_header}\r
To: {to_header};tag={to_tag}\r
Call-ID: {call_id}\r
CSeq: {cseq}\r
Server: {self.SERVER_AGENT}\r
Contact: <sip:{self.server_name}:5060>\r
Content-Type: application/sdp\r
Content-Length: {len(sdp_bytes)}\r
\r
{sdp}"""
        return response.encode('utf-8')

    def generate_invite_ok_response(self, msg: SIPMessage, addr: Tuple[str, int], to_tag: str) -> bytes:
        """Generate 200 OK response for INVITE - fake call answer to waste attacker RTP resources"""
        call_id = msg.headers.get('call-id', 'unknown')
        from_header = msg.headers.get('from', '<sip:unknown@unknown>')
        to_header = msg.headers.get('to', '<sip:unknown@unknown>')
        via = msg.headers.get('via', f'SIP/2.0/UDP {addr[0]}:{addr[1]}')
        cseq = msg.headers.get('cseq', '1 INVITE')

        # Generate fake RTP port (random high port that goes nowhere)
        rtp_port = random.randint(10000, 60000)

        # Full SDP for "answered" call - attacker will send RTP here (to nowhere)
        sdp = f"""v=0\r
o=SiPbx {random.randint(1000000, 9999999)} {random.randint(1000000, 9999999)} IN IP4 {self.server_name}\r
s=SIP Call\r
c=IN IP4 {self.server_name}\r
t=0 0\r
m=audio {rtp_port} RTP/AVP 0 8 18 101\r
a=rtpmap:0 PCMU/8000\r
a=rtpmap:8 PCMA/8000\r
a=rtpmap:18 G729/8000\r
a=rtpmap:101 telephone-event/8000\r
a=fmtp:101 0-16\r
a=ptime:20\r
a=sendrecv\r
"""
        sdp_bytes = sdp.encode('utf-8')
        bloat = self._generate_bloat_headers()

        response = f"""SIP/2.0 200 OK\r
Via: {via}\r
From: {from_header}\r
To: {to_header};tag={to_tag}\r
Call-ID: {call_id}\r
CSeq: {cseq}\r
Server: {self.SERVER_AGENT}\r
Contact: <sip:{self.server_name}:5060>\r
Content-Type: application/sdp\r
{bloat}\r
Content-Length: {len(sdp_bytes)}\r
\r
{sdp}"""
        return response.encode('utf-8')

    async def should_tarpit(self, source_ip: str) -> bool:
        """Check if we should tarpit this IP"""
        if not self.tarpit_config.get('enabled', False):
            return False

        # If blocklist_only is true, check if IP is on blocklist
        if self.tarpit_config.get('blocklist_only', True):
            if self.is_blocked_callback:
                return await self.is_blocked_callback(source_ip)
            return False

        # Tarpit everyone
        return True

    def should_throttle(self, source_ip: str) -> bool:
        """Check if we should throttle (drop) response to this IP"""
        if not self.throttle_config.get('enabled', True):
            return False

        max_requests = self.throttle_config.get('requests_per_minute', 30)
        if max_requests <= 0:
            return False

        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)

        # Get or create timestamp list for this IP
        if source_ip not in self._request_counts:
            self._request_counts[source_ip] = []

        # Clean old timestamps
        self._request_counts[source_ip] = [ts for ts in self._request_counts[source_ip] if ts > minute_ago]

        # Check if over limit
        if len(self._request_counts[source_ip]) >= max_requests:
            # Track dropped count
            self._throttle_stats[source_ip] = self._throttle_stats.get(source_ip, 0) + 1
            return True

        # Add current timestamp
        self._request_counts[source_ip].append(now)
        return False

    def get_throttle_stats(self) -> Dict[str, int]:
        """Get throttle statistics (dropped counts per IP)"""
        return dict(self._throttle_stats)


class SIPProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP Protocol for SIP"""

    def __init__(self, honeypot: SIPHoneypot, log_callback=None):
        self.honeypot = honeypot
        self.log_callback = log_callback
        # Track active tarpit sessions by call-id
        self.tarpit_sessions: Dict[str, asyncio.Task] = {}
        # Track session metadata for display
        self.tarpit_session_info: Dict[str, dict] = {}

    def connection_made(self, transport):
        self.transport = transport
        self.honeypot.transport = transport
        logger.info(f"SIP Honeypot listening on {self.honeypot.host}:{self.honeypot.port}")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming SIP message"""
        asyncio.create_task(self._handle_message(data, addr))

    async def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """Async handler for SIP messages"""
        source_ip, source_port = addr

        msg = self.honeypot.parse_sip_message(data)
        if not msg:
            logger.warning(f"Invalid SIP message from {source_ip}:{source_port}")
            return

        logger.info(f"SIP {msg.method} from {source_ip}:{source_port}")

        # Extract any credentials
        creds = self.honeypot.extract_credentials(msg)

        # Log the attempt (log throttling handled by callback)
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': source_ip,
            'source_port': source_port,
            'method': msg.method,
            'uri': msg.uri,
            'user_agent': msg.headers.get('user-agent', 'unknown'),
            'from': msg.headers.get('from', ''),
            'to': msg.headers.get('to', ''),
            'credentials': creds,
            'raw_message': msg.raw[:2000]  # Truncate for storage
        }

        if self.log_callback:
            asyncio.create_task(self.log_callback(log_entry))

        # Check response throttling - drop response if over limit
        if self.honeypot.should_throttle(source_ip):
            logger.debug(f"Throttled response to {source_ip}")
            return

        # Check for CANCEL - stop any active tarpit for this call
        call_id = msg.headers.get('call-id', '')
        if msg.method == 'CANCEL' and call_id in self.tarpit_sessions:
            self.tarpit_sessions[call_id].cancel()
            del self.tarpit_sessions[call_id]
            logger.info(f"Tarpit cancelled for {source_ip} (call-id: {call_id[:20]}...)")
            response = self.honeypot.generate_ok_response(msg, addr)
            self.transport.sendto(response, addr)
            return

        # Check if we should tarpit INVITE requests
        if msg.method == 'INVITE' and await self.honeypot.should_tarpit(source_ip):
            # Start tarpit session
            if call_id not in self.tarpit_sessions:
                logger.info(f"Starting tarpit for {source_ip}")
                task = asyncio.create_task(self._run_tarpit(msg, addr, call_id))
                self.tarpit_sessions[call_id] = task
            return

        # Generate response based on method
        if msg.method == 'OPTIONS':
            # Respond to OPTIONS to appear as real server
            response = self.honeypot.generate_ok_response(msg, addr)
        elif msg.method == 'REGISTER':
            # Challenge for credentials
            if not creds.get('response'):
                # First attempt - send challenge
                response = self.honeypot.generate_challenge_response(msg, addr)
            else:
                # They sent credentials - accept to make them think it worked!
                logger.info(f"Captured credentials from {source_ip}: {creds} - sending fake success")
                response = self.honeypot.generate_register_ok_response(msg, addr)
                # Log credential capture as separate entry for easy filtering
                if self.log_callback:
                    cred_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': source_ip,
                        'source_port': addr[1],
                        'protocol': 'SIP',
                        'honeypot_type': 'sip',
                        'method': 'CREDENTIAL_CAPTURE',
                        'uri': msg.uri,
                        'user_agent': msg.headers.get('user-agent', 'unknown'),
                        'from': msg.headers.get('from', ''),
                        'to': msg.headers.get('to', ''),
                        'credentials': creds,
                        'raw_message': ''
                    }
                    asyncio.create_task(self.log_callback(cred_entry))
        elif msg.method == 'INVITE':
            # Challenge for credentials, then accept to waste their RTP resources
            if not creds.get('response'):
                # First attempt - send challenge
                response = self.honeypot.generate_challenge_response(msg, addr)
            else:
                # They sent credentials - accept the call!
                # This makes them think the call connected and they'll send RTP to nowhere
                logger.info(f"Captured credentials from {source_ip}: {creds} - accepting call")
                to_tag = hashlib.md5(f"{call_id}{datetime.now()}".encode()).hexdigest()[:8]
                response = self.honeypot.generate_invite_ok_response(msg, addr, to_tag)
                # Log credential capture as separate entry for easy filtering
                if self.log_callback:
                    cred_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': source_ip,
                        'source_port': addr[1],
                        'protocol': 'SIP',
                        'honeypot_type': 'sip',
                        'method': 'CREDENTIAL_CAPTURE',
                        'uri': msg.uri,
                        'user_agent': msg.headers.get('user-agent', 'unknown'),
                        'from': msg.headers.get('from', ''),
                        'to': msg.headers.get('to', ''),
                        'credentials': creds,
                        'raw_message': ''
                    }
                    asyncio.create_task(self.log_callback(cred_entry))
        else:
            # For other methods, send OK
            response = self.honeypot.generate_ok_response(msg, addr)

        self.transport.sendto(response, addr)

    async def _run_tarpit(self, msg: SIPMessage, addr: Tuple[str, int], call_id: str):
        """Run tarpit session - quick ringing then fake answer to waste RTP bandwidth"""
        source_ip = addr[0]
        source_port = addr[1]
        to_tag = hashlib.md5(f"{call_id}{datetime.now()}".encode()).hexdigest()[:8]

        # Extract target from INVITE
        to_uri = msg.headers.get('To', '')
        target = to_uri.split('@')[0].replace('<sip:', '').replace('sip:', '') if to_uri else 'unknown'

        # Initialize session info
        start_time = datetime.now()
        self.tarpit_session_info[call_id] = {
            'ip': source_ip,
            'port': source_port,
            'target': target,
            'phase': 'ringing',
            'ring_count': 0,
            'total_rings': 10,  # Will be updated when ringing starts
            'start_time': start_time.isoformat(),
            'answered_time': None,
            'call_duration_planned': 0,
            'call_elapsed': 0
        }
        logger.debug(f"Tarpit session added: {call_id[:16]}... (total active: {len(self.tarpit_session_info)})")

        try:
            # Send 100 Trying first
            trying = self.honeypot.generate_trying_response(msg, addr)
            self.transport.sendto(trying, addr)
            await asyncio.sleep(0.1)

            # Send 183 Session Progress with SDP (makes them think call is connecting)
            progress = self.honeypot.generate_session_progress_response(msg, addr, to_tag)
            self.transport.sendto(progress, addr)
            await asyncio.sleep(0.5)

            # Total ringing duration: 5-20 seconds, then answer
            total_ring_duration = random.uniform(5, 20)
            ring_interval = 2.0  # Send a ring every 2 seconds
            elapsed = 0
            ring_num = 0

            # Update session info with expected rings
            expected_rings = int(total_ring_duration / ring_interval) + 1
            if call_id in self.tarpit_session_info:
                self.tarpit_session_info[call_id]['total_rings'] = expected_rings

            # Keep sending 180 Ringing during the ringing period
            while elapsed < total_ring_duration:
                ring_num += 1
                ringing = self.honeypot.generate_ringing_response(msg, addr, to_tag)
                self.transport.sendto(ringing, addr)
                # Update session info
                if call_id in self.tarpit_session_info:
                    self.tarpit_session_info[call_id]['ring_count'] = ring_num
                logger.debug(f"Tarpit ringing {ring_num} to {source_ip}, {total_ring_duration - elapsed:.1f}s until answer")
                await asyncio.sleep(ring_interval)
                elapsed += ring_interval

            # "Answer" the call - send 200 OK with SDP
            # Attacker will now send RTP to our fake address (wasting their bandwidth)
            answer = self.honeypot.generate_invite_ok_response(msg, addr, to_tag)
            self.transport.sendto(answer, addr)

            # Random call duration between 5-20 minutes (more realistic)
            call_duration_min = random.randint(5, 20)
            call_duration_sec = call_duration_min * 60
            answered_time = datetime.now()

            # Parse attacker's SDP to find their RTP address
            rtp_ip, rtp_port = parse_sdp_media_address(msg.body)
            # If SDP has 0.0.0.0, use the source IP instead
            if rtp_ip == '0.0.0.0' or not rtp_ip:
                rtp_ip = source_ip

            # Update session info - now in answered/RTP phase
            if call_id in self.tarpit_session_info:
                self.tarpit_session_info[call_id].update({
                    'phase': 'answered',
                    'answered_time': answered_time.isoformat(),
                    'call_duration_planned': call_duration_sec
                })

            # Start sending fart sounds if we have their RTP address
            fart_sender = None
            fart_task = None
            if rtp_ip and rtp_port:
                logger.info(f"Tarpit answered call for {source_ip} - sending farts to {rtp_ip}:{rtp_port} for {call_duration_min} min")
                fart_sender = RTPFartSender(rtp_ip, rtp_port)
                fart_task = asyncio.create_task(fart_sender.send_farts(call_duration_sec))
            else:
                logger.info(f"Tarpit answered call for {source_ip} - fake {call_duration_min} min call (no RTP addr found)")

            # Hold the "call" open - they'll keep sending RTP the whole time
            try:
                elapsed = 0
                while elapsed < call_duration_sec:
                    await asyncio.sleep(30)  # Check every 30 seconds
                    elapsed += 30
                    # Update elapsed time in session info
                    if call_id in self.tarpit_session_info:
                        self.tarpit_session_info[call_id]['call_elapsed'] = elapsed
            finally:
                # Stop fart sender
                if fart_sender:
                    fart_sender.stop()
                if fart_task:
                    fart_task.cancel()
                    try:
                        await fart_task
                    except asyncio.CancelledError:
                        pass

            logger.info(f"Tarpit call ended for {source_ip} ({ring_num} rings + {call_duration_min} min fake call)")

        except asyncio.CancelledError:
            logger.info(f"Tarpit interrupted for {source_ip}")
        except Exception as e:
            logger.error(f"Tarpit error for {source_ip}: {e}")
        finally:
            # Clean up session
            if call_id in self.tarpit_sessions:
                del self.tarpit_sessions[call_id]
            if call_id in self.tarpit_session_info:
                del self.tarpit_session_info[call_id]


async def run_sip_honeypot(host: str = '0.0.0.0', port: int = 5060, log_callback=None,
                          tarpit_config: Dict = None, is_blocked_callback: Callable = None,
                          throttle_config: Dict = None, protocol_holder: dict = None):
    """Run the SIP honeypot server"""
    honeypot = SIPHoneypot(
        host=host,
        port=port,
        tarpit_config=tarpit_config,
        is_blocked_callback=is_blocked_callback,
        throttle_config=throttle_config
    )

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SIPProtocol(honeypot, log_callback),
        local_addr=(host, port)
    )

    # Store protocol reference for external access (e.g., API)
    if protocol_holder is not None:
        protocol_holder['protocol'] = protocol

    logger.info(f"SIP Honeypot started on {host}:{port}")
    if tarpit_config and tarpit_config.get('enabled'):
        logger.info(f"Tarpit enabled: {tarpit_config.get('ringing_count')} rings, {tarpit_config.get('delay_ms')}ms delay")
    if throttle_config and throttle_config.get('enabled'):
        logger.info(f"Response throttle enabled: {throttle_config.get('requests_per_minute')} req/min per IP")

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        transport.close()


if __name__ == '__main__':
    asyncio.run(run_sip_honeypot())
