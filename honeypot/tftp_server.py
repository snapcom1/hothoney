#!/usr/bin/env python3
"""
TFTP Honeypot Server
Emulates a TFTP server to capture provisioning attempts from VoIP phones
"""

import asyncio
import logging
import struct
from typing import Callable, Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# TFTP Opcodes
OPCODE_RRQ = 1    # Read request
OPCODE_WRQ = 2    # Write request
OPCODE_DATA = 3   # Data
OPCODE_ACK = 4    # Acknowledgment
OPCODE_ERROR = 5  # Error

# TFTP Error Codes
ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OP = 4
ERR_UNKNOWN_TID = 5
ERR_FILE_EXISTS = 6
ERR_NO_SUCH_USER = 7

# Common VoIP phone config file patterns
VOIP_CONFIG_PATTERNS = [
    # Polycom
    '.cfg', 'sip.cfg', 'phone1.cfg', 'bootrom.ld', '000000000000.cfg',
    'macaddress.cfg', 'overrides', 'polycom',
    # Yealink
    '.boot', 'y0000000000.cfg', 'common.cfg', 'mac.cfg',
    # Grandstream
    'cfg', 'gs_config', 'grandstream',
    # Cisco
    'SEP', 'CTLSEP', 'ITLSEP', 'XMLDefault.cnf.xml', 'SIPDefault.cnf',
    # Avaya
    '46xxsettings.txt', 'avaya',
    # Generic
    'config', 'settings', 'firmware', '.bin', '.rom', '.ld'
]


class TFTPHoneypot(asyncio.DatagramProtocol):
    """TFTP Honeypot Protocol Handler"""

    def __init__(self, log_callback: Callable = None):
        self.log_callback = log_callback
        self.transport = None
        self.sessions: Dict[tuple, Dict] = {}  # Track active sessions

    def connection_made(self, transport):
        self.transport = transport
        logger.info("TFTP Honeypot ready to receive connections")

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle incoming TFTP packets"""
        if len(data) < 2:
            return

        opcode = struct.unpack('!H', data[:2])[0]

        try:
            if opcode == OPCODE_RRQ:
                asyncio.create_task(self.handle_read_request(data, addr))
            elif opcode == OPCODE_WRQ:
                asyncio.create_task(self.handle_write_request(data, addr))
            elif opcode == OPCODE_DATA:
                asyncio.create_task(self.handle_data(data, addr))
            elif opcode == OPCODE_ACK:
                asyncio.create_task(self.handle_ack(data, addr))
            else:
                self.send_error(addr, ERR_ILLEGAL_OP, "Illegal operation")
        except Exception as e:
            logger.error(f"Error handling TFTP packet from {addr}: {e}")

    async def handle_read_request(self, data: bytes, addr: tuple):
        """Handle TFTP Read Request (RRQ)"""
        try:
            # Parse RRQ packet: opcode (2) + filename + \0 + mode + \0
            parts = data[2:].split(b'\x00')
            if len(parts) < 2:
                self.send_error(addr, ERR_NOT_DEFINED, "Invalid request")
                return

            filename = parts[0].decode('utf-8', errors='replace')
            mode = parts[1].decode('utf-8', errors='replace').lower()

            source_ip = addr[0]
            source_port = addr[1]

            logger.info(f"TFTP RRQ from {source_ip}:{source_port} - File: {filename}, Mode: {mode}")

            # Determine if this looks like a VoIP config request
            is_voip_config = any(pattern.lower() in filename.lower() for pattern in VOIP_CONFIG_PATTERNS)

            # Log the event
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_ip,
                'source_port': source_port,
                'protocol': 'TFTP',
                'honeypot_type': 'tftp',
                'method': 'RRQ',
                'uri': filename,
                'user_agent': f"TFTP/{mode}",
                'headers': {
                    'filename': filename,
                    'mode': mode,
                    'is_voip_config': is_voip_config
                },
                'raw_data': data[:500].hex() if len(data) > 0 else None
            }

            if self.log_callback:
                await self.log_callback(event)

            # Generate fake response based on filename
            fake_config = self.generate_fake_config(filename)

            if fake_config:
                # Send fake config data
                await self.send_file_data(addr, fake_config)
            else:
                # File not found
                self.send_error(addr, ERR_FILE_NOT_FOUND, "File not found")

        except Exception as e:
            logger.error(f"Error processing RRQ: {e}")
            self.send_error(addr, ERR_NOT_DEFINED, "Internal error")

    async def handle_write_request(self, data: bytes, addr: tuple):
        """Handle TFTP Write Request (WRQ) - capture uploaded files"""
        try:
            parts = data[2:].split(b'\x00')
            if len(parts) < 2:
                self.send_error(addr, ERR_NOT_DEFINED, "Invalid request")
                return

            filename = parts[0].decode('utf-8', errors='replace')
            mode = parts[1].decode('utf-8', errors='replace').lower()

            source_ip = addr[0]
            source_port = addr[1]

            logger.info(f"TFTP WRQ from {source_ip}:{source_port} - File: {filename}, Mode: {mode}")

            # Initialize session to capture uploaded data
            self.sessions[addr] = {
                'filename': filename,
                'mode': mode,
                'data': b'',
                'block': 0,
                'source_ip': source_ip
            }

            # Log the write attempt
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_ip,
                'source_port': source_port,
                'protocol': 'TFTP',
                'honeypot_type': 'tftp',
                'method': 'WRQ',
                'uri': filename,
                'user_agent': f"TFTP/{mode}",
                'headers': {
                    'filename': filename,
                    'mode': mode,
                    'operation': 'upload_attempt'
                }
            }

            if self.log_callback:
                await self.log_callback(event)

            # Send ACK for block 0 to accept the write
            self.send_ack(addr, 0)

        except Exception as e:
            logger.error(f"Error processing WRQ: {e}")
            self.send_error(addr, ERR_NOT_DEFINED, "Internal error")

    async def handle_data(self, data: bytes, addr: tuple):
        """Handle incoming DATA packets (for WRQ sessions)"""
        if addr not in self.sessions:
            self.send_error(addr, ERR_UNKNOWN_TID, "Unknown transfer ID")
            return

        if len(data) < 4:
            return

        block_num = struct.unpack('!H', data[2:4])[0]
        block_data = data[4:]

        session = self.sessions[addr]
        session['data'] += block_data
        session['block'] = block_num

        # Send ACK
        self.send_ack(addr, block_num)

        # If block is less than 512 bytes, transfer is complete
        if len(block_data) < 512:
            logger.info(f"TFTP upload complete from {addr[0]}: {session['filename']} ({len(session['data'])} bytes)")

            # Log the completed upload with captured data
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': session['source_ip'],
                'source_port': addr[1],
                'protocol': 'TFTP',
                'honeypot_type': 'tftp',
                'method': 'UPLOAD_COMPLETE',
                'uri': session['filename'],
                'headers': {
                    'filename': session['filename'],
                    'size': len(session['data']),
                    'blocks': session['block']
                },
                'credentials': {
                    'uploaded_data_preview': session['data'][:1000].decode('utf-8', errors='replace')
                }
            }

            if self.log_callback:
                await self.log_callback(event)

            # Clean up session
            del self.sessions[addr]

    async def handle_ack(self, data: bytes, addr: tuple):
        """Handle ACK packets (for RRQ sessions)"""
        # For honeypot purposes, we don't need to track multi-block transfers
        pass

    def send_ack(self, addr: tuple, block: int):
        """Send ACK packet"""
        packet = struct.pack('!HH', OPCODE_ACK, block)
        self.transport.sendto(packet, addr)

    def send_error(self, addr: tuple, error_code: int, message: str):
        """Send ERROR packet"""
        packet = struct.pack('!HH', OPCODE_ERROR, error_code) + message.encode() + b'\x00'
        self.transport.sendto(packet, addr)

    async def send_file_data(self, addr: tuple, data: bytes):
        """Send file data in TFTP DATA packets"""
        block = 1
        offset = 0
        block_size = 512

        while offset < len(data) or block == 1:
            chunk = data[offset:offset + block_size]
            packet = struct.pack('!HH', OPCODE_DATA, block) + chunk
            self.transport.sendto(packet, addr)

            # For honeypot, we send data but don't wait for ACKs
            # Real TFTP would wait for ACK before sending next block
            offset += block_size
            block += 1

            if len(chunk) < block_size:
                break

            # Small delay between blocks
            await asyncio.sleep(0.01)

    def generate_fake_config(self, filename: str) -> Optional[bytes]:
        """Generate fake config file content based on filename"""
        filename_lower = filename.lower()

        # Polycom configs
        if 'sip.cfg' in filename_lower or filename_lower.endswith('.cfg'):
            return self.generate_polycom_config(filename)

        # Yealink configs
        if filename_lower.startswith('y0') or '.boot' in filename_lower:
            return self.generate_yealink_config(filename)

        # Grandstream
        if 'cfg' in filename_lower and 'gs' in filename_lower:
            return self.generate_grandstream_config(filename)

        # Cisco
        if 'sep' in filename_lower or 'xmldefault' in filename_lower:
            return self.generate_cisco_config(filename)

        # Generic config
        if any(ext in filename_lower for ext in ['.cfg', '.conf', '.txt', 'config', 'settings']):
            return self.generate_generic_config(filename)

        # Firmware requests - return empty/error
        if any(ext in filename_lower for ext in ['.bin', '.rom', '.ld', 'firmware']):
            return None

        return None

    def generate_polycom_config(self, filename: str) -> bytes:
        """Generate fake Polycom config"""
        config = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!-- Polycom Configuration - {filename} -->
<polycomConfig>
    <reg reg.1.address="1001" reg.1.auth.userId="1001" reg.1.auth.password="honeypot123"
         reg.1.server.1.address="sip.honeypot.local" reg.1.server.1.port="5060"/>
    <voIpProt voIpProt.server.1.address="sip.honeypot.local"/>
    <tcpIpApp tcpIpApp.sntp.address="time.honeypot.local"/>
</polycomConfig>
"""
        return config.encode('utf-8')

    def generate_yealink_config(self, filename: str) -> bytes:
        """Generate fake Yealink config"""
        config = f"""#!version:1.0.0.1
## Yealink Configuration - {filename}
account.1.enable = 1
account.1.label = Extension 1001
account.1.display_name = Honeypot User
account.1.auth_name = 1001
account.1.user_name = 1001
account.1.password = honeypot123
account.1.sip_server.1.address = sip.honeypot.local
account.1.sip_server.1.port = 5060
"""
        return config.encode('utf-8')

    def generate_grandstream_config(self, filename: str) -> bytes:
        """Generate fake Grandstream config"""
        config = f"""# Grandstream Configuration - {filename}
P270=sip.honeypot.local
P47=sip.honeypot.local
P35=1001
P36=1001
P34=honeypot123
P3=1001
P2=0
"""
        return config.encode('utf-8')

    def generate_cisco_config(self, filename: str) -> bytes:
        """Generate fake Cisco config"""
        config = f"""<?xml version="1.0" encoding="UTF-8"?>
<device>
    <devicePool>
        <callManager>
            <processNodeName>sip.honeypot.local</processNodeName>
        </callManager>
    </devicePool>
    <sipProfile>
        <sipProxies>sip.honeypot.local</sipProxies>
    </sipProfile>
</device>
"""
        return config.encode('utf-8')

    def generate_generic_config(self, filename: str) -> bytes:
        """Generate generic config"""
        config = f"""# Configuration File - {filename}
# Generated by Honeypot
server=sip.honeypot.local
port=5060
username=1001
password=honeypot123
"""
        return config.encode('utf-8')


async def run_tftp_honeypot(host: str = '0.0.0.0', port: int = 69,
                            log_callback: Callable = None):
    """Start the TFTP honeypot server"""
    logger.info(f"Starting TFTP Honeypot on {host}:{port}")

    loop = asyncio.get_event_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: TFTPHoneypot(log_callback),
        local_addr=(host, port)
    )

    logger.info(f"TFTP Honeypot started on {host}:{port}")

    try:
        # Keep running
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        transport.close()
        logger.info("TFTP Honeypot stopped")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    async def test_callback(event):
        print(f"Event: {event}")

    asyncio.run(run_tftp_honeypot(log_callback=test_callback))
