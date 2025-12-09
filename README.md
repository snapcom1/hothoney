# HotHoney - SIP Honeypot

A comprehensive SIP/VoIP honeypot system that captures malicious traffic, wastes attacker resources, and generates IP blocklists for Juniper routers.

## Features

### Core Honeypot
- **SIP Honeypot**: Fake SIP server that captures REGISTER, INVITE, and other SIP attacks
- **Provisioning Honeypot**: Emulates Polycom, Yealink, Grandstream, and NetSapiens provisioning endpoints
- **Credential Capture**: Extracts usernames and passwords from SIP authentication attempts
- **Auto-blocking**: Automatically blocks IPs after configurable threshold of attacks

### Tarpit & Resource Wasting
- **Call Tarpitting**: Answers INVITE requests and keeps attackers on the line for 1-3 hours
- **Fake Registration Success**: Responds with 200 OK to REGISTER attempts (after capturing credentials)
- **RTP Fart Sounds**: Sends synthetic fart audio via RTP to answered calls, wasting attacker bandwidth 💨
- **Random Delays**: Randomized ring duration (5-20 seconds) before answering to appear more realistic

### Threat Intelligence
- **APIBAN Integration**: Automatically imports known SIP attackers from apiban.org
- **Auto-sync**: Configurable sync interval to keep blocklist updated
- **Throttling**: Rate limiting to prevent overwhelming the honeypot

### Web Dashboard
- **Real-time Logs**: View SIP attacks as they happen with filtering by method type
- **Active Sessions**: Monitor attackers currently being tarpitted in real-time
- **Blocklist Management**: Add, remove, import/export blocked IPs
- **Whitelist Support**: Protect your own IP ranges from blocking
- **Multi-user**: Role-based access (admin/viewer)
- **Email Alerts**: SMTP integration for attack notifications

### Export & Integration
- **Juniper Export**: Generate prefix-lists and firewall filters for Juniper routers
- **Multiple Formats**: Prefix-list, firewall filter, full config, XML (NETCONF), JSON
- **Automated Push**: Scripts to push blocklists to routers via SSH

## Quick Start

```bash
# Clone and configure
cp .env.example .env
# Edit .env with your passwords and SERVER_NAME

# Start with Docker Compose
docker-compose up -d

# Access web UI (HTTPS)
open https://your-server-name
# Default login: admin / changeme
```

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 80 | TCP | HTTP - Provisioning honeypot (via Apache) |
| 443 | TCP | HTTPS - Web UI (via Apache) |
| 5060 | UDP | SIP Honeypot |

## Architecture

```
                                        ┌──────────────────┐
                    ┌───────────────────│  Apache:80/443   │
                    │                   └────────┬─────────┘
                    │                            │
    SIP Traffic ────┼──► ┌─────────────────────┐ │
       :5060        │    │  SIP Honeypot:5060  │─┼─┐
                    │    └─────────────────────┘ │ │
                    │                            │ │
                    │    ┌─────────────────────┐ │ │  ┌──────────────┐
HTTP Provisioning ──┼───►│ HTTP Honeypot:8080  │◄┘ ├─►│   MariaDB    │
       :80          │    └─────────────────────┘   │  └──────────────┘
                    │                              │
                    │    ┌─────────────────────┐   │
  HTTPS Web UI ─────┴───►│  API Server:8081    │◄──┘
       :443              └─────────────────────┘
                                   │
                                   ▼
                         ┌─────────────────────┐
                         │  Juniper Routers    │
                         └─────────────────────┘
```

## SSL Certificates

### Self-Signed (Default)
A self-signed certificate is automatically generated on first startup. This is fine for testing but browsers will show warnings.

### Using Your Own Certificates
Place your certificates in `./apache/ssl/`:
```bash
# Copy your certificates
cp your-cert.crt apache/ssl/server.crt
cp your-key.key apache/ssl/server.key

# Restart Apache
docker-compose restart apache
```

### Using Let's Encrypt
For production, use Let's Encrypt:
```bash
# Install certbot on host
apt install certbot

# Get certificate (stop Apache first)
docker-compose stop apache
certbot certonly --standalone -d your-domain.com

# Copy certificates
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem apache/ssl/server.crt
cp /etc/letsencrypt/live/your-domain.com/privkey.pem apache/ssl/server.key

# Start Apache
docker-compose start apache
```

## Provisioning Endpoints Emulated

The honeypot responds to common provisioning paths:

### Polycom
- `/{mac}.cfg`, `/{mac}-phone.cfg`
- `/sip.cfg`, `/phone1.cfg`

### Yealink
- `/y{mac}.cfg`, `/{mac}.boot`

### Grandstream
- `/cfg{mac}`, `/cfg{mac}.xml`

### NetSapiens NDP
- `/ndp/adminlogin.php` - Admin login trap
- `/ndp/device.php` - Device registration trap
- `/portal/login.php` - User portal login trap

## Juniper Integration

### Export Formats

1. **Prefix List** - Standard prefix-list for routing policies
2. **Firewall Filter** - Direct firewall filter terms
3. **Full Config** - Both prefix-list and filter using the list
4. **XML** - NETCONF XML format
5. **JSON** - JSON-RPC format

### Manual Export

```bash
# From web UI
Navigate to Export → Select format → Download

# From command line
python scripts/export_to_juniper.py --format full --output blocklist.conf
```

### Automated Push to Router

```bash
# Configure SSH key authentication first
./scripts/push_to_router.sh router.example.com

# Add to cron for hourly updates
0 * * * * /opt/sip-honeypot/scripts/push_to_router.sh router.example.com
```

### Juniper Configuration Example

```junos
# Apply the filter to your external interface
set interfaces ge-0/0/0 unit 0 family inet filter input HONEYPOT-BLOCK

# Or use in routing policy
set policy-options policy-statement BLOCK-HONEYPOT term 1 from prefix-list HONEYPOT-BLOCKLIST
set policy-options policy-statement BLOCK-HONEYPOT term 1 then reject
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Current user info

### Blocklist
- `GET /api/blocklist` - List blocked IPs
- `POST /api/blocklist` - Add IP to blocklist
- `DELETE /api/blocklist/{ip}` - Remove IP
- `POST /api/blocklist/bulk` - Bulk import IPs

### Whitelist
- `GET /api/whitelist` - List whitelisted IPs
- `POST /api/whitelist` - Add to whitelist
- `DELETE /api/whitelist/{ip}` - Remove from whitelist

### Logs
- `GET /api/logs` - View honeypot logs

### Export
- `GET /api/export/juniper?format=full` - Preview export
- `GET /api/export/download?format=full` - Download export file

### Users (Admin only)
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| SERVER_NAME | localhost | Domain name for SSL cert |
| DB_HOST | localhost | MariaDB host |
| DB_PORT | 3306 | MariaDB port |
| DB_USER | honeypot | Database user |
| DB_PASSWORD | honeypot | Database password |
| DB_NAME | sip_honeypot | Database name |
| SIP_PORT | 5060 | SIP honeypot port |
| HTTP_PORT | 8080 | HTTP honeypot port |
| API_PORT | 8081 | Web UI/API port |
| ADMIN_USER | admin | Default admin username |
| ADMIN_PASS | changeme | Default admin password |
| AUTO_BLOCK_THRESHOLD | 3 | Hits before auto-block |

## Tarpit & RTP Details

### How Tarpitting Works

When an attacker sends an INVITE (call attempt), the honeypot:

1. **Rings** for 5-20 seconds (randomized) with 180 Ringing responses
2. **Answers** with 200 OK containing a fake SDP
3. **Holds the call** for 1-3 hours while sending RTP audio
4. **Sends fart sounds** via RTP to the attacker's media port 💨

This wastes attacker resources:
- Keeps their call leg open and tied up
- Consumes their bandwidth with RTP traffic
- Makes automated dialers wait instead of moving to next target

### Fake Registration Success

For REGISTER attacks, the honeypot:

1. Sends 401 Unauthorized with a challenge (captures credentials)
2. Accepts the auth response with 200 OK
3. Logs the captured username/password for analysis

This makes attackers think they succeeded, encouraging them to:
- Continue attacking (generating more logs)
- Attempt calls through the "registered" account
- Reveal more about their attack patterns

## APIBAN Integration

[APIBAN](https://apiban.org) provides a free, community-driven blocklist of known SIP attackers.

### Setup

1. Get a free API key from https://apiban.org
2. In the web dashboard, go to Settings → APIBAN
3. Enter your API key and enable auto-sync
4. Configure sync interval (default: 5 minutes)

The honeypot will automatically import new blocked IPs and add them to your blocklist.

## Security Notes

1. **Change default passwords** before production deployment
2. **Use real SSL certificates** for production (Let's Encrypt is free)
3. **Whitelist** your own IP ranges before deploying
4. The honeypot intentionally exposes ports 80, 443, and 5060 to attract attackers
5. Consider placing the web UI behind a VPN for additional security

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run without Docker (requires MariaDB)
python main.py

# Run individual components
python honeypot/sip_server.py
python honeypot/provisioning_server.py
python backend/api.py
```

## License

MIT License
