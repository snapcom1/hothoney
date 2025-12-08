# Juniper SRX Honeypot Blocklist Integration

## Available Feed URLs

| URL | Description |
|-----|-------------|
| `/api/public/juniper-feed` | Clean IP list with prefixes (IP/32 or IP/128) |
| `/api/public/juniper-prefixlist` | Full Junos prefix-list config format |
| `/api/public/juniper-prefixlist?name=CUSTOM` | Custom prefix-list name (creates CUSTOM-V4 and CUSTOM-V6) |

## Quick Setup

### 1. Install the Op Script

Copy `update-honeypot-blocklist.slax` to your SRX:

```bash
scp update-honeypot-blocklist.slax user@srx:/var/db/scripts/op/
```

### 2. Configure the Script

```junos
set system scripts op file update-honeypot-blocklist.slax
set system scripts language slax
```

### 3. Run Manually (Test)

```junos
op update-honeypot-blocklist
```

### 4. Schedule Automatic Updates (Hourly)

```junos
set event-options generate-event HONEYPOT-UPDATE time-interval 3600
set event-options policy UPDATE-HONEYPOT-BLOCKLIST events HONEYPOT-UPDATE
set event-options policy UPDATE-HONEYPOT-BLOCKLIST then event-script update-honeypot-blocklist.slax
set system scripts op file update-honeypot-blocklist.slax
```

### 5. Create Firewall Filters

```junos
# IPv4 filter
set firewall family inet filter BLOCK-SIP-ATTACKERS term HONEYPOT from source-prefix-list HONEYPOT-BLOCKLIST-V4
set firewall family inet filter BLOCK-SIP-ATTACKERS term HONEYPOT then discard
set firewall family inet filter BLOCK-SIP-ATTACKERS term HONEYPOT then count honeypot-blocked
set firewall family inet filter BLOCK-SIP-ATTACKERS term HONEYPOT then log
set firewall family inet filter BLOCK-SIP-ATTACKERS term ACCEPT then accept

# IPv6 filter
set firewall family inet6 filter BLOCK-SIP-ATTACKERS-V6 term HONEYPOT from source-prefix-list HONEYPOT-BLOCKLIST-V6
set firewall family inet6 filter BLOCK-SIP-ATTACKERS-V6 term HONEYPOT then discard
set firewall family inet6 filter BLOCK-SIP-ATTACKERS-V6 term HONEYPOT then count honeypot-blocked-v6
set firewall family inet6 filter BLOCK-SIP-ATTACKERS-V6 term HONEYPOT then log
set firewall family inet6 filter BLOCK-SIP-ATTACKERS-V6 term ACCEPT then accept
```

### 6. Apply to Interface

```junos
set interfaces ge-0/0/0 unit 0 family inet filter input BLOCK-SIP-ATTACKERS
set interfaces ge-0/0/0 unit 0 family inet6 filter input BLOCK-SIP-ATTACKERS-V6
```

## Verification

```junos
# Check prefix-list contents
show configuration policy-options prefix-list HONEYPOT-BLOCKLIST-V4
show configuration policy-options prefix-list HONEYPOT-BLOCKLIST-V6

# Check filter counters
show firewall filter BLOCK-SIP-ATTACKERS
show firewall filter BLOCK-SIP-ATTACKERS-V6

# View logs
show firewall log
```

## Troubleshooting

### Script won't run
- Ensure SLAX language is enabled: `set system scripts language slax`
- Check script permissions: `ls -la /var/db/scripts/op/`

### Can't fetch URL
- Test connectivity: `run request url https://hothoney.snapcom.com/api/public/juniper-feed`
- Check DNS resolution
- Verify no firewall blocking outbound HTTPS

### Empty prefix-lists
- Check the feed URL returns data
- Look for errors in script output
