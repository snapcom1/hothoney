#!/usr/bin/env python3
"""
Standalone script to export blocklist to Juniper routers
Can be run via cron for automated updates

Usage:
    python export_to_juniper.py --format full --output /path/to/blocklist.conf
    python export_to_juniper.py --format prefix-list --push-to router.example.com
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from database import Database, BlocklistManager
from juniper_export import export_blocklist, JuniperExporter


async def main():
    parser = argparse.ArgumentParser(description='Export honeypot blocklist for Juniper routers')
    parser.add_argument('--format', choices=['prefix-list', 'filter', 'full', 'xml', 'json', 'simple'],
                        default='full', help='Export format')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--prefix-name', default='HONEYPOT-BLOCKLIST', help='Prefix list name')
    parser.add_argument('--filter-name', default='HONEYPOT-BLOCK', help='Filter name')

    # Database connection
    parser.add_argument('--db-host', default=os.getenv('DB_HOST', 'localhost'))
    parser.add_argument('--db-port', type=int, default=int(os.getenv('DB_PORT', 3306)))
    parser.add_argument('--db-user', default=os.getenv('DB_USER', 'honeypot'))
    parser.add_argument('--db-password', default=os.getenv('DB_PASSWORD', 'honeypot'))
    parser.add_argument('--db-name', default=os.getenv('DB_NAME', 'sip_honeypot'))

    args = parser.parse_args()

    # Connect to database
    db = Database(
        host=args.db_host,
        port=args.db_port,
        user=args.db_user,
        password=args.db_password,
        database=args.db_name
    )

    try:
        await db.connect()
        blocklist = BlocklistManager(db)

        # Get blocked IPs
        ips = await blocklist.get_blocked_ips(active_only=True, limit=50000)
        print(f"# Exporting {len(ips)} blocked IPs", file=sys.stderr)

        # Generate export
        output = export_blocklist(
            ips,
            format=args.format,
            prefix_list_name=args.prefix_name,
            filter_name=args.filter_name
        )

        # Output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"# Written to {args.output}", file=sys.stderr)
        else:
            print(output)

    finally:
        await db.close()


if __name__ == '__main__':
    asyncio.run(main())
