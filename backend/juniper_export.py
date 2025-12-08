#!/usr/bin/env python3
"""
Juniper Router Export Module
Generates prefix-lists and firewall filter configurations
"""

from datetime import datetime
from typing import List, Dict


class JuniperExporter:
    """Export blocked IPs to Juniper router formats"""

    def __init__(self, prefix_list_name: str = "HONEYPOT-BLOCKLIST",
                 filter_name: str = "HONEYPOT-BLOCK"):
        self.prefix_list_name = prefix_list_name
        self.filter_name = filter_name

    def generate_prefix_list(self, ips: List[Dict], include_comments: bool = True) -> str:
        """
        Generate Juniper prefix-list configuration

        Example output:
        set policy-options prefix-list HONEYPOT-BLOCKLIST 1.2.3.4/32
        set policy-options prefix-list HONEYPOT-BLOCKLIST 5.6.7.8/32
        """
        lines = []

        if include_comments:
            lines.append(f"# Honeypot Blocklist - Generated {datetime.utcnow().isoformat()}")
            lines.append(f"# Total IPs: {len(ips)}")
            lines.append("")

        for entry in ips:
            ip = entry.get('ip_address', entry) if isinstance(entry, dict) else entry
            # Ensure /32 for single IPs
            if '/' not in ip:
                ip = f"{ip}/32"

            line = f"set policy-options prefix-list {self.prefix_list_name} {ip}"

            if include_comments and isinstance(entry, dict):
                reason = entry.get('reason', '')
                if reason:
                    line += f"  # {reason[:50]}"

            lines.append(line)

        return '\n'.join(lines)

    def generate_prefix_list_delete(self) -> str:
        """Generate command to delete existing prefix-list"""
        return f"delete policy-options prefix-list {self.prefix_list_name}"

    def generate_filter_terms(self, ips: List[Dict], include_comments: bool = True) -> str:
        """
        Generate Juniper firewall filter configuration

        Example output:
        set firewall family inet filter HONEYPOT-BLOCK term BLOCK-1 from source-address 1.2.3.4/32
        set firewall family inet filter HONEYPOT-BLOCK term BLOCK-1 then discard
        """
        lines = []

        if include_comments:
            lines.append(f"# Honeypot Firewall Filter - Generated {datetime.utcnow().isoformat()}")
            lines.append(f"# Total IPs: {len(ips)}")
            lines.append("")

        # Create individual terms for each IP (or batch them)
        for i, entry in enumerate(ips, 1):
            ip = entry.get('ip_address', entry) if isinstance(entry, dict) else entry
            if '/' not in ip:
                ip = f"{ip}/32"

            term_name = f"BLOCK-{i}"

            if include_comments and isinstance(entry, dict):
                reason = entry.get('reason', '')
                if reason:
                    lines.append(f"# {reason[:80]}")

            lines.append(f"set firewall family inet filter {self.filter_name} term {term_name} from source-address {ip}")
            lines.append(f"set firewall family inet filter {self.filter_name} term {term_name} then discard")

        # Add default accept term at the end
        lines.append("")
        lines.append(f"# Default accept term")
        lines.append(f"set firewall family inet filter {self.filter_name} term ACCEPT-ALL then accept")

        return '\n'.join(lines)

    def generate_filter_with_prefix_list(self, include_comments: bool = True) -> str:
        """
        Generate filter that references the prefix-list (more efficient)

        Example output:
        set firewall family inet filter HONEYPOT-BLOCK term BLOCK-HONEYPOT from source-prefix-list HONEYPOT-BLOCKLIST
        set firewall family inet filter HONEYPOT-BLOCK term BLOCK-HONEYPOT then discard
        set firewall family inet filter HONEYPOT-BLOCK term ACCEPT-ALL then accept
        """
        lines = []

        if include_comments:
            lines.append(f"# Honeypot Firewall Filter (using prefix-list)")
            lines.append(f"# Generated {datetime.utcnow().isoformat()}")
            lines.append("")

        lines.append(f"set firewall family inet filter {self.filter_name} term BLOCK-HONEYPOT from source-prefix-list {self.prefix_list_name}")
        lines.append(f"set firewall family inet filter {self.filter_name} term BLOCK-HONEYPOT then discard")
        lines.append(f"set firewall family inet filter {self.filter_name} term ACCEPT-ALL then accept")

        return '\n'.join(lines)

    def generate_full_config(self, ips: List[Dict], include_comments: bool = True) -> str:
        """Generate complete configuration with both prefix-list and filter"""
        sections = []

        if include_comments:
            sections.append("# ================================================")
            sections.append("# SIP Honeypot Blocklist - Juniper Configuration")
            sections.append(f"# Generated: {datetime.utcnow().isoformat()}")
            sections.append(f"# Total Blocked IPs: {len(ips)}")
            sections.append("# ================================================")
            sections.append("")

        # Prefix list
        sections.append("# === PREFIX LIST ===")
        sections.append(self.generate_prefix_list(ips, include_comments=False))
        sections.append("")

        # Filter using prefix list
        sections.append("# === FIREWALL FILTER (using prefix-list) ===")
        sections.append(self.generate_filter_with_prefix_list(include_comments=False))
        sections.append("")

        # Application hint
        if include_comments:
            sections.append("# === APPLICATION ===")
            sections.append("# Apply filter to interface:")
            sections.append("# set interfaces ge-0/0/0 unit 0 family inet filter input HONEYPOT-BLOCK")
            sections.append("")

        return '\n'.join(sections)

    def generate_rollback_config(self) -> str:
        """Generate commands to remove the honeypot configuration"""
        lines = [
            "# Rollback commands - Remove honeypot blocklist",
            f"delete policy-options prefix-list {self.prefix_list_name}",
            f"delete firewall family inet filter {self.filter_name}",
        ]
        return '\n'.join(lines)


class JuniperAPIExporter:
    """Export in formats suitable for Juniper API/automation"""

    def __init__(self, prefix_list_name: str = "HONEYPOT-BLOCKLIST"):
        self.prefix_list_name = prefix_list_name

    def to_json_rpc(self, ips: List[Dict]) -> dict:
        """Generate JSON-RPC format for Juniper API"""
        prefix_list_entries = []
        for entry in ips:
            ip = entry.get('ip_address', entry) if isinstance(entry, dict) else entry
            if '/' not in ip:
                ip = f"{ip}/32"
            prefix_list_entries.append({"name": ip})

        return {
            "configuration": {
                "policy-options": {
                    "prefix-list": {
                        "name": self.prefix_list_name,
                        "prefix-list-item": prefix_list_entries
                    }
                }
            }
        }

    def to_xml(self, ips: List[Dict]) -> str:
        """Generate XML format for NETCONF"""
        entries = []
        for entry in ips:
            ip = entry.get('ip_address', entry) if isinstance(entry, dict) else entry
            if '/' not in ip:
                ip = f"{ip}/32"
            entries.append(f"            <prefix-list-item><name>{ip}</name></prefix-list-item>")

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <policy-options>
        <prefix-list>
            <name>{self.prefix_list_name}</name>
{chr(10).join(entries)}
        </prefix-list>
    </policy-options>
</configuration>
"""

    def to_simple_list(self, ips: List[Dict]) -> str:
        """Generate simple IP list (one per line)"""
        lines = []
        for entry in ips:
            ip = entry.get('ip_address', entry) if isinstance(entry, dict) else entry
            lines.append(ip)
        return '\n'.join(lines)


def export_blocklist(ips: List[Dict], format: str = 'prefix-list',
                     prefix_list_name: str = "HONEYPOT-BLOCKLIST",
                     filter_name: str = "HONEYPOT-BLOCK") -> str:
    """
    Export blocklist in specified format

    Formats:
    - prefix-list: Juniper prefix-list commands
    - filter: Juniper firewall filter terms
    - full: Complete config with prefix-list and filter
    - xml: NETCONF XML format
    - json: JSON-RPC format
    - simple: Plain IP list
    """
    exporter = JuniperExporter(prefix_list_name, filter_name)
    api_exporter = JuniperAPIExporter(prefix_list_name)

    formats = {
        'prefix-list': lambda: exporter.generate_prefix_list(ips),
        'filter': lambda: exporter.generate_filter_terms(ips),
        'full': lambda: exporter.generate_full_config(ips),
        'xml': lambda: api_exporter.to_xml(ips),
        'json': lambda: str(api_exporter.to_json_rpc(ips)),
        'simple': lambda: api_exporter.to_simple_list(ips),
    }

    if format not in formats:
        raise ValueError(f"Unknown format: {format}. Available: {list(formats.keys())}")

    return formats[format]()
