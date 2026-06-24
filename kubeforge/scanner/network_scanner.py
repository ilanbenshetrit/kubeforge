"""
kubeforge/scanner/network_scanner.py
──────────────────────────────────────
NetworkScanner — scans hosts for open ports and flags risky services.

Checks common dangerous ports:
  22   SSH
  23   Telnet (unencrypted)
  3306 MySQL exposed
  5432 PostgreSQL exposed
  6379 Redis (no auth by default)
  27017 MongoDB (no auth by default)
  9200 Elasticsearch (no auth by default)
  8080/8443 Admin panels
  2375/2376 Docker daemon (critical if exposed)
  10250 Kubernetes kubelet API
  etcd 2379/2380
"""

import asyncio
import socket
from datetime import datetime
from typing import Optional, List

from kubeforge.scanner.base import BaseScanner
from kubeforge.models.threat import ScanSummary, ThreatEvent, Severity, ThreatCategory
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.network")

RISKY_PORTS: list[dict] = [
    {"port": 23,    "name": "Telnet",               "severity": Severity.CRITICAL,
     "description": "Telnet is unencrypted — credentials sent in plain text."},
    {"port": 2375,  "name": "Docker Daemon (HTTP)",  "severity": Severity.CRITICAL,
     "description": "Docker daemon exposed without TLS — full container/host control."},
    {"port": 2376,  "name": "Docker Daemon (TLS)",   "severity": Severity.HIGH,
     "description": "Docker daemon exposed with TLS — verify access control."},
    {"port": 6379,  "name": "Redis",                 "severity": Severity.CRITICAL,
     "description": "Redis exposed — often runs without authentication by default."},
    {"port": 27017, "name": "MongoDB",               "severity": Severity.CRITICAL,
     "description": "MongoDB exposed — may be accessible without authentication."},
    {"port": 9200,  "name": "Elasticsearch",         "severity": Severity.CRITICAL,
     "description": "Elasticsearch exposed — data readable without authentication."},
    {"port": 2379,  "name": "etcd",                  "severity": Severity.CRITICAL,
     "description": "etcd exposed — contains Kubernetes secrets and config."},
    {"port": 2380,  "name": "etcd peer",             "severity": Severity.HIGH,
     "description": "etcd peer port exposed."},
    {"port": 10250, "name": "Kubernetes Kubelet API","severity": Severity.CRITICAL,
     "description": "Kubelet API exposed — can execute commands in any pod."},
    {"port": 10255, "name": "Kubernetes Kubelet (read-only)", "severity": Severity.HIGH,
     "description": "Kubelet read-only port exposed — leaks pod/node info."},
    {"port": 3306,  "name": "MySQL",                 "severity": Severity.HIGH,
     "description": "MySQL database port exposed to network."},
    {"port": 5432,  "name": "PostgreSQL",            "severity": Severity.HIGH,
     "description": "PostgreSQL database port exposed to network."},
    {"port": 1433,  "name": "MSSQL",                 "severity": Severity.HIGH,
     "description": "SQL Server port exposed to network."},
    {"port": 5984,  "name": "CouchDB",               "severity": Severity.HIGH,
     "description": "CouchDB exposed — may be accessible without authentication."},
    {"port": 8500,  "name": "Consul",                "severity": Severity.HIGH,
     "description": "HashiCorp Consul API exposed."},
    {"port": 4848,  "name": "GlassFish Admin",       "severity": Severity.HIGH,
     "description": "GlassFish admin console exposed."},
    {"port": 8080,  "name": "HTTP Alt / Admin Panel", "severity": Severity.MEDIUM,
     "description": "Alternative HTTP port open — may expose admin panel."},
    {"port": 8443,  "name": "HTTPS Alt / Admin Panel","severity": Severity.MEDIUM,
     "description": "Alternative HTTPS port open — may expose admin panel."},
    {"port": 22,    "name": "SSH",                   "severity": Severity.LOW,
     "description": "SSH port open — ensure key-based auth and no root login."},
    {"port": 21,    "name": "FTP",                   "severity": Severity.HIGH,
     "description": "FTP is unencrypted — use SFTP instead."},
    {"port": 25,    "name": "SMTP",                  "severity": Severity.MEDIUM,
     "description": "SMTP port open — verify relay restrictions."},
]

DEFAULT_TIMEOUT = 1.5  # seconds per port


async def _check_port(host: str, port: int, timeout: float) -> bool:
    """Return True if the port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


class NetworkScanner(BaseScanner):
    """Scans hosts for open risky ports."""

    name = "network_scanner"

    def __init__(self, hosts: Optional[List[str]] = None):
        super().__init__()
        self.hosts = hosts or settings.network_scan_hosts

    async def scan(self) -> ScanSummary:
        summary = ScanSummary(
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            scanner_name=self.name,
        )

        if not self.hosts:
            logger.info("network_scan_skipped", reason="no hosts configured")
            return summary

        for host in self.hosts:
            logger.info("network_scanning_host", host=host)
            summary.total_files_scanned += 1  # reuse counter for hosts

            # Check all risky ports concurrently
            tasks = [
                _check_port(host, p["port"], DEFAULT_TIMEOUT)
                for p in RISKY_PORTS
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for port_def, is_open in zip(RISKY_PORTS, results):
                if is_open is True:
                    event = ThreatEvent(
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=port_def["severity"],
                        title=f"Open Port: {port_def['name']} ({port_def['port']})",
                        description=port_def["description"],
                        source=self.name,
                        location=f"{host}:{port_def['port']}",
                        raw_evidence=f"{host}:{port_def['port']} is OPEN",
                    )
                    summary.add_event(event)
                    logger.info(
                        "open_port_found",
                        host=host,
                        port=port_def["port"],
                        service=port_def["name"],
                        severity=port_def["severity"].value,
                    )

        return summary
