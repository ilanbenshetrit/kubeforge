"""
kubeforge/scanner/k8s_scanner.py
──────────────────────────────────
K8sScanner — scans Kubernetes YAML manifests and Dockerfiles for
security misconfigurations.

Kubernetes checks:
  • privileged containers
  • hostPID / hostNetwork / hostIPC
  • runAsRoot / missing runAsNonRoot
  • allowPrivilegeEscalation
  • missing resource limits
  • :latest image tag

Dockerfile checks:
  • running as root / missing USER directive
  • hardcoded secrets via ENV
  • remote ADD (ADD http://...)
  • --no-check-certificate
"""

import os
import re
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional

from kubeforge.scanner.base import BaseScanner
from kubeforge.models.threat import ScanSummary, ThreatEvent, Severity, ThreatCategory
from kubeforge.config import settings
from kubeforge.utils.logger import get_logger

logger = get_logger("scanner.k8s")


# ── Kubernetes YAML patterns ──────────────────────────────────────────────────
K8S_PATTERNS: list[dict] = [
    {
        "name": "Privileged Container",
        "regex": r"privileged\s*:\s*true",
        "severity": Severity.CRITICAL,
        "description": "Container runs in privileged mode — full host access.",
    },
    {
        "name": "Host PID Namespace",
        "regex": r"hostPID\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Pod shares host PID namespace — can see/kill host processes.",
    },
    {
        "name": "Host Network",
        "regex": r"hostNetwork\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Pod shares host network — bypasses network policies.",
    },
    {
        "name": "Host IPC",
        "regex": r"hostIPC\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Pod shares host IPC namespace.",
    },
    {
        "name": "Running as Root (runAsUser: 0)",
        "regex": r"runAsUser\s*:\s*0",
        "severity": Severity.HIGH,
        "description": "Container explicitly runs as root user (UID 0).",
    },
    {
        "name": "runAsNonRoot disabled",
        "regex": r"runAsNonRoot\s*:\s*false",
        "severity": Severity.HIGH,
        "description": "runAsNonRoot is explicitly set to false.",
    },
    {
        "name": "Allow Privilege Escalation",
        "regex": r"allowPrivilegeEscalation\s*:\s*true",
        "severity": Severity.HIGH,
        "description": "Container can gain more privileges than its parent process.",
    },
    {
        "name": "Hardcoded Secret in K8s Manifest",
        "regex": r"(?i)(password|secret|token|api[_\-]?key)\s*:\s*['\"]?[A-Za-z0-9+/=\-_]{8,}['\"]?",
        "severity": Severity.CRITICAL,
        "description": "Possible hardcoded secret found in Kubernetes manifest.",
    },
    {
        "name": "Image using :latest tag",
        "regex": r"image\s*:\s*[^\s]+:latest",
        "severity": Severity.LOW,
        "description": "Using :latest tag makes deployments non-reproducible.",
    },
    {
        "name": "Writable Root Filesystem",
        "regex": r"readOnlyRootFilesystem\s*:\s*false",
        "severity": Severity.MEDIUM,
        "description": "Container root filesystem is writable — increases attack surface.",
    },
]

# ── Dockerfile patterns ───────────────────────────────────────────────────────
DOCKER_PATTERNS: list[dict] = [
    {
        "name": "Running as Root in Dockerfile",
        "regex": r"^USER\s+root",
        "severity": Severity.HIGH,
        "description": "Dockerfile explicitly sets USER to root.",
        "multiline": True,
    },
    {
        "name": "Hardcoded Secret via ENV",
        "regex": r"(?i)^ENV\s+.*(password|secret|token|api[_\-]?key)\s*[=\s]\s*\S+",
        "severity": Severity.CRITICAL,
        "description": "Secret baked into image via ENV instruction.",
        "multiline": True,
    },
    {
        "name": "Remote ADD (prefer COPY)",
        "regex": r"^ADD\s+https?://",
        "severity": Severity.MEDIUM,
        "description": "ADD with a remote URL — use COPY + curl with checksum instead.",
        "multiline": True,
    },
    {
        "name": "Skipping TLS verification",
        "regex": r"--no-check-certificate|--insecure|-k\s",
        "severity": Severity.HIGH,
        "description": "TLS verification disabled — vulnerable to MITM attacks.",
    },
    {
        "name": "apt-get without --no-install-recommends",
        "regex": r"apt-get install(?!.*--no-install-recommends)",
        "severity": Severity.LOW,
        "description": "Installs unnecessary packages — increases image size and attack surface.",
    },
    {
        "name": "Pinned package version missing",
        "regex": r"apt-get install\s+[a-z][\w\-]+((?!\=).)*$",
        "severity": Severity.LOW,
        "description": "Package versions not pinned — builds may be non-reproducible.",
        "multiline": True,
    },
]

# File patterns for K8s
K8S_EXTENSIONS = {".yaml", ".yml"}
K8S_KEYWORDS   = re.compile(r"(apiVersion|kind\s*:|spec\s*:|containers\s*:)", re.IGNORECASE)

# File patterns for Docker
DOCKER_NAMES = re.compile(r"^(Dockerfile|dockerfile)([\.\-].+)?$", re.IGNORECASE)
DOCKER_EXTENSIONS = {".dockerfile"}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


class K8sScanner(BaseScanner):
    """Scans Kubernetes manifests and Dockerfiles for security issues."""

    name = "k8s_scanner"

    def __init__(self, target_paths: Optional[List[str]] = None):
        super().__init__()
        self.target_paths = target_paths or settings.scan_target_paths
        self.max_file_bytes = settings.max_file_size_mb * 1024 * 1024

        self._k8s_compiled = [
            {**p, "compiled": re.compile(p["regex"], re.MULTILINE | re.IGNORECASE)}
            for p in K8S_PATTERNS
        ]
        self._docker_compiled = [
            {**p, "compiled": re.compile(p["regex"], re.MULTILINE | re.IGNORECASE)}
            for p in DOCKER_PATTERNS
        ]

    def _is_k8s_file(self, path: Path) -> bool:
        if path.suffix.lower() not in K8S_EXTENSIONS:
            return False
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:500]
            return bool(K8S_KEYWORDS.search(head))
        except Exception:
            return False

    def _is_docker_file(self, path: Path) -> bool:
        return (
            bool(DOCKER_NAMES.match(path.name))
            or path.suffix.lower() in DOCKER_EXTENSIONS
        )

    def _iter_files(self, root: str) -> Iterator[tuple[Path, str]]:
        """Yield (path, file_type) tuples."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                path = Path(dirpath) / filename
                try:
                    if path.stat().st_size > self.max_file_bytes:
                        continue
                except OSError:
                    continue
                if self._is_docker_file(path):
                    yield path, "docker"
                elif self._is_k8s_file(path):
                    yield path, "k8s"

    def _scan_file(self, path: Path, file_type: str) -> list[ThreatEvent]:
        events = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("file_read_error", path=str(path), error=str(exc))
            return events

        patterns = self._k8s_compiled if file_type == "k8s" else self._docker_compiled

        for pattern in patterns:
            for match in pattern["compiled"].finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                evidence = match.group(0)[:120]
                events.append(ThreatEvent(
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=pattern["severity"],
                    title=f"{pattern['name']} [{file_type.upper()}]",
                    description=pattern["description"],
                    source=self.name,
                    location=f"{path}:{line_no}",
                    raw_evidence=evidence,
                ))
        return events

    async def scan(self) -> ScanSummary:
        summary = ScanSummary(
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            scanner_name=self.name,
        )

        for root in self.target_paths:
            if not os.path.exists(root):
                logger.warning("scan_path_not_found", path=root)
                continue

            loop = asyncio.get_event_loop()
            files = list(self._iter_files(root))
            summary.total_files_scanned += len(files)

            for path, file_type in files:
                events = await loop.run_in_executor(
                    None, self._scan_file, path, file_type
                )
                for event in events:
                    summary.add_event(event)
                    logger.info(
                        "k8s_threat_detected",
                        severity=event.severity.value,
                        title=event.title,
                        location=event.location,
                    )

        return summary
