"""
kubeforge/utils/logger.py
─────────────────────────
Structured logger for the entire platform.
Every log line is JSON — easy to ingest into ELK, Grafana Loki, etc.
"""

import structlog
import logging
import sys


def setup_logging(debug: bool = False) -> None:
    """Call once at startup to configure structlog."""
    level = logging.DEBUG if debug else logging.INFO

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "kubeforge"):
    """Return a bound logger with the given name."""
    return structlog.get_logger(name)
