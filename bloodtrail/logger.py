"""
BloodTrail Debug Logger

Standalone replacement for crack.core.debug. Uses stdlib logging.
Provides the same interface (DebugLogger, Component, StepType, init_debug)
so existing code works with minimal changes.
"""

import logging
from enum import Enum

_log = logging.getLogger("bloodtrail")


class Component(Enum):
    BLOODTRAIL = "bloodtrail"
    BT_NEO4J = "bt_neo4j"
    BT_PARSER = "bt_parser"
    BT_IMPORT = "bt_import"
    BT_SPRAY = "bt_spray"
    BT_PWNED = "bt_pwned"
    BT_RECOMMEND = "bt_recommend"
    BT_QUERY = "bt_query"
    BT_CREDS = "bt_creds"


class StepType(Enum):
    PROCESSING = "processing"
    PARSING = "parsing"
    VALIDATION = "validation"
    QUERYING = "querying"
    CONNECTION = "connection"
    TOOL_CALL = "tool_call"
    IMPORT = "import"
    EXPORT = "export"
    INIT = "init"
    CLEANUP = "cleanup"
    CONFIG_LOAD = "config_load"
    RECOMMENDATION = "recommendation"
    CREDENTIAL = "credential"
    ENUMERATION = "enumeration"


class DebugLogger:
    """Drop-in replacement for crack.core.debug.DebugLogger."""

    def __init__(self, component: Component):
        self.component = component
        self._log = logging.getLogger(f"bloodtrail.{component.value}")

    def verbose(self, message, step=StepType.PROCESSING, **context):
        self._log.debug(message, extra=context)

    def info(self, message, step=StepType.PROCESSING, **context):
        self._log.info(message, extra=context)

    def warning(self, message, step=StepType.PROCESSING, **context):
        self._log.warning(message, extra=context)

    def error(self, message, step=StepType.PROCESSING, **context):
        self._log.error(message, extra=context)


def init_debug(debug_filter=None):
    """Initialize debug logging from --debug flag."""
    if not debug_filter:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s: %(message)s"))
    _log.addHandler(handler)
    _log.setLevel(logging.DEBUG)
