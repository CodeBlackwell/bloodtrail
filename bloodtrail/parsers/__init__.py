"""
BloodTrail Parsers Module

Config file parsers for credential extraction from common formats:
- Azure PowerShell XML (PSADPasswordCredential)
- Web.config / App.config (.NET connection strings)
- Unattend.xml (Windows deployment)
- Groups.xml (GPP passwords)
- .env files
- Generic JSON with password/secret fields

Each parser extracts credentials AND suggests next steps for exploitation.
"""

from .config_parser import (
    ConfigParserBase,
    ConfigParserRegistry,
    ExtractionResult,
    NextStep,
    # Concrete parsers
    AzurePSCredentialParser,
    WebConfigParser,
    UnattendXmlParser,
    GroupsPolicyParser,
    EnvFileParser,
    GenericJsonParser,
    GenericXmlParser,
    # Convenience
    get_default_registry,
    extract_from_file,
    extract_from_content,
)

__all__ = [
    "ConfigParserBase",
    "ConfigParserRegistry",
    "ExtractionResult",
    "NextStep",
    "AzurePSCredentialParser",
    "WebConfigParser",
    "UnattendXmlParser",
    "GroupsPolicyParser",
    "EnvFileParser",
    "GenericJsonParser",
    "GenericXmlParser",
    "get_default_registry",
    "extract_from_file",
    "extract_from_content",
]
