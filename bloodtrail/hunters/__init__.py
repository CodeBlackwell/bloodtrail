"""
BloodTrail Hunters - Credential and secret extraction tools.

Specialized modules for extracting credentials from:
- SQLite databases
- .NET assemblies
- Configuration files
- Registry exports
"""

from .sqlite_hunter import (
    SqliteHunter,
    SqliteHuntResult,
    ExtractedCredential,
    PasswordType,
    format_hunt_result as format_sqlite_result,
)
from .dotnet_hunter import (
    DotNetHunter,
    DotNetHuntResult,
    ExtractedSecret,
    SecretType,
    format_hunt_result as format_dotnet_result,
)
from .deleted_objects import (
    DeletedObjectsParser,
    DeletedObjectsResult,
    DeletedObject,
    ObjectType,
    format_deleted_objects_result,
)

__all__ = [
    # SQLite
    "SqliteHunter",
    "SqliteHuntResult",
    "ExtractedCredential",
    "PasswordType",
    "format_sqlite_result",
    # .NET
    "DotNetHunter",
    "DotNetHuntResult",
    "ExtractedSecret",
    "SecretType",
    "format_dotnet_result",
    # Deleted Objects
    "DeletedObjectsParser",
    "DeletedObjectsResult",
    "DeletedObject",
    "ObjectType",
    "format_deleted_objects_result",
]
