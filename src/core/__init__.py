"""Core business logic for Git-Switch.

This module contains the profile manager, session manager,
cryptographic operations, and repository management logic.
"""

from src.core.crypto import (
    ITERATIONS,
    KEY_LENGTH,
    NONCE_LENGTH,
    SALT_LENGTH,
    CryptoService,
    secure_zero,
)
from src.core.import_export import (
    ARCHIVE_MAGIC,
    ARCHIVE_VERSION,
    ExportResult,
    ImportExportService,
    ImportResult,
)
from src.core.protocols import (
    CryptoServiceProtocol,
    ProfileManagerProtocol,
    RepositoryManagerProtocol,
    SessionManagerProtocol,
)
from src.core.repository_manager import RepositoryManager
from src.core.settings_manager import SettingsManager

__all__ = [
    "ARCHIVE_MAGIC",
    "ARCHIVE_VERSION",
    # Crypto
    "CryptoService",
    # Protocols
    "CryptoServiceProtocol",
    "ExportResult",
    "ITERATIONS",
    # Import/Export
    "ImportExportService",
    "ImportResult",
    "KEY_LENGTH",
    "NONCE_LENGTH",
    "ProfileManagerProtocol",
    # Repository
    "RepositoryManager",
    "RepositoryManagerProtocol",
    "SALT_LENGTH",
    "SessionManagerProtocol",
    # Settings
    "SettingsManager",
    "secure_zero",
]
