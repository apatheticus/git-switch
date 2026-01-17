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
from src.core.protocols import (
    CryptoServiceProtocol,
    ProfileManagerProtocol,
    RepositoryManagerProtocol,
    SessionManagerProtocol,
)
from src.core.settings_manager import SettingsManager

__all__ = [
    "ITERATIONS",
    "KEY_LENGTH",
    "NONCE_LENGTH",
    "SALT_LENGTH",
    # Crypto
    "CryptoService",
    # Protocols
    "CryptoServiceProtocol",
    "ProfileManagerProtocol",
    "RepositoryManagerProtocol",
    "SessionManagerProtocol",
    # Settings
    "SettingsManager",
    "secure_zero",
]
