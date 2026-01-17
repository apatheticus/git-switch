"""Data models for Git-Switch.

This module contains dataclasses for Profile, Repository, Settings,
and related entities with validation rules.
"""

from src.models.exceptions import (
    AuthenticationError,
    CredentialServiceError,
    EncryptionError,
    GitServiceError,
    GitSwitchError,
    GPGServiceError,
    InvalidPasswordError,
    InvalidRepositoryError,
    ProfileError,
    ProfileNotFoundError,
    ProfileValidationError,
    RepositoryError,
    ServiceError,
    SessionExpiredError,
    SSHServiceError,
)
from src.models.profile import GPGKey, Profile, SSHKey
from src.models.repository import Repository
from src.models.serialization import (
    GitSwitchEncoder,
    deserialize_bytes,
    deserialize_datetime,
    deserialize_path,
    deserialize_uuid,
    serialize,
)
from src.models.settings import MasterKeyConfig, Settings

__all__ = [
    "AuthenticationError",
    "CredentialServiceError",
    "EncryptionError",
    "GPGKey",
    "GPGServiceError",
    "GitServiceError",
    # Serialization
    "GitSwitchEncoder",
    # Exceptions
    "GitSwitchError",
    "InvalidPasswordError",
    "InvalidRepositoryError",
    "MasterKeyConfig",
    "Profile",
    "ProfileError",
    "ProfileNotFoundError",
    "ProfileValidationError",
    # Repository
    "Repository",
    "RepositoryError",
    # Profile models
    "SSHKey",
    "SSHServiceError",
    "ServiceError",
    "SessionExpiredError",
    # Settings
    "Settings",
    "deserialize_bytes",
    "deserialize_datetime",
    "deserialize_path",
    "deserialize_uuid",
    "serialize",
]
