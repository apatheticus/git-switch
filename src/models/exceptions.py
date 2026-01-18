"""Exception hierarchy for Git-Switch.

This module defines all custom exceptions used throughout the application.
All exceptions inherit from GitSwitchError to enable catch-all error handling.
"""

from __future__ import annotations


class GitSwitchError(Exception):
    """Base exception for all Git-Switch errors.

    All application-specific exceptions should inherit from this class
    to enable catch-all error handling at the top level.
    """


# =============================================================================
# Authentication Errors
# =============================================================================


class AuthenticationError(GitSwitchError):
    """Authentication-related errors.

    Base class for all authentication failures including password
    verification and session management.
    """


class InvalidPasswordError(AuthenticationError):
    """Incorrect master password.

    Raised when the provided master password does not match
    the stored verification hash.
    """


class SessionExpiredError(AuthenticationError):
    """Session has timed out.

    Raised when attempting to access protected resources
    after the session auto-lock timeout has elapsed.
    """


# =============================================================================
# Encryption Errors
# =============================================================================


class EncryptionError(GitSwitchError):
    """Encryption/decryption failures.

    Raised when AES-256-GCM encryption or decryption fails,
    which may indicate wrong key or tampered data.
    """


# =============================================================================
# Profile Errors
# =============================================================================


class ProfileError(GitSwitchError):
    """Profile-related errors.

    Base class for all profile management failures.
    """


class ProfileNotFoundError(ProfileError):
    """Profile does not exist.

    Raised when attempting to access or modify a profile
    that is not found in the profile store.
    """


class ProfileValidationError(ProfileError):
    """Profile data validation failed.

    Raised when profile data does not meet validation requirements
    such as missing required fields or invalid email format.
    """


# =============================================================================
# Service Errors
# =============================================================================


class ServiceError(GitSwitchError):
    """External service interaction errors.

    Base class for all failures when interacting with
    external services (Git, SSH, GPG, credentials).
    """


class GitServiceError(ServiceError):
    """Git configuration errors.

    Raised when git commands fail or git configuration
    cannot be read or written.
    """


class SSHServiceError(ServiceError):
    """SSH agent errors.

    Raised when ssh-agent service interaction fails,
    including key addition and removal operations.
    """


class GPGServiceError(ServiceError):
    """GPG keyring errors.

    Raised when GPG operations fail, including key import,
    export, and signing verification.
    """


class CredentialServiceError(ServiceError):
    """Windows Credential Manager errors.

    Raised when Windows Credential Manager operations fail,
    including credential enumeration and deletion.
    """


# =============================================================================
# Repository Errors
# =============================================================================


class RepositoryError(GitSwitchError):
    """Repository-related errors.

    Base class for all repository management failures.
    """


class InvalidRepositoryError(RepositoryError):
    """Path is not a valid Git repository.

    Raised when a path does not contain a .git directory
    or is not accessible as a Git repository.
    """


# =============================================================================
# Import/Export Errors
# =============================================================================


class ImportExportError(GitSwitchError):
    """Base exception for import/export operations.

    Base class for all failures related to profile import
    and export functionality.
    """


class InvalidArchiveError(ImportExportError):
    """Archive file is invalid or corrupted.

    Raised when an archive file has an invalid magic number,
    unsupported version, or corrupted data structure.
    """


class ArchivePasswordError(ImportExportError):
    """Archive password is incorrect.

    Raised when the provided password cannot decrypt
    the archive contents.
    """


__all__ = [
    # Import/Export
    "ArchivePasswordError",
    # Authentication
    "AuthenticationError",
    "CredentialServiceError",
    # Encryption
    "EncryptionError",
    "GPGServiceError",
    "GitServiceError",
    # Base
    "GitSwitchError",
    # Import/Export
    "ImportExportError",
    "InvalidArchiveError",
    "InvalidPasswordError",
    "InvalidRepositoryError",
    # Profile
    "ProfileError",
    "ProfileNotFoundError",
    "ProfileValidationError",
    # Repository
    "RepositoryError",
    "SSHServiceError",
    # Service
    "ServiceError",
    "SessionExpiredError",
]
