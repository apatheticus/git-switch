"""Unit tests for Git-Switch exception hierarchy.

Tests verify exception inheritance, instantiation, and message handling.
"""

from __future__ import annotations

import pytest

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

# =============================================================================
# Base Exception Tests
# =============================================================================


class TestGitSwitchError:
    """Tests for the base GitSwitchError exception."""

    def test_inherits_from_exception(self) -> None:
        """GitSwitchError should inherit from Exception."""
        assert issubclass(GitSwitchError, Exception)

    def test_can_be_raised(self) -> None:
        """GitSwitchError should be raisable."""
        with pytest.raises(GitSwitchError):
            raise GitSwitchError()

    def test_can_be_raised_with_message(self) -> None:
        """GitSwitchError should accept a message."""
        message = "Test error message"
        with pytest.raises(GitSwitchError) as exc_info:
            raise GitSwitchError(message)
        assert str(exc_info.value) == message

    def test_can_catch_all_subclasses(self) -> None:
        """All custom exceptions should be catchable via GitSwitchError."""
        exceptions = [
            AuthenticationError,
            InvalidPasswordError,
            SessionExpiredError,
            EncryptionError,
            ProfileError,
            ProfileNotFoundError,
            ProfileValidationError,
            ServiceError,
            GitServiceError,
            SSHServiceError,
            GPGServiceError,
            CredentialServiceError,
            RepositoryError,
            InvalidRepositoryError,
        ]
        for exc_class in exceptions:
            with pytest.raises(GitSwitchError):
                raise exc_class("Test")


# =============================================================================
# Authentication Exception Tests
# =============================================================================


class TestAuthenticationError:
    """Tests for authentication-related exceptions."""

    def test_inherits_from_git_switch_error(self) -> None:
        """AuthenticationError should inherit from GitSwitchError."""
        assert issubclass(AuthenticationError, GitSwitchError)

    def test_can_be_raised_with_message(self) -> None:
        """AuthenticationError should accept a message."""
        message = "Authentication failed"
        with pytest.raises(AuthenticationError) as exc_info:
            raise AuthenticationError(message)
        assert str(exc_info.value) == message


class TestInvalidPasswordError:
    """Tests for InvalidPasswordError exception."""

    def test_inherits_from_authentication_error(self) -> None:
        """InvalidPasswordError should inherit from AuthenticationError."""
        assert issubclass(InvalidPasswordError, AuthenticationError)

    def test_inherits_from_git_switch_error(self) -> None:
        """InvalidPasswordError should also inherit from GitSwitchError."""
        assert issubclass(InvalidPasswordError, GitSwitchError)

    def test_can_be_raised(self) -> None:
        """InvalidPasswordError should be raisable."""
        with pytest.raises(InvalidPasswordError):
            raise InvalidPasswordError("Wrong password")


class TestSessionExpiredError:
    """Tests for SessionExpiredError exception."""

    def test_inherits_from_authentication_error(self) -> None:
        """SessionExpiredError should inherit from AuthenticationError."""
        assert issubclass(SessionExpiredError, AuthenticationError)

    def test_can_be_raised(self) -> None:
        """SessionExpiredError should be raisable."""
        with pytest.raises(SessionExpiredError):
            raise SessionExpiredError("Session timed out")


# =============================================================================
# Encryption Exception Tests
# =============================================================================


class TestEncryptionError:
    """Tests for EncryptionError exception."""

    def test_inherits_from_git_switch_error(self) -> None:
        """EncryptionError should inherit from GitSwitchError."""
        assert issubclass(EncryptionError, GitSwitchError)

    def test_can_be_raised(self) -> None:
        """EncryptionError should be raisable."""
        with pytest.raises(EncryptionError):
            raise EncryptionError("Decryption failed")


# =============================================================================
# Profile Exception Tests
# =============================================================================


class TestProfileError:
    """Tests for profile-related exceptions."""

    def test_inherits_from_git_switch_error(self) -> None:
        """ProfileError should inherit from GitSwitchError."""
        assert issubclass(ProfileError, GitSwitchError)

    def test_can_be_raised(self) -> None:
        """ProfileError should be raisable."""
        with pytest.raises(ProfileError):
            raise ProfileError("Profile operation failed")


class TestProfileNotFoundError:
    """Tests for ProfileNotFoundError exception."""

    def test_inherits_from_profile_error(self) -> None:
        """ProfileNotFoundError should inherit from ProfileError."""
        assert issubclass(ProfileNotFoundError, ProfileError)

    def test_can_be_raised(self) -> None:
        """ProfileNotFoundError should be raisable."""
        with pytest.raises(ProfileNotFoundError):
            raise ProfileNotFoundError("Profile not found")


class TestProfileValidationError:
    """Tests for ProfileValidationError exception."""

    def test_inherits_from_profile_error(self) -> None:
        """ProfileValidationError should inherit from ProfileError."""
        assert issubclass(ProfileValidationError, ProfileError)

    def test_can_be_raised(self) -> None:
        """ProfileValidationError should be raisable."""
        with pytest.raises(ProfileValidationError):
            raise ProfileValidationError("Invalid email format")


# =============================================================================
# Service Exception Tests
# =============================================================================


class TestServiceError:
    """Tests for service-related exceptions."""

    def test_inherits_from_git_switch_error(self) -> None:
        """ServiceError should inherit from GitSwitchError."""
        assert issubclass(ServiceError, GitSwitchError)

    def test_can_be_raised(self) -> None:
        """ServiceError should be raisable."""
        with pytest.raises(ServiceError):
            raise ServiceError("Service unavailable")


class TestGitServiceError:
    """Tests for GitServiceError exception."""

    def test_inherits_from_service_error(self) -> None:
        """GitServiceError should inherit from ServiceError."""
        assert issubclass(GitServiceError, ServiceError)

    def test_can_be_raised(self) -> None:
        """GitServiceError should be raisable."""
        with pytest.raises(GitServiceError):
            raise GitServiceError("Git command failed")


class TestSSHServiceError:
    """Tests for SSHServiceError exception."""

    def test_inherits_from_service_error(self) -> None:
        """SSHServiceError should inherit from ServiceError."""
        assert issubclass(SSHServiceError, ServiceError)

    def test_can_be_raised(self) -> None:
        """SSHServiceError should be raisable."""
        with pytest.raises(SSHServiceError):
            raise SSHServiceError("SSH agent not running")


class TestGPGServiceError:
    """Tests for GPGServiceError exception."""

    def test_inherits_from_service_error(self) -> None:
        """GPGServiceError should inherit from ServiceError."""
        assert issubclass(GPGServiceError, ServiceError)

    def test_can_be_raised(self) -> None:
        """GPGServiceError should be raisable."""
        with pytest.raises(GPGServiceError):
            raise GPGServiceError("GPG not installed")


class TestCredentialServiceError:
    """Tests for CredentialServiceError exception."""

    def test_inherits_from_service_error(self) -> None:
        """CredentialServiceError should inherit from ServiceError."""
        assert issubclass(CredentialServiceError, ServiceError)

    def test_can_be_raised(self) -> None:
        """CredentialServiceError should be raisable."""
        with pytest.raises(CredentialServiceError):
            raise CredentialServiceError("Credential Manager access denied")


# =============================================================================
# Repository Exception Tests
# =============================================================================


class TestRepositoryError:
    """Tests for repository-related exceptions."""

    def test_inherits_from_git_switch_error(self) -> None:
        """RepositoryError should inherit from GitSwitchError."""
        assert issubclass(RepositoryError, GitSwitchError)

    def test_can_be_raised(self) -> None:
        """RepositoryError should be raisable."""
        with pytest.raises(RepositoryError):
            raise RepositoryError("Repository operation failed")


class TestInvalidRepositoryError:
    """Tests for InvalidRepositoryError exception."""

    def test_inherits_from_repository_error(self) -> None:
        """InvalidRepositoryError should inherit from RepositoryError."""
        assert issubclass(InvalidRepositoryError, RepositoryError)

    def test_can_be_raised(self) -> None:
        """InvalidRepositoryError should be raisable."""
        with pytest.raises(InvalidRepositoryError):
            raise InvalidRepositoryError("Not a git repository")


# =============================================================================
# Exception Hierarchy Structure Tests
# =============================================================================


class TestExceptionHierarchy:
    """Tests verifying the complete exception hierarchy structure."""

    def test_authentication_branch(self) -> None:
        """Verify authentication exception branch structure."""
        # AuthenticationError -> GitSwitchError
        assert issubclass(AuthenticationError, GitSwitchError)
        # InvalidPasswordError -> AuthenticationError
        assert issubclass(InvalidPasswordError, AuthenticationError)
        # SessionExpiredError -> AuthenticationError
        assert issubclass(SessionExpiredError, AuthenticationError)

    def test_profile_branch(self) -> None:
        """Verify profile exception branch structure."""
        # ProfileError -> GitSwitchError
        assert issubclass(ProfileError, GitSwitchError)
        # ProfileNotFoundError -> ProfileError
        assert issubclass(ProfileNotFoundError, ProfileError)
        # ProfileValidationError -> ProfileError
        assert issubclass(ProfileValidationError, ProfileError)

    def test_service_branch(self) -> None:
        """Verify service exception branch structure."""
        # ServiceError -> GitSwitchError
        assert issubclass(ServiceError, GitSwitchError)
        # All service-specific errors -> ServiceError
        assert issubclass(GitServiceError, ServiceError)
        assert issubclass(SSHServiceError, ServiceError)
        assert issubclass(GPGServiceError, ServiceError)
        assert issubclass(CredentialServiceError, ServiceError)

    def test_repository_branch(self) -> None:
        """Verify repository exception branch structure."""
        # RepositoryError -> GitSwitchError
        assert issubclass(RepositoryError, GitSwitchError)
        # InvalidRepositoryError -> RepositoryError
        assert issubclass(InvalidRepositoryError, RepositoryError)

    def test_encryption_is_direct_child(self) -> None:
        """EncryptionError should be a direct child of GitSwitchError."""
        assert issubclass(EncryptionError, GitSwitchError)
        assert not issubclass(EncryptionError, ServiceError)
        assert not issubclass(EncryptionError, AuthenticationError)
