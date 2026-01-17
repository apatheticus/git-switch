"""Unit tests for CredentialService.

These tests verify Windows Credential Manager operations including:
- Listing Git credentials
- Deleting specific credentials
- Clearing all Git credentials
- Checking credential existence

TDD Note: These tests are written before the CredentialService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from src.services.credential_service import CredentialService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def credential_service() -> "CredentialService":
    """Create a CredentialService instance for testing."""
    from src.services.credential_service import CredentialService

    return CredentialService()


# =============================================================================
# list_git_credentials Tests
# =============================================================================


class TestListGitCredentials:
    """Tests for list_git_credentials() method."""

    def test_list_git_credentials_returns_git_targets(
        self, credential_service: "CredentialService"
    ) -> None:
        """list_git_credentials should return Git-related credential targets."""
        with patch.object(
            credential_service, "_enumerate_credentials"
        ) as mock_enum:
            mock_enum.return_value = [
                "git:https://github.com",
                "git:https://gitlab.com",
                "LegacyGeneric:target=git:https://bitbucket.org",
                "other:unrelated:credential",
            ]

            result = credential_service.list_git_credentials()

            # Should only include git-related credentials
            assert "git:https://github.com" in result
            assert "git:https://gitlab.com" in result
            assert any("bitbucket" in cred.lower() for cred in result)
            assert "other:unrelated:credential" not in result

    def test_list_git_credentials_returns_empty_when_no_credentials(
        self, credential_service: "CredentialService"
    ) -> None:
        """list_git_credentials should return empty list when no Git credentials exist."""
        with patch.object(
            credential_service, "_enumerate_credentials"
        ) as mock_enum:
            mock_enum.return_value = []

            result = credential_service.list_git_credentials()

            assert result == []


# =============================================================================
# delete_credential Tests
# =============================================================================


class TestDeleteCredential:
    """Tests for delete_credential() method."""

    def test_delete_credential_removes_specific_target(
        self, credential_service: "CredentialService"
    ) -> None:
        """delete_credential should remove a specific credential by target."""
        with patch.object(
            credential_service, "_delete_credential_impl"
        ) as mock_delete:
            mock_delete.return_value = True

            result = credential_service.delete_credential("git:https://github.com")

            assert result is True
            mock_delete.assert_called_once_with("git:https://github.com")

    def test_delete_credential_returns_false_when_not_found(
        self, credential_service: "CredentialService"
    ) -> None:
        """delete_credential should return False when credential doesn't exist."""
        with patch.object(
            credential_service, "_delete_credential_impl"
        ) as mock_delete:
            mock_delete.return_value = False

            result = credential_service.delete_credential("nonexistent:target")

            assert result is False


# =============================================================================
# clear_git_credentials Tests
# =============================================================================


class TestClearGitCredentials:
    """Tests for clear_git_credentials() method."""

    def test_clear_git_credentials_removes_all_git_credentials(
        self, credential_service: "CredentialService"
    ) -> None:
        """clear_git_credentials should remove all Git-related credentials."""
        with (
            patch.object(
                credential_service, "list_git_credentials"
            ) as mock_list,
            patch.object(
                credential_service, "delete_credential"
            ) as mock_delete,
        ):
            mock_list.return_value = [
                "git:https://github.com",
                "git:https://gitlab.com",
            ]
            mock_delete.return_value = True

            result = credential_service.clear_git_credentials()

            assert len(result) == 2
            assert "git:https://github.com" in result
            assert "git:https://gitlab.com" in result
            assert mock_delete.call_count == 2

    def test_clear_git_credentials_returns_empty_when_no_credentials(
        self, credential_service: "CredentialService"
    ) -> None:
        """clear_git_credentials should return empty list when no credentials exist."""
        with patch.object(
            credential_service, "list_git_credentials"
        ) as mock_list:
            mock_list.return_value = []

            result = credential_service.clear_git_credentials()

            assert result == []


# =============================================================================
# has_credential Tests
# =============================================================================


class TestHasCredential:
    """Tests for has_credential() method."""

    def test_has_credential_returns_true_when_exists(
        self, credential_service: "CredentialService"
    ) -> None:
        """has_credential should return True when credential exists."""
        with patch.object(
            credential_service, "_get_credential"
        ) as mock_get:
            mock_get.return_value = {"target": "git:https://github.com"}

            result = credential_service.has_credential("git:https://github.com")

            assert result is True

    def test_has_credential_returns_false_when_missing(
        self, credential_service: "CredentialService"
    ) -> None:
        """has_credential should return False when credential doesn't exist."""
        with patch.object(
            credential_service, "_get_credential"
        ) as mock_get:
            mock_get.return_value = None

            result = credential_service.has_credential("nonexistent:target")

            assert result is False


# =============================================================================
# Integration-style Tests (with mocked Windows API)
# =============================================================================


class TestCredentialServiceIntegration:
    """Tests verifying CredentialService behavior with mocked Windows API."""

    def test_credential_patterns_filter_correctly(
        self, credential_service: "CredentialService"
    ) -> None:
        """Credential filtering should identify all Git-related patterns."""
        test_credentials = [
            "git:https://github.com",
            "git:https://dev.azure.com",
            "LegacyGeneric:target=git:https://github.com",
            "WindowsLive:target=id.live.com",
            "Microsoft:Office:Settings",
        ]

        with patch.object(
            credential_service, "_enumerate_credentials"
        ) as mock_enum:
            mock_enum.return_value = test_credentials

            result = credential_service.list_git_credentials()

            # Only git-related credentials should be returned
            assert len(result) == 3
            assert all("git" in cred.lower() for cred in result)
