"""Unit tests for GitService.

These tests verify Git configuration operations including:
- Checking if Git is installed
- Reading/writing global Git config
- Reading/writing local (repository) Git config

TDD Note: These tests are written before the GitService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from src.services.git_service import GitService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def git_service() -> "GitService":
    """Create a GitService instance for testing."""
    from src.services.git_service import GitService

    return GitService()


@pytest.fixture
def mock_subprocess() -> MagicMock:
    """Create a mock for subprocess.run."""
    return MagicMock()


# =============================================================================
# is_git_installed Tests
# =============================================================================


class TestIsGitInstalled:
    """Tests for is_git_installed() method."""

    def test_is_git_installed_returns_true_when_git_available(
        self, git_service: "GitService"
    ) -> None:
        """is_git_installed should return True when git is in PATH."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/git"

            result = git_service.is_git_installed()

            assert result is True
            mock_which.assert_called_once_with("git")

    def test_is_git_installed_returns_false_when_git_missing(
        self, git_service: "GitService"
    ) -> None:
        """is_git_installed should return False when git is not in PATH."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None

            result = git_service.is_git_installed()

            assert result is False


# =============================================================================
# get_global_config Tests
# =============================================================================


class TestGetGlobalConfig:
    """Tests for get_global_config() method."""

    def test_get_global_config_returns_current_values(
        self, git_service: "GitService"
    ) -> None:
        """get_global_config should return current global Git configuration."""
        with patch("subprocess.run") as mock_run:
            # Mock different config values for each call
            mock_results = {
                "user.name": MagicMock(
                    returncode=0, stdout="Test User\n", stderr=""
                ),
                "user.email": MagicMock(
                    returncode=0, stdout="test@example.com\n", stderr=""
                ),
                "user.signingkey": MagicMock(
                    returncode=0, stdout="ABCD1234\n", stderr=""
                ),
                "commit.gpgsign": MagicMock(
                    returncode=0, stdout="true\n", stderr=""
                ),
            }

            def side_effect(cmd, **kwargs):
                key = cmd[-1]  # Last argument is the config key
                return mock_results.get(key, MagicMock(returncode=1, stdout="", stderr=""))

            mock_run.side_effect = side_effect

            result = git_service.get_global_config()

            assert result["user.name"] == "Test User"
            assert result["user.email"] == "test@example.com"
            assert result["user.signingkey"] == "ABCD1234"
            assert result["commit.gpgsign"] == "true"


# =============================================================================
# set_global_config Tests
# =============================================================================


class TestSetGlobalConfig:
    """Tests for set_global_config() method."""

    def test_set_global_config_updates_user_name_and_email(
        self, git_service: "GitService"
    ) -> None:
        """set_global_config should update user.name and user.email."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            git_service.set_global_config(
                username="New User",
                email="new@example.com",
            )

            # Verify git config commands were called
            calls = mock_run.call_args_list
            assert any("user.name" in str(call) and "New User" in str(call) for call in calls)
            assert any("user.email" in str(call) and "new@example.com" in str(call) for call in calls)

    def test_set_global_config_with_gpg_signing(
        self, git_service: "GitService"
    ) -> None:
        """set_global_config should set GPG signing config when provided."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            git_service.set_global_config(
                username="New User",
                email="new@example.com",
                signing_key="ABCD1234EFGH5678",
                gpg_sign=True,
            )

            calls = mock_run.call_args_list
            assert any("user.signingkey" in str(call) and "ABCD1234EFGH5678" in str(call) for call in calls)
            assert any("commit.gpgsign" in str(call) and "true" in str(call) for call in calls)

    def test_set_global_config_unsets_signing_key_when_none(
        self, git_service: "GitService"
    ) -> None:
        """set_global_config should unset signing key when None provided."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            git_service.set_global_config(
                username="New User",
                email="new@example.com",
                signing_key=None,
                gpg_sign=False,
            )

            calls = mock_run.call_args_list
            # Should call --unset for signing key or set gpgsign to false
            call_strs = [str(call) for call in calls]
            assert any("commit.gpgsign" in s and "false" in s for s in call_strs)


# =============================================================================
# get_local_config Tests
# =============================================================================


class TestGetLocalConfig:
    """Tests for get_local_config() method."""

    def test_get_local_config_returns_repository_values(
        self, git_service: "GitService", mock_git_repo: Path
    ) -> None:
        """get_local_config should return local repository configuration."""
        with patch("subprocess.run") as mock_run:
            mock_results = {
                "user.name": MagicMock(
                    returncode=0, stdout="Repo User\n", stderr=""
                ),
                "user.email": MagicMock(
                    returncode=0, stdout="repo@example.com\n", stderr=""
                ),
            }

            def side_effect(cmd, **kwargs):
                key = cmd[-1]
                return mock_results.get(key, MagicMock(returncode=1, stdout="", stderr=""))

            mock_run.side_effect = side_effect

            result = git_service.get_local_config(mock_git_repo)

            assert result["user.name"] == "Repo User"
            assert result["user.email"] == "repo@example.com"


# =============================================================================
# set_local_config Tests
# =============================================================================


class TestSetLocalConfig:
    """Tests for set_local_config() method."""

    def test_set_local_config_updates_repository_config(
        self, git_service: "GitService", mock_git_repo: Path
    ) -> None:
        """set_local_config should update repository-specific configuration."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            git_service.set_local_config(
                repo_path=mock_git_repo,
                username="Repo User",
                email="repo@example.com",
            )

            calls = mock_run.call_args_list
            # Verify --local flag or cwd is set to repo_path
            assert len(calls) > 0
            assert any("user.name" in str(call) for call in calls)

    def test_set_local_config_raises_invalid_repository_error(
        self, git_service: "GitService", temp_dir: Path
    ) -> None:
        """set_local_config should raise InvalidRepositoryError for non-repo path."""
        from src.models.exceptions import InvalidRepositoryError

        non_repo_path = temp_dir / "not-a-repo"
        non_repo_path.mkdir(exist_ok=True)

        with pytest.raises(InvalidRepositoryError):
            git_service.set_local_config(
                repo_path=non_repo_path,
                username="Test User",
                email="test@example.com",
            )


class TestSetLocalConfigWithGPG:
    """Tests for set_local_config with GPG settings."""

    def test_set_local_config_with_gpg_signing(
        self, git_service: "GitService", mock_git_repo: Path
    ) -> None:
        """set_local_config should handle GPG signing configuration."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            git_service.set_local_config(
                repo_path=mock_git_repo,
                username="Repo User",
                email="repo@example.com",
                signing_key="LOCAL_GPG_KEY",
                gpg_sign=True,
            )

            calls = mock_run.call_args_list
            assert any("user.signingkey" in str(call) for call in calls)
            assert any("commit.gpgsign" in str(call) for call in calls)
