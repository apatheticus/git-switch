"""Integration tests for profile switch workflow.

These tests verify the complete profile switching workflow including:
- Coordinating all services (Git, SSH, GPG, Credentials)
- End-to-end profile switch scenarios
- Error handling and rollback behavior

TDD Note: These tests are written before the full implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from src.core.profile_manager import ProfileManager


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_session_manager() -> MagicMock:
    """Create a mock SessionManager that is unlocked."""
    mock = MagicMock()
    mock.is_unlocked = True
    mock.encryption_key = b"K" * 32
    return mock


@pytest.fixture
def mock_crypto_service() -> MagicMock:
    """Create a mock CryptoService."""
    mock = MagicMock()
    mock.encrypt.side_effect = lambda data, key: b"ENC:" + data
    mock.decrypt.side_effect = (
        lambda data, key: data[4:] if data.startswith(b"ENC:") else data
    )
    return mock


@pytest.fixture
def mock_git_service() -> MagicMock:
    """Create a mock GitService."""
    mock = MagicMock()
    mock.is_git_installed.return_value = True
    mock.get_global_config.return_value = {
        "user.name": "Old User",
        "user.email": "old@example.com",
    }
    mock.set_global_config.return_value = None
    mock.set_local_config.return_value = None
    return mock


@pytest.fixture
def mock_ssh_service() -> MagicMock:
    """Create a mock SSHService."""
    mock = MagicMock()
    mock.is_agent_running.return_value = True
    mock.list_keys.return_value = []
    mock.add_key.return_value = True
    mock.remove_all_keys.return_value = True
    mock.test_connection.return_value = (True, "Hi testuser!")
    return mock


@pytest.fixture
def mock_gpg_service() -> MagicMock:
    """Create a mock GPGService."""
    mock = MagicMock()
    mock.is_gpg_installed.return_value = True
    mock.list_keys.return_value = []
    mock.verify_signing_capability.return_value = True
    mock.import_key.return_value = "ABCD1234EFGH5678"
    return mock


@pytest.fixture
def mock_credential_service() -> MagicMock:
    """Create a mock CredentialService."""
    mock = MagicMock()
    mock.list_git_credentials.return_value = [
        "git:https://github.com",
        "git:https://gitlab.com",
    ]
    mock.clear_git_credentials.return_value = [
        "git:https://github.com",
        "git:https://gitlab.com",
    ]
    return mock


@pytest.fixture
def sample_ssh_private_key() -> bytes:
    """Sample SSH private key for testing."""
    return b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBtest1234567890abcdefghijklmnopqrstuvwxyzAAAAHHRlc3RAZXhh
bXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"""


@pytest.fixture
def sample_ssh_public_key() -> bytes:
    """Sample SSH public key for testing."""
    return b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBtest1234567890 test@example.com"


@pytest.fixture
def profile_manager_with_mocks(
    mock_session_manager: MagicMock,
    mock_crypto_service: MagicMock,
    mock_git_service: MagicMock,
    mock_ssh_service: MagicMock,
    mock_gpg_service: MagicMock,
    mock_credential_service: MagicMock,
    temp_dir: Path,
) -> "ProfileManager":
    """Create a ProfileManager with all mock services for integration testing."""
    from src.core.profile_manager import ProfileManager

    keys_dir = temp_dir / "keys"
    keys_dir.mkdir(exist_ok=True)

    with (
        patch("src.core.profile_manager.get_profiles_path") as mock_profiles_path,
        patch("src.core.profile_manager.get_ssh_key_path") as mock_ssh_path,
        patch("src.core.profile_manager.get_gpg_key_path") as mock_gpg_path,
    ):
        mock_profiles_path.return_value = temp_dir / "profiles.dat"
        mock_ssh_path.side_effect = lambda pid: keys_dir / f"{pid}.ssh"
        mock_gpg_path.side_effect = lambda pid: keys_dir / f"{pid}.gpg"

        manager = ProfileManager(
            mock_session_manager,
            mock_crypto_service,
            git_service=mock_git_service,
            ssh_service=mock_ssh_service,
            gpg_service=mock_gpg_service,
            credential_service=mock_credential_service,
        )
        manager._git_service = mock_git_service
        manager._ssh_service = mock_ssh_service
        manager._gpg_service = mock_gpg_service
        manager._credential_service = mock_credential_service
        yield manager


# =============================================================================
# Complete Workflow Tests
# =============================================================================


class TestCompleteProfileSwitchWorkflow:
    """Tests for complete profile switch workflow."""

    def test_complete_profile_switch_workflow(
        self,
        profile_manager_with_mocks: "ProfileManager",
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
        mock_ssh_service: MagicMock,
        mock_credential_service: MagicMock,
    ) -> None:
        """Complete workflow: create profile, switch to it, verify all services called."""
        # Create a profile
        profile = profile_manager_with_mocks.create_profile(
            name="Work Profile",
            git_username="work-user",
            git_email="work@company.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            organization="CompanyOrg",
        )

        # Switch to the profile
        profile_manager_with_mocks.switch_profile(profile.id)

        # Verify credentials were cleared
        mock_credential_service.clear_git_credentials.assert_called_once()

        # Verify SSH key management
        mock_ssh_service.remove_all_keys.assert_called_once()
        mock_ssh_service.add_key.assert_called_once()

        # Verify Git config was updated
        mock_git_service.set_global_config.assert_called_once()

        # Verify profile state
        updated = profile_manager_with_mocks.get_profile(profile.id)
        assert updated.is_active is True
        assert updated.last_used is not None


class TestProfileSwitchCoordination:
    """Tests for service coordination during profile switch."""

    def test_profile_switch_coordinates_all_services(
        self,
        profile_manager_with_mocks: "ProfileManager",
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
        mock_ssh_service: MagicMock,
        mock_gpg_service: MagicMock,
        mock_credential_service: MagicMock,
    ) -> None:
        """Profile switch should coordinate all services in correct order."""
        gpg_private = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
        gpg_public = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"

        profile = profile_manager_with_mocks.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            gpg_enabled=True,
            gpg_key_id="ABCD1234EFGH5678",
            gpg_private_key=gpg_private,
            gpg_public_key=gpg_public,
        )

        profile_manager_with_mocks.switch_profile(profile.id)

        # All services should be called
        mock_credential_service.clear_git_credentials.assert_called()
        mock_ssh_service.remove_all_keys.assert_called()
        mock_ssh_service.add_key.assert_called()
        mock_gpg_service.import_key.assert_called()
        mock_git_service.set_global_config.assert_called()


class TestProfileSwitchRollback:
    """Tests for rollback behavior on failures."""

    def test_profile_switch_rollback_on_ssh_failure(
        self,
        profile_manager_with_mocks: "ProfileManager",
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_ssh_service: MagicMock,
    ) -> None:
        """Profile switch should handle SSH failures gracefully."""
        from src.models.exceptions import SSHServiceError

        profile = profile_manager_with_mocks.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Make SSH add_key fail
        mock_ssh_service.add_key.side_effect = SSHServiceError("Failed to add key")

        with pytest.raises(SSHServiceError):
            profile_manager_with_mocks.switch_profile(profile.id)

        # Profile should not be marked as active on failure
        updated = profile_manager_with_mocks.get_profile(profile.id)
        assert updated.is_active is False


# =============================================================================
# Multiple Profile Switch Tests
# =============================================================================


class TestMultipleProfileSwitch:
    """Tests for switching between multiple profiles."""

    def test_switch_between_profiles_deactivates_previous(
        self,
        profile_manager_with_mocks: "ProfileManager",
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """Switching profiles should deactivate the previous profile."""
        profile1 = profile_manager_with_mocks.create_profile(
            name="Personal",
            git_username="personal",
            git_email="personal@gmail.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )
        profile2 = profile_manager_with_mocks.create_profile(
            name="Work",
            git_username="work",
            git_email="work@company.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Switch to profile1
        profile_manager_with_mocks.switch_profile(profile1.id)
        assert profile_manager_with_mocks.get_active_profile().id == profile1.id

        # Switch to profile2
        profile_manager_with_mocks.switch_profile(profile2.id)

        # Verify only profile2 is active
        assert profile_manager_with_mocks.get_active_profile().id == profile2.id

        p1 = profile_manager_with_mocks.get_profile(profile1.id)
        p2 = profile_manager_with_mocks.get_profile(profile2.id)
        assert p1.is_active is False
        assert p2.is_active is True

    def test_switch_clears_previous_ssh_keys(
        self,
        profile_manager_with_mocks: "ProfileManager",
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_ssh_service: MagicMock,
    ) -> None:
        """Switching profiles should clear SSH keys before adding new one."""
        profile1 = profile_manager_with_mocks.create_profile(
            name="Personal",
            git_username="personal",
            git_email="personal@gmail.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )
        profile2 = profile_manager_with_mocks.create_profile(
            name="Work",
            git_username="work",
            git_email="work@company.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager_with_mocks.switch_profile(profile1.id)
        profile_manager_with_mocks.switch_profile(profile2.id)

        # remove_all_keys should be called for each switch
        assert mock_ssh_service.remove_all_keys.call_count == 2


# =============================================================================
# Local Scope Tests
# =============================================================================


class TestLocalScopeSwitch:
    """Tests for local (repository) scope profile switching."""

    def test_local_scope_does_not_affect_global_config(
        self,
        profile_manager_with_mocks: "ProfileManager",
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
        temp_dir: Path,
    ) -> None:
        """Local scope switch should only affect repository config."""
        repo_path = temp_dir / "my-repo"
        repo_path.mkdir(exist_ok=True)
        (repo_path / ".git").mkdir(exist_ok=True)

        profile = profile_manager_with_mocks.create_profile(
            name="RepoProfile",
            git_username="repo-user",
            git_email="repo@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager_with_mocks.switch_profile(
            profile.id, scope="local", repo_path=repo_path
        )

        # Should call set_local_config instead of set_global_config
        mock_git_service.set_local_config.assert_called_once()
        mock_git_service.set_global_config.assert_not_called()
