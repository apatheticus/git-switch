"""End-to-end tests for profile switch workflow.

These tests verify the complete profile switching workflow including:
- Profile creation with SSH keys
- Profile switching with Git config updates
- SSH key management during switch
- GPG key handling
- Profile state persistence

TDD Note: These tests exercise the full workflow with real components
(CryptoService, SessionManager, ProfileManager) but with mocked external
services (Git, SSH, GPG, Credentials).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from src.core.crypto import CryptoService
    from src.core.profile_manager import ProfileManager
    from src.core.session import SessionManager


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def real_crypto_service() -> CryptoService:
    """Create a real CryptoService for e2e testing."""
    from src.core.crypto import CryptoService

    return CryptoService()


@pytest.fixture
def e2e_session_manager(
    real_crypto_service: CryptoService, temp_dir: Path
) -> SessionManager:
    """Create a SessionManager with real crypto for e2e testing."""
    from src.core.session import SessionManager

    with patch("src.core.session.get_master_key_path") as mock_path:
        mock_path.return_value = temp_dir / "master.json"
        manager = SessionManager(real_crypto_service, auto_lock_timeout=15)
        # Setup password and unlock
        manager.setup_master_password("TestPassword123!")
        yield manager


@pytest.fixture
def e2e_profile_manager(
    e2e_session_manager: SessionManager,
    real_crypto_service: CryptoService,
    mock_git_service: MagicMock,
    mock_ssh_service: MagicMock,
    mock_gpg_service: MagicMock,
    mock_credential_service: MagicMock,
    temp_dir: Path,
) -> ProfileManager:
    """Create a ProfileManager with real crypto and mocked external services."""
    from src.core.profile_manager import ProfileManager

    with (
        patch("src.utils.paths.get_profiles_path") as mock_profiles_path,
        patch("src.utils.paths.get_ssh_key_path") as mock_ssh_path,
        patch("src.utils.paths.get_gpg_key_path") as mock_gpg_path,
    ):
        # Configure path mocks
        mock_profiles_path.return_value = temp_dir / "profiles.dat"

        def ssh_key_path(profile_id: str) -> Path:
            return temp_dir / f"ssh_{profile_id}.key"

        def gpg_key_path(profile_id: str) -> Path:
            return temp_dir / f"gpg_{profile_id}.key"

        mock_ssh_path.side_effect = ssh_key_path
        mock_gpg_path.side_effect = gpg_key_path

        manager = ProfileManager(
            session_manager=e2e_session_manager,
            crypto_service=real_crypto_service,
            git_service=mock_git_service,
            ssh_service=mock_ssh_service,
            gpg_service=mock_gpg_service,
            credential_service=mock_credential_service,
        )
        yield manager


@pytest.fixture
def profile_manager_factory(
    real_crypto_service: CryptoService,
    mock_git_service: MagicMock,
    mock_ssh_service: MagicMock,
    mock_gpg_service: MagicMock,
    mock_credential_service: MagicMock,
    temp_dir: Path,
):
    """Factory for creating new ProfileManager instances (simulates restart)."""
    from src.core.profile_manager import ProfileManager
    from src.core.session import SessionManager

    master_path = temp_dir / "master.json"
    profiles_path = temp_dir / "profiles.dat"

    def create_manager(password: str = "TestPassword123!") -> ProfileManager:  # noqa: S107
        with (
            patch("src.core.session.get_master_key_path") as mock_master_path,
            patch("src.utils.paths.get_profiles_path") as mock_profiles_path,
            patch("src.utils.paths.get_ssh_key_path") as mock_ssh_path,
            patch("src.utils.paths.get_gpg_key_path") as mock_gpg_path,
        ):
            mock_master_path.return_value = master_path
            mock_profiles_path.return_value = profiles_path

            def ssh_key_path(profile_id: str) -> Path:
                return temp_dir / f"ssh_{profile_id}.key"

            def gpg_key_path(profile_id: str) -> Path:
                return temp_dir / f"gpg_{profile_id}.key"

            mock_ssh_path.side_effect = ssh_key_path
            mock_gpg_path.side_effect = gpg_key_path

            # Create session manager
            session = SessionManager(real_crypto_service, auto_lock_timeout=15)

            # Setup or unlock
            if session.has_master_password():
                session.unlock(password)
            else:
                session.setup_master_password(password)

            return ProfileManager(
                session_manager=session,
                crypto_service=real_crypto_service,
                git_service=mock_git_service,
                ssh_service=mock_ssh_service,
                gpg_service=mock_gpg_service,
                credential_service=mock_credential_service,
            )

    return create_manager


@pytest.fixture
def sample_ssh_private_key_valid() -> bytes:
    """Provide a valid-looking SSH private key for testing."""
    return b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBIZWxsb1dvcmxkVGVzdEtleTEyMzQ1Njc4OTBhYmNkZWYAAAAIYWJjZGVm
Z2gBAgMEBQYHCA==
-----END OPENSSH PRIVATE KEY-----
"""


@pytest.fixture
def sample_ssh_public_key_valid() -> bytes:
    """Provide a matching SSH public key for testing."""
    return b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEhlbGxvV29ybGRUZXN0S2V5MTIzNDU2Nzg5MGFiY2RlZg== test@example.com"


@pytest.fixture
def sample_gpg_private_key() -> bytes:
    """Provide a sample GPG private key for testing."""
    return b"""-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Test

lQHYBGTest12345678901234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
ghijklmnopqrstuvwxyz0123456789+/=
-----END PGP PRIVATE KEY BLOCK-----
"""


# =============================================================================
# Basic Profile Switch Workflow Tests
# =============================================================================


class TestBasicProfileSwitchWorkflow:
    """E2E tests for basic profile switching."""

    def test_create_and_switch_single_profile(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Create profile with SSH key, switch to it, verify state."""
        # Create a profile
        profile = e2e_profile_manager.create_profile(
            name="Work Profile",
            git_username="workuser",
            git_email="work@company.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
            organization="Company Inc",
        )

        # Profile should be created
        assert profile.name == "Work Profile"
        assert profile.git_username == "workuser"
        assert profile.git_email == "work@company.com"
        assert profile.is_active is False

        # Switch to the profile
        e2e_profile_manager.switch_profile(profile.id)

        # Retrieve and verify profile is now active
        updated_profile = e2e_profile_manager.get_profile(profile.id)
        assert updated_profile is not None
        assert updated_profile.is_active is True
        assert updated_profile.last_used is not None

    def test_switch_marks_profile_active_and_updates_last_used(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify profile state changes correctly on switch."""
        # Create profile
        profile = e2e_profile_manager.create_profile(
            name="Test Profile",
            git_username="testuser",
            git_email="test@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Initially not active and no last_used
        assert profile.is_active is False
        assert profile.last_used is None

        # Record time before switch
        before_switch = datetime.now(tz=UTC)

        # Switch to profile
        e2e_profile_manager.switch_profile(profile.id)

        # Verify state
        updated = e2e_profile_manager.get_profile(profile.id)
        assert updated is not None
        assert updated.is_active is True
        assert updated.last_used is not None
        assert updated.last_used >= before_switch

    def test_switch_deactivates_previous_active_profile(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify old profile deactivated when switching to new one."""
        # Create two profiles
        profile1 = e2e_profile_manager.create_profile(
            name="Profile 1",
            git_username="user1",
            git_email="user1@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        profile2 = e2e_profile_manager.create_profile(
            name="Profile 2",
            git_username="user2",
            git_email="user2@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch to profile 1
        e2e_profile_manager.switch_profile(profile1.id)
        updated1 = e2e_profile_manager.get_profile(profile1.id)
        assert updated1 is not None
        assert updated1.is_active is True

        # Switch to profile 2
        e2e_profile_manager.switch_profile(profile2.id)

        # Profile 1 should be deactivated
        final1 = e2e_profile_manager.get_profile(profile1.id)
        final2 = e2e_profile_manager.get_profile(profile2.id)

        assert final1 is not None
        assert final1.is_active is False
        assert final2 is not None
        assert final2.is_active is True


# =============================================================================
# Multi-Service Orchestration Tests
# =============================================================================


class TestMultiServiceOrchestration:
    """E2E tests for service orchestration during switch."""

    def test_switch_clears_credentials_before_updating_git(
        self,
        e2e_profile_manager: ProfileManager,
        mock_credential_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify credential clearing happens during switch."""
        # Setup mock to return some credentials
        mock_credential_service.clear_git_credentials.return_value = [
            "git:https://github.com"
        ]

        profile = e2e_profile_manager.create_profile(
            name="Test Profile",
            git_username="testuser",
            git_email="test@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch
        e2e_profile_manager.switch_profile(profile.id)

        # Verify credentials were cleared
        mock_credential_service.clear_git_credentials.assert_called_once()

    def test_switch_updates_git_config_with_profile_data(
        self,
        e2e_profile_manager: ProfileManager,
        mock_git_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify Git config set correctly during switch."""
        profile = e2e_profile_manager.create_profile(
            name="Test Profile",
            git_username="testuser",
            git_email="test@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch
        e2e_profile_manager.switch_profile(profile.id)

        # Verify Git config was set
        mock_git_service.set_global_config.assert_called_once_with(
            username="testuser",
            email="test@example.com",
            signing_key=None,  # No GPG
            gpg_sign=False,
        )

    def test_switch_removes_old_ssh_keys_before_adding_new(
        self,
        e2e_profile_manager: ProfileManager,
        mock_ssh_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify SSH key management during switch."""
        profile = e2e_profile_manager.create_profile(
            name="Test Profile",
            git_username="testuser",
            git_email="test@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch
        e2e_profile_manager.switch_profile(profile.id)

        # Verify old keys removed
        mock_ssh_service.remove_all_keys.assert_called_once()
        # Verify new key added
        mock_ssh_service.add_key.assert_called_once()

    def test_switch_imports_gpg_key_when_enabled(
        self,
        e2e_profile_manager: ProfileManager,
        mock_gpg_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
        sample_gpg_private_key: bytes,
    ) -> None:
        """Verify GPG key import when GPG is enabled."""
        profile = e2e_profile_manager.create_profile(
            name="GPG Profile",
            git_username="gpguser",
            git_email="gpg@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
            gpg_enabled=True,
            gpg_key_id="ABCD1234",
            gpg_private_key=sample_gpg_private_key,
        )

        # Switch
        e2e_profile_manager.switch_profile(profile.id)

        # Verify GPG key was imported
        mock_gpg_service.import_key.assert_called_once()


# =============================================================================
# Scope Variations Tests
# =============================================================================


class TestScopeVariations:
    """E2E tests for global vs local scope switching."""

    def test_global_scope_calls_set_global_config(
        self,
        e2e_profile_manager: ProfileManager,
        mock_git_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify global scope uses set_global_config."""
        profile = e2e_profile_manager.create_profile(
            name="Global Profile",
            git_username="globaluser",
            git_email="global@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch with global scope (default)
        e2e_profile_manager.switch_profile(profile.id, scope="global")

        # Verify global config called
        mock_git_service.set_global_config.assert_called_once()
        mock_git_service.set_local_config.assert_not_called()

    def test_local_scope_calls_set_local_config_with_repo_path(
        self,
        e2e_profile_manager: ProfileManager,
        mock_git_service: MagicMock,
        mock_git_repo: Path,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify local scope uses set_local_config with repo path."""
        profile = e2e_profile_manager.create_profile(
            name="Local Profile",
            git_username="localuser",
            git_email="local@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch with local scope
        e2e_profile_manager.switch_profile(
            profile.id, scope="local", repo_path=mock_git_repo
        )

        # Verify local config called with repo path
        mock_git_service.set_local_config.assert_called_once_with(
            repo_path=mock_git_repo,
            username="localuser",
            email="local@example.com",
            signing_key=None,
            gpg_sign=False,
        )
        mock_git_service.set_global_config.assert_not_called()


# =============================================================================
# GPG Support Tests
# =============================================================================


class TestGPGSupport:
    """E2E tests for GPG key handling."""

    def test_switch_with_gpg_enabled_imports_key(
        self,
        e2e_profile_manager: ProfileManager,
        mock_gpg_service: MagicMock,
        mock_git_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
        sample_gpg_private_key: bytes,
    ) -> None:
        """Verify GPG enabled path imports key and sets signing config."""
        profile = e2e_profile_manager.create_profile(
            name="GPG Enabled Profile",
            git_username="gpguser",
            git_email="gpg@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
            gpg_enabled=True,
            gpg_key_id="DEADBEEF",
            gpg_private_key=sample_gpg_private_key,
        )

        # Switch
        e2e_profile_manager.switch_profile(profile.id)

        # Verify GPG import
        mock_gpg_service.import_key.assert_called_once()

        # Verify Git config has signing settings
        mock_git_service.set_global_config.assert_called_once_with(
            username="gpguser",
            email="gpg@example.com",
            signing_key="DEADBEEF",
            gpg_sign=True,
        )

    def test_switch_with_gpg_disabled_skips_import(
        self,
        e2e_profile_manager: ProfileManager,
        mock_gpg_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify GPG disabled path skips import."""
        profile = e2e_profile_manager.create_profile(
            name="No GPG Profile",
            git_username="nogpguser",
            git_email="nogpg@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
            gpg_enabled=False,
        )

        # Switch
        e2e_profile_manager.switch_profile(profile.id)

        # Verify no GPG import
        mock_gpg_service.import_key.assert_not_called()


# =============================================================================
# Profile Persistence Tests
# =============================================================================


class TestProfilePersistence:
    """E2E tests for profile state persistence."""

    def test_profile_state_persists_after_manager_reload(
        self,
        profile_manager_factory,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify profile state persists after manager reload."""
        # Create first manager and add a profile
        manager1 = profile_manager_factory()
        profile = manager1.create_profile(
            name="Persistent Profile",
            git_username="persistuser",
            git_email="persist@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch to activate
        manager1.switch_profile(profile.id)

        # Create new manager (simulates restart)
        manager2 = profile_manager_factory()

        # Load profiles and check state
        profiles = manager2.list_profiles()
        assert len(profiles) == 1
        assert profiles[0].name == "Persistent Profile"
        assert profiles[0].is_active is True

    def test_switched_profile_active_after_app_restart(
        self,
        profile_manager_factory,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Simulate app restart and verify profile active state persists."""
        # First session: create and switch
        manager1 = profile_manager_factory()
        profile = manager1.create_profile(
            name="Restart Test Profile",
            git_username="restartuser",
            git_email="restart@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )
        profile_id = profile.id
        manager1.switch_profile(profile_id)

        # Second session: reload
        manager2 = profile_manager_factory()
        reloaded_profile = manager2.get_profile(profile_id)

        assert reloaded_profile is not None
        assert reloaded_profile.is_active is True
        assert reloaded_profile.name == "Restart Test Profile"


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """E2E tests for error handling during switch."""

    def test_switch_fails_with_session_locked(
        self,
        e2e_session_manager: SessionManager,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify switch fails when session is locked."""
        from src.models.exceptions import SessionExpiredError

        # Create profile while unlocked
        profile = e2e_profile_manager.create_profile(
            name="Test Profile",
            git_username="testuser",
            git_email="test@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Lock the session
        e2e_session_manager.lock()

        # Attempt switch should fail
        with pytest.raises(SessionExpiredError):
            e2e_profile_manager.switch_profile(profile.id)

    def test_switch_with_nonexistent_profile_raises_error(
        self,
        e2e_profile_manager: ProfileManager,
    ) -> None:
        """Verify error handling for nonexistent profile."""
        from uuid import uuid4

        from src.models.exceptions import ProfileNotFoundError

        # Try to switch to a non-existent profile
        fake_id = uuid4()
        with pytest.raises(ProfileNotFoundError):
            e2e_profile_manager.switch_profile(fake_id)


# =============================================================================
# Multiple Profile Switching Tests
# =============================================================================


class TestMultipleProfileSwitching:
    """E2E tests for switching between multiple profiles."""

    def test_switch_between_multiple_profiles(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify multi-profile switching works correctly."""
        # Create three profiles
        profiles = []
        for i in range(3):
            profile = e2e_profile_manager.create_profile(
                name=f"Profile {i}",
                git_username=f"user{i}",
                git_email=f"user{i}@example.com",
                ssh_private_key=sample_ssh_private_key_valid,
                ssh_public_key=sample_ssh_public_key_valid,
            )
            profiles.append(profile)

        # Switch through all profiles
        for _i, profile in enumerate(profiles):
            e2e_profile_manager.switch_profile(profile.id)

            # Verify only current profile is active
            all_profiles = e2e_profile_manager.list_profiles()
            active_count = sum(1 for p in all_profiles if p.is_active)
            assert active_count == 1

            current = e2e_profile_manager.get_profile(profile.id)
            assert current is not None
            assert current.is_active is True

    def test_rapid_switches_maintain_consistent_state(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify state consistency with rapid profile switches."""
        # Create two profiles
        profile1 = e2e_profile_manager.create_profile(
            name="Profile A",
            git_username="userA",
            git_email="userA@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        profile2 = e2e_profile_manager.create_profile(
            name="Profile B",
            git_username="userB",
            git_email="userB@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Rapidly switch back and forth
        for _ in range(10):
            e2e_profile_manager.switch_profile(profile1.id)
            e2e_profile_manager.switch_profile(profile2.id)

        # Final state should have only profile2 active
        all_profiles = e2e_profile_manager.list_profiles()
        active_count = sum(1 for p in all_profiles if p.is_active)
        assert active_count == 1

        final_profile2 = e2e_profile_manager.get_profile(profile2.id)
        assert final_profile2 is not None
        assert final_profile2.is_active is True

        final_profile1 = e2e_profile_manager.get_profile(profile1.id)
        assert final_profile1 is not None
        assert final_profile1.is_active is False


# =============================================================================
# Active Profile Query Tests
# =============================================================================


class TestActiveProfileQueries:
    """E2E tests for querying active profile state."""

    def test_get_active_profile_returns_current(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify get_active_profile returns the switched profile."""
        profile = e2e_profile_manager.create_profile(
            name="Active Profile",
            git_username="activeuser",
            git_email="active@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # No active profile initially
        assert e2e_profile_manager.get_active_profile() is None

        # Switch
        e2e_profile_manager.switch_profile(profile.id)

        # Should return the active profile
        active = e2e_profile_manager.get_active_profile()
        assert active is not None
        assert active.id == profile.id
        assert active.name == "Active Profile"

    def test_no_active_profile_before_any_switch(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify no active profile before any switch."""
        # Create profile but don't switch
        e2e_profile_manager.create_profile(
            name="Inactive Profile",
            git_username="inactiveuser",
            git_email="inactive@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Should be no active profile
        assert e2e_profile_manager.get_active_profile() is None


# =============================================================================
# Profile Update and Switch Tests
# =============================================================================


class TestProfileUpdateAndSwitch:
    """E2E tests for profile update and switch interaction."""

    def test_update_active_profile_maintains_active_state(
        self,
        e2e_profile_manager: ProfileManager,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify updating active profile maintains active state."""
        profile = e2e_profile_manager.create_profile(
            name="Original Name",
            git_username="originaluser",
            git_email="original@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch to activate
        e2e_profile_manager.switch_profile(profile.id)

        # Update the profile
        updated = e2e_profile_manager.update_profile(
            profile.id,
            name="Updated Name",
            git_email="updated@example.com",
        )

        # Should still be active
        assert updated.is_active is True
        assert updated.name == "Updated Name"
        assert updated.git_email == "updated@example.com"

    def test_delete_active_profile_clears_state(
        self,
        e2e_profile_manager: ProfileManager,
        mock_git_service: MagicMock,
        mock_ssh_service: MagicMock,
        sample_ssh_private_key_valid: bytes,
        sample_ssh_public_key_valid: bytes,
    ) -> None:
        """Verify deleting active profile clears Git config and SSH agent."""
        profile = e2e_profile_manager.create_profile(
            name="To Delete",
            git_username="deleteuser",
            git_email="delete@example.com",
            ssh_private_key=sample_ssh_private_key_valid,
            ssh_public_key=sample_ssh_public_key_valid,
        )

        # Switch to activate
        e2e_profile_manager.switch_profile(profile.id)

        # Reset mocks after switch
        mock_git_service.reset_mock()
        mock_ssh_service.reset_mock()

        # Delete active profile
        e2e_profile_manager.delete_profile(profile.id)

        # Git config should be cleared
        mock_git_service.set_global_config.assert_called_once_with(
            username="",
            email="",
            signing_key=None,
            gpg_sign=False,
        )

        # SSH keys should be removed
        mock_ssh_service.remove_all_keys.assert_called_once()

        # No active profile anymore
        assert e2e_profile_manager.get_active_profile() is None
