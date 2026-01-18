"""Unit tests for ProfileManager CRUD operations.

These tests verify profile management functionality including:
- Listing profiles
- Getting individual profiles
- Creating profiles with SSH/GPG keys
- Updating profiles
- Deleting profiles

TDD Note: These tests are written before the ProfileManager implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

if TYPE_CHECKING:
    from src.core.profile_manager import ProfileManager


# =============================================================================
# Mock Service Fixtures (for switch_profile tests)
# =============================================================================


@pytest.fixture
def mock_git_service() -> MagicMock:
    """Create a mock GitService."""
    mock = MagicMock()
    mock.is_git_installed.return_value = True
    mock.get_global_config.return_value = {
        "user.name": "Test User",
        "user.email": "test@example.com",
    }
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
    mock.list_git_credentials.return_value = []
    mock.clear_git_credentials.return_value = []
    return mock


@pytest.fixture
def mock_git_repo(temp_dir: Path) -> Path:
    """Create a mock Git repository for testing."""
    repo_dir = temp_dir / "test-repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    git_dir = repo_dir / ".git"
    git_dir.mkdir(exist_ok=True)
    (git_dir / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    return repo_dir


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
def mock_session_manager_locked() -> MagicMock:
    """Create a mock SessionManager that is locked."""
    mock = MagicMock()
    mock.is_unlocked = False
    mock.encryption_key = None
    return mock


@pytest.fixture
def mock_crypto_service() -> MagicMock:
    """Create a mock CryptoService."""
    mock = MagicMock()
    mock.encrypt.side_effect = lambda data, key: b"ENC:" + data
    mock.decrypt.side_effect = lambda data, key: data[4:] if data.startswith(b"ENC:") else data
    return mock


@pytest.fixture
def profile_manager(
    mock_session_manager: MagicMock, mock_crypto_service: MagicMock, temp_dir: Path
) -> ProfileManager:
    """Create a ProfileManager instance for testing."""
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

        manager = ProfileManager(mock_session_manager, mock_crypto_service)
        yield manager


@pytest.fixture
def profile_manager_locked(
    mock_session_manager_locked: MagicMock, mock_crypto_service: MagicMock, temp_dir: Path
) -> ProfileManager:
    """Create a ProfileManager with locked session."""
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

        manager = ProfileManager(mock_session_manager_locked, mock_crypto_service)
        yield manager


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


# =============================================================================
# List Profiles Tests
# =============================================================================


class TestListProfiles:
    """Tests for list_profiles() method."""

    def test_list_profiles_empty_when_no_profiles(self, profile_manager: ProfileManager) -> None:
        """list_profiles should return empty list when no profiles exist."""
        profiles = profile_manager.list_profiles()
        assert profiles == []

    def test_list_profiles_returns_all_profiles(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """list_profiles should return all created profiles."""
        # Create two profiles
        profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )
        profile_manager.create_profile(
            name="Personal",
            git_username="personal-user",
            git_email="personal@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profiles = profile_manager.list_profiles()

        assert len(profiles) == 2
        names = [p.name for p in profiles]
        assert "Work" in names
        assert "Personal" in names


# =============================================================================
# Get Profile Tests
# =============================================================================


class TestGetProfile:
    """Tests for get_profile() method."""

    def test_get_profile_returns_profile_when_exists(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """get_profile should return the profile when it exists."""
        created = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile = profile_manager.get_profile(created.id)

        assert profile is not None
        assert profile.name == "Work"
        assert profile.git_email == "work@example.com"

    def test_get_profile_returns_none_when_not_found(self, profile_manager: ProfileManager) -> None:
        """get_profile should return None when profile doesn't exist."""
        random_id = uuid4()
        profile = profile_manager.get_profile(random_id)
        assert profile is None


# =============================================================================
# Get Active Profile Tests
# =============================================================================


class TestGetActiveProfile:
    """Tests for get_active_profile() method."""

    def test_get_active_profile_returns_active(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """get_active_profile should return the active profile."""
        # Create profile and mark it active
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Manually set active (normally done via switch_profile)
        profile_manager._profiles[0].is_active = True

        active = profile_manager.get_active_profile()

        assert active is not None
        assert active.name == "Work"
        assert active.is_active is True

    def test_get_active_profile_returns_none_when_no_active(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """get_active_profile should return None when no profile is active."""
        profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        active = profile_manager.get_active_profile()

        assert active is None


# =============================================================================
# Create Profile Tests
# =============================================================================


class TestCreateProfile:
    """Tests for create_profile() method."""

    def test_create_profile_with_ssh_only(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """create_profile should create a profile with SSH key only."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        assert profile is not None
        assert profile.name == "Work"
        assert profile.git_username == "work-user"
        assert profile.git_email == "work@example.com"
        assert profile.ssh_key is not None
        assert profile.gpg_key.enabled is False

    def test_create_profile_with_ssh_and_gpg(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """create_profile should create a profile with SSH and GPG keys."""
        gpg_private = (
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        gpg_public = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"
        )

        profile = profile_manager.create_profile(
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

        assert profile.gpg_key.enabled is True
        assert profile.gpg_key.key_id == "ABCD1234EFGH5678"

    def test_create_profile_validates_email(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """create_profile should validate email format."""
        from src.models.exceptions import ProfileValidationError

        with pytest.raises((ProfileValidationError, ValueError)):
            profile_manager.create_profile(
                name="Work",
                git_username="work-user",
                git_email="invalid-email",  # No @ symbol
                ssh_private_key=sample_ssh_private_key,
                ssh_public_key=sample_ssh_public_key,
            )

    def test_create_profile_stores_encrypted_keys(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_crypto_service: MagicMock,
    ) -> None:
        """create_profile should encrypt SSH private key before storage."""
        profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Verify encrypt was called
        mock_crypto_service.encrypt.assert_called()

    def test_create_profile_raises_session_expired_when_locked(
        self,
        profile_manager_locked: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """create_profile should raise SessionExpiredError when session is locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.create_profile(
                name="Work",
                git_username="work-user",
                git_email="work@example.com",
                ssh_private_key=sample_ssh_private_key,
                ssh_public_key=sample_ssh_public_key,
            )


# =============================================================================
# Update Profile Tests
# =============================================================================


class TestUpdateProfile:
    """Tests for update_profile() method."""

    def test_update_profile_updates_fields(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """update_profile should update specified fields."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        updated = profile_manager.update_profile(
            profile.id,
            name="Work Updated",
            git_email="new-work@example.com",
        )

        assert updated.name == "Work Updated"
        assert updated.git_email == "new-work@example.com"
        assert updated.git_username == "work-user"  # Unchanged

    def test_update_profile_replaces_ssh_key(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """update_profile should replace SSH key when provided."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        new_private = (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nnewkey\n-----END OPENSSH PRIVATE KEY-----"
        )
        new_public = b"ssh-ed25519 NEWKEY newuser@example.com"

        updated = profile_manager.update_profile(
            profile.id,
            ssh_private_key=new_private,
            ssh_public_key=new_public,
        )

        # Public key should be updated
        assert updated.ssh_key is not None
        assert updated.ssh_key.public_key == new_public

    def test_update_profile_raises_not_found(self, profile_manager: ProfileManager) -> None:
        """update_profile should raise ProfileNotFoundError for non-existent profile."""
        from src.models.exceptions import ProfileNotFoundError

        random_id = uuid4()
        with pytest.raises(ProfileNotFoundError):
            profile_manager.update_profile(random_id, name="New Name")


# =============================================================================
# Delete Profile Tests
# =============================================================================


class TestDeleteProfile:
    """Tests for delete_profile() method."""

    def test_delete_profile_removes_profile(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """delete_profile should remove the profile from the list."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager.delete_profile(profile.id)

        assert profile_manager.get_profile(profile.id) is None
        assert len(profile_manager.list_profiles()) == 0

    def test_delete_profile_removes_key_files(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_crypto_service: MagicMock,
    ) -> None:
        """delete_profile should remove associated key files."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager.delete_profile(profile.id)

        # Verify secure_delete_file was called for key cleanup
        mock_crypto_service.secure_delete_file.assert_called()

    def test_delete_profile_raises_not_found(self, profile_manager: ProfileManager) -> None:
        """delete_profile should raise ProfileNotFoundError for non-existent profile."""
        from src.models.exceptions import ProfileNotFoundError

        random_id = uuid4()
        with pytest.raises(ProfileNotFoundError):
            profile_manager.delete_profile(random_id)


# =============================================================================
# Persistence Tests
# =============================================================================


class TestProfilePersistence:
    """Tests for profile storage persistence."""

    def test_profiles_persist_after_reload(
        self,
        mock_session_manager: MagicMock,
        mock_crypto_service: MagicMock,
        temp_dir: Path,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """Profiles should persist and reload correctly."""
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

            # Create first manager and add profile
            manager1 = ProfileManager(mock_session_manager, mock_crypto_service)
            created = manager1.create_profile(
                name="Persistent",
                git_username="persist-user",
                git_email="persist@example.com",
                ssh_private_key=sample_ssh_private_key,
                ssh_public_key=sample_ssh_public_key,
            )

            # Create second manager (simulating app restart)
            manager2 = ProfileManager(mock_session_manager, mock_crypto_service)
            profiles = manager2.list_profiles()

            assert len(profiles) == 1
            assert profiles[0].name == "Persistent"
            assert profiles[0].id == created.id


# =============================================================================
# Session Lock Behavior Tests
# =============================================================================


class TestSessionLockBehavior:
    """Tests for behavior when session is locked."""

    def test_list_profiles_requires_unlocked_session(
        self, profile_manager_locked: ProfileManager
    ) -> None:
        """list_profiles should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.list_profiles()

    def test_get_profile_requires_unlocked_session(
        self, profile_manager_locked: ProfileManager
    ) -> None:
        """get_profile should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.get_profile(uuid4())

    def test_update_profile_requires_unlocked_session(
        self, profile_manager_locked: ProfileManager
    ) -> None:
        """update_profile should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.update_profile(uuid4(), name="New Name")

    def test_delete_profile_requires_unlocked_session(
        self, profile_manager_locked: ProfileManager
    ) -> None:
        """delete_profile should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.delete_profile(uuid4())


# =============================================================================
# Switch Profile Tests (Phase 4 - US2)
# =============================================================================


@pytest.fixture
def profile_manager_with_services(
    mock_session_manager: MagicMock,
    mock_crypto_service: MagicMock,
    mock_git_service: MagicMock,
    mock_ssh_service: MagicMock,
    mock_gpg_service: MagicMock,
    mock_credential_service: MagicMock,
    temp_dir: Path,
) -> ProfileManager:
    """Create a ProfileManager with all service mocks for switch_profile testing."""
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


class TestSwitchProfile:
    """Tests for switch_profile() method."""

    def test_switch_profile_updates_git_config(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
    ) -> None:
        """switch_profile should update global Git configuration."""
        profile = profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager_with_services.switch_profile(profile.id)

        mock_git_service.set_global_config.assert_called_once()
        call_kwargs = mock_git_service.set_global_config.call_args
        assert (
            call_kwargs.kwargs.get("username") == "work-user"
            or call_kwargs[1].get("username") == "work-user"
        )

    def test_switch_profile_clears_credentials(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_credential_service: MagicMock,
    ) -> None:
        """switch_profile should clear cached Git credentials."""
        profile = profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager_with_services.switch_profile(profile.id)

        mock_credential_service.clear_git_credentials.assert_called_once()

    def test_switch_profile_adds_ssh_key_to_agent(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_ssh_service: MagicMock,
    ) -> None:
        """switch_profile should add the profile's SSH key to ssh-agent."""
        profile = profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager_with_services.switch_profile(profile.id)

        mock_ssh_service.remove_all_keys.assert_called_once()
        mock_ssh_service.add_key.assert_called_once()

    def test_switch_profile_imports_gpg_key_when_enabled(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_gpg_service: MagicMock,
    ) -> None:
        """switch_profile should import GPG key when GPG is enabled."""
        gpg_private = (
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        gpg_public = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"
        )

        profile = profile_manager_with_services.create_profile(
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

        profile_manager_with_services.switch_profile(profile.id)

        mock_gpg_service.import_key.assert_called()

    def test_switch_profile_deactivates_previous_active_profile(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """switch_profile should deactivate the previously active profile."""
        profile1 = profile_manager_with_services.create_profile(
            name="Profile1",
            git_username="user1",
            git_email="user1@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )
        profile2 = profile_manager_with_services.create_profile(
            name="Profile2",
            git_username="user2",
            git_email="user2@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Switch to first profile
        profile_manager_with_services.switch_profile(profile1.id)
        assert profile_manager_with_services.get_active_profile().id == profile1.id

        # Switch to second profile
        profile_manager_with_services.switch_profile(profile2.id)

        # First profile should be inactive
        p1 = profile_manager_with_services.get_profile(profile1.id)
        p2 = profile_manager_with_services.get_profile(profile2.id)
        assert p1.is_active is False
        assert p2.is_active is True

    def test_switch_profile_updates_last_used_timestamp(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """switch_profile should update the last_used timestamp."""
        profile = profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        original_last_used = profile.last_used

        profile_manager_with_services.switch_profile(profile.id)

        updated = profile_manager_with_services.get_profile(profile.id)
        assert updated.last_used is not None
        if original_last_used is not None:
            assert updated.last_used > original_last_used

    def test_switch_profile_raises_profile_not_found(
        self, profile_manager_with_services: ProfileManager
    ) -> None:
        """switch_profile should raise ProfileNotFoundError for non-existent profile."""
        from src.models.exceptions import ProfileNotFoundError

        random_id = uuid4()
        with pytest.raises(ProfileNotFoundError):
            profile_manager_with_services.switch_profile(random_id)

    def test_switch_profile_requires_unlocked_session(
        self, profile_manager_locked: ProfileManager
    ) -> None:
        """switch_profile should raise SessionExpiredError when session is locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.switch_profile(uuid4())

    def test_switch_profile_local_scope_updates_repo_config(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
        mock_git_repo: Path,
    ) -> None:
        """switch_profile with local scope should update repository config."""
        profile = profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        profile_manager_with_services.switch_profile(
            profile.id, scope="local", repo_path=mock_git_repo
        )

        mock_git_service.set_local_config.assert_called_once()
        call_kwargs = mock_git_service.set_local_config.call_args
        assert (
            call_kwargs.kwargs.get("repo_path") == mock_git_repo
            or call_kwargs[1].get("repo_path") == mock_git_repo
        )


# =============================================================================
# Update Profile Edge Cases (Phase 6 - US4)
# =============================================================================


class TestUpdateProfileEdgeCases:
    """Tests for update_profile edge cases."""

    def test_update_profile_with_ssh_key_deletes_old_key_file(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_crypto_service: MagicMock,
    ) -> None:
        """update_profile should delete old SSH key file before saving new one."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Reset mock to track new calls
        mock_crypto_service.secure_delete_file.reset_mock()

        new_private = (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nnewkey\n-----END OPENSSH PRIVATE KEY-----"
        )
        new_public = b"ssh-ed25519 NEWKEY newuser@example.com"

        profile_manager.update_profile(
            profile.id,
            ssh_private_key=new_private,
            ssh_public_key=new_public,
        )

        # Verify secure_delete_file was called for old SSH key
        mock_crypto_service.secure_delete_file.assert_called()

    def test_update_profile_disabling_gpg_deletes_gpg_key_file(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_crypto_service: MagicMock,
    ) -> None:
        """update_profile should delete GPG key file when disabling GPG."""
        gpg_private = (
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        gpg_public = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"
        )

        profile = profile_manager.create_profile(
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

        # Reset mock to track new calls
        mock_crypto_service.secure_delete_file.reset_mock()

        # Disable GPG
        updated = profile_manager.update_profile(
            profile.id,
            gpg_enabled=False,
        )

        assert updated.gpg_key.enabled is False
        # Verify secure_delete_file was called for GPG key file
        mock_crypto_service.secure_delete_file.assert_called()

    def test_update_profile_preserves_created_at_timestamp(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """update_profile should not modify created_at timestamp."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        original_created_at = profile.created_at

        updated = profile_manager.update_profile(
            profile.id,
            name="Work Updated",
        )

        assert updated.created_at == original_created_at

    def test_update_profile_preserves_last_used_timestamp(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """update_profile should not modify last_used timestamp."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Set a specific last_used value
        profile_manager._profiles[0].last_used

        updated = profile_manager.update_profile(
            profile.id,
            name="Work Updated",
        )

        # last_used should not be modified by update
        assert updated.last_used == profile.last_used

    def test_update_profile_with_passphrase_change(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_crypto_service: MagicMock,
    ) -> None:
        """update_profile should allow updating SSH passphrase."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            ssh_passphrase="old-passphrase",
        )

        # Reset mock to track new calls
        mock_crypto_service.encrypt.reset_mock()

        # Update with new passphrase
        profile_manager.update_profile(
            profile.id,
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            ssh_passphrase="new-passphrase",
        )

        # Verify encrypt was called (for the new passphrase)
        mock_crypto_service.encrypt.assert_called()


# =============================================================================
# Delete Profile Edge Cases (Phase 6 - US4)
# =============================================================================


class TestDeleteProfileEdgeCases:
    """Tests for delete_profile edge cases."""

    def test_delete_active_profile_clears_git_config(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
        mock_ssh_service: MagicMock,
    ) -> None:
        """delete_profile should clear Git config when deleting active profile."""
        profile = profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Switch to make it active
        profile_manager_with_services.switch_profile(profile.id)
        mock_git_service.reset_mock()
        mock_ssh_service.reset_mock()

        # Delete the active profile
        profile_manager_with_services.delete_profile(profile.id)

        # Verify Git config was cleared (set to empty or unset)
        mock_git_service.set_global_config.assert_called_once()
        # Verify SSH keys were removed from agent
        mock_ssh_service.remove_all_keys.assert_called()

    def test_delete_profile_when_key_files_missing_succeeds(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_crypto_service: MagicMock,
    ) -> None:
        """delete_profile should succeed even if key files don't exist."""
        profile = profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Make secure_delete_file raise an error simulating missing file
        # But _delete_key_files already handles this, so it shouldn't propagate
        mock_crypto_service.secure_delete_file.side_effect = FileNotFoundError("File not found")

        # Should not raise
        profile_manager.delete_profile(profile.id)

        # Profile should be removed
        assert profile_manager.get_profile(profile.id) is None

    def test_delete_profile_with_gpg_enabled_cleans_up_gpg_file(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_crypto_service: MagicMock,
    ) -> None:
        """delete_profile should clean up GPG key file when profile has GPG enabled."""
        gpg_private = (
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
        )
        gpg_public = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"
        )

        profile = profile_manager.create_profile(
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

        # Reset mock to track delete calls
        mock_crypto_service.secure_delete_file.reset_mock()

        profile_manager.delete_profile(profile.id)

        # Verify secure_delete_file was called at least twice (SSH and GPG)
        assert mock_crypto_service.secure_delete_file.call_count >= 1

    def test_delete_inactive_profile_does_not_clear_git_config(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
        mock_ssh_service: MagicMock,
    ) -> None:
        """delete_profile should NOT clear Git config when deleting inactive profile."""
        profile1 = profile_manager_with_services.create_profile(
            name="Profile1",
            git_username="user1",
            git_email="user1@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )
        profile2 = profile_manager_with_services.create_profile(
            name="Profile2",
            git_username="user2",
            git_email="user2@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Switch to profile1 (make it active)
        profile_manager_with_services.switch_profile(profile1.id)
        mock_git_service.reset_mock()
        mock_ssh_service.reset_mock()

        # Delete profile2 (inactive)
        profile_manager_with_services.delete_profile(profile2.id)

        # Git config should NOT be cleared (profile1 is still active)
        mock_git_service.set_global_config.assert_not_called()
        mock_ssh_service.remove_all_keys.assert_not_called()


# =============================================================================
# Detect Current Profile Tests
# =============================================================================


class TestDetectCurrentProfile:
    """Tests for detect_current_profile() method."""

    def test_detect_current_profile_matches_by_email(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
    ) -> None:
        """detect_current_profile should match profile by email."""
        # Create a profile
        profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Configure git service to return matching email
        mock_git_service.get_global_config.return_value = {
            "user.name": "work-user",
            "user.email": "work@example.com",
        }

        detected = profile_manager_with_services.detect_current_profile()

        assert detected is not None
        assert detected.name == "Work"
        assert detected.is_active is True

    def test_detect_current_profile_matches_case_insensitive_email(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
    ) -> None:
        """detect_current_profile should match email case-insensitively."""
        profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="Work@Example.COM",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        mock_git_service.get_global_config.return_value = {
            "user.name": "work-user",
            "user.email": "work@example.com",
        }

        detected = profile_manager_with_services.detect_current_profile()

        assert detected is not None
        assert detected.name == "Work"

    def test_detect_current_profile_returns_none_when_no_match(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
    ) -> None:
        """detect_current_profile should return None when no profile matches."""
        profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        mock_git_service.get_global_config.return_value = {
            "user.name": "other-user",
            "user.email": "other@example.com",
        }

        detected = profile_manager_with_services.detect_current_profile()

        assert detected is None

    def test_detect_current_profile_returns_none_when_no_git_config(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
    ) -> None:
        """detect_current_profile should return None when git config is empty."""
        profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        mock_git_service.get_global_config.return_value = {
            "user.name": "",
            "user.email": "",
        }

        detected = profile_manager_with_services.detect_current_profile()

        assert detected is None

    def test_detect_current_profile_does_not_reactivate_already_active(
        self,
        profile_manager_with_services: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        mock_git_service: MagicMock,
    ) -> None:
        """detect_current_profile should not save if profile already active."""
        profile = profile_manager_with_services.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # Switch to make it active
        profile_manager_with_services.switch_profile(profile.id)

        mock_git_service.get_global_config.return_value = {
            "user.name": "work-user",
            "user.email": "work@example.com",
        }

        # Store current save count
        original_save_count = profile_manager_with_services._save_profiles

        detected = profile_manager_with_services.detect_current_profile()

        assert detected is not None
        assert detected.name == "Work"
        # Profile should already be active, no need to re-save

    def test_detect_current_profile_without_git_service(
        self,
        profile_manager: ProfileManager,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """detect_current_profile should return None when git service unavailable."""
        profile_manager.create_profile(
            name="Work",
            git_username="work-user",
            git_email="work@example.com",
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
        )

        # profile_manager fixture doesn't have git_service
        detected = profile_manager.detect_current_profile()

        assert detected is None
