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

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

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
    mock.decrypt.side_effect = (
        lambda data, key: data[4:] if data.startswith(b"ENC:") else data
    )
    return mock


@pytest.fixture
def profile_manager(
    mock_session_manager: MagicMock, mock_crypto_service: MagicMock, temp_dir: Path
) -> "ProfileManager":
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
) -> "ProfileManager":
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

    def test_list_profiles_empty_when_no_profiles(
        self, profile_manager: "ProfileManager"
    ) -> None:
        """list_profiles should return empty list when no profiles exist."""
        profiles = profile_manager.list_profiles()
        assert profiles == []

    def test_list_profiles_returns_all_profiles(
        self,
        profile_manager: "ProfileManager",
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
        profile_manager: "ProfileManager",
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

    def test_get_profile_returns_none_when_not_found(
        self, profile_manager: "ProfileManager"
    ) -> None:
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
        profile_manager: "ProfileManager",
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
        profile_manager: "ProfileManager",
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
        profile_manager: "ProfileManager",
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
        profile_manager: "ProfileManager",
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """create_profile should create a profile with SSH and GPG keys."""
        gpg_private = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
        gpg_public = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"

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
        profile_manager: "ProfileManager",
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
        profile_manager: "ProfileManager",
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
        profile_manager_locked: "ProfileManager",
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
        profile_manager: "ProfileManager",
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
        profile_manager: "ProfileManager",
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

        new_private = b"-----BEGIN OPENSSH PRIVATE KEY-----\nnewkey\n-----END OPENSSH PRIVATE KEY-----"
        new_public = b"ssh-ed25519 NEWKEY newuser@example.com"

        updated = profile_manager.update_profile(
            profile.id,
            ssh_private_key=new_private,
            ssh_public_key=new_public,
        )

        # Public key should be updated
        assert updated.ssh_key is not None
        assert updated.ssh_key.public_key == new_public

    def test_update_profile_raises_not_found(
        self, profile_manager: "ProfileManager"
    ) -> None:
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
        profile_manager: "ProfileManager",
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
        profile_manager: "ProfileManager",
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

    def test_delete_profile_raises_not_found(
        self, profile_manager: "ProfileManager"
    ) -> None:
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
        self, profile_manager_locked: "ProfileManager"
    ) -> None:
        """list_profiles should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.list_profiles()

    def test_get_profile_requires_unlocked_session(
        self, profile_manager_locked: "ProfileManager"
    ) -> None:
        """get_profile should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.get_profile(uuid4())

    def test_update_profile_requires_unlocked_session(
        self, profile_manager_locked: "ProfileManager"
    ) -> None:
        """update_profile should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.update_profile(uuid4(), name="New Name")

    def test_delete_profile_requires_unlocked_session(
        self, profile_manager_locked: "ProfileManager"
    ) -> None:
        """delete_profile should raise SessionExpiredError when locked."""
        from src.models.exceptions import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            profile_manager_locked.delete_profile(uuid4())
