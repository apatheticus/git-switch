"""Unit tests for Git-Switch data models.

Tests verify dataclass validation, serialization, and edge cases.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

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

# =============================================================================
# SSHKey Tests
# =============================================================================


class TestSSHKey:
    """Tests for the SSHKey dataclass."""

    def test_valid_ssh_key(self) -> None:
        """SSHKey should accept valid encrypted keys."""
        key = SSHKey(
            private_key_encrypted=b"encrypted_private_key",
            public_key=b"ssh-ed25519 AAAA...",
            fingerprint="SHA256:abc123",
        )
        assert key.private_key_encrypted == b"encrypted_private_key"
        assert key.public_key == b"ssh-ed25519 AAAA..."
        assert key.fingerprint == "SHA256:abc123"

    def test_ssh_key_with_passphrase(self) -> None:
        """SSHKey should accept encrypted passphrase."""
        key = SSHKey(
            private_key_encrypted=b"encrypted_private_key",
            public_key=b"ssh-ed25519 AAAA...",
            passphrase_encrypted=b"encrypted_passphrase",
        )
        assert key.passphrase_encrypted == b"encrypted_passphrase"

    def test_ssh_key_without_passphrase(self) -> None:
        """SSHKey should allow None passphrase."""
        key = SSHKey(
            private_key_encrypted=b"encrypted_private_key",
            public_key=b"ssh-ed25519 AAAA...",
        )
        assert key.passphrase_encrypted is None

    def test_empty_private_key_raises(self) -> None:
        """SSHKey should reject empty private key."""
        with pytest.raises(ValueError, match="SSH private key is required"):
            SSHKey(
                private_key_encrypted=b"",
                public_key=b"ssh-ed25519 AAAA...",
            )

    def test_empty_public_key_raises(self) -> None:
        """SSHKey should reject empty public key."""
        with pytest.raises(ValueError, match="SSH public key is required"):
            SSHKey(
                private_key_encrypted=b"encrypted_private_key",
                public_key=b"",
            )


# =============================================================================
# GPGKey Tests
# =============================================================================


class TestGPGKey:
    """Tests for the GPGKey dataclass."""

    def test_disabled_gpg_key(self) -> None:
        """GPGKey should allow disabled state with no keys."""
        key = GPGKey(enabled=False)
        assert key.enabled is False
        assert key.key_id == ""
        assert key.private_key_encrypted is None
        assert key.public_key is None

    def test_enabled_gpg_key(self) -> None:
        """GPGKey should accept valid enabled configuration."""
        key = GPGKey(
            enabled=True,
            key_id="ABCD1234EFGH5678",
            private_key_encrypted=b"encrypted_gpg_key",
            public_key=b"-----BEGIN PGP PUBLIC KEY BLOCK-----",
        )
        assert key.enabled is True
        assert key.key_id == "ABCD1234EFGH5678"

    def test_enabled_without_key_id_raises(self) -> None:
        """GPGKey should reject enabled state without key ID."""
        with pytest.raises(ValueError, match="GPG key ID required when GPG is enabled"):
            GPGKey(
                enabled=True,
                key_id="",
                private_key_encrypted=b"encrypted_gpg_key",
            )

    def test_enabled_without_private_key_raises(self) -> None:
        """GPGKey should reject enabled state without private key."""
        with pytest.raises(ValueError, match="GPG private key required when GPG is enabled"):
            GPGKey(
                enabled=True,
                key_id="ABCD1234EFGH5678",
                private_key_encrypted=None,
            )

    def test_default_gpg_key(self) -> None:
        """GPGKey defaults should be disabled with empty values."""
        key = GPGKey()
        assert key.enabled is False
        assert key.key_id == ""


# =============================================================================
# Profile Tests
# =============================================================================


class TestProfile:
    """Tests for the Profile dataclass."""

    @pytest.fixture
    def valid_ssh_key(self) -> SSHKey:
        """Create a valid SSHKey for testing."""
        return SSHKey(
            private_key_encrypted=b"encrypted_key",
            public_key=b"ssh-ed25519 AAAA...",
            fingerprint="SHA256:test",
        )

    def test_valid_profile(self, valid_ssh_key: SSHKey) -> None:
        """Profile should accept valid configuration."""
        profile = Profile(
            name="Work Profile",
            git_username="John Doe",
            git_email="john@company.com",
            ssh_key=valid_ssh_key,
        )
        assert profile.name == "Work Profile"
        assert profile.git_username == "John Doe"
        assert profile.git_email == "john@company.com"
        assert profile.ssh_key is not None
        assert isinstance(profile.id, UUID)

    def test_profile_with_organization(self, valid_ssh_key: SSHKey) -> None:
        """Profile should accept optional organization."""
        profile = Profile(
            name="Work",
            git_username="John",
            git_email="john@company.com",
            organization="Acme Corp",
            ssh_key=valid_ssh_key,
        )
        assert profile.organization == "Acme Corp"

    def test_profile_auto_generates_id(self, valid_ssh_key: SSHKey) -> None:
        """Profile should auto-generate UUID if not provided."""
        profile = Profile(
            name="Test",
            git_username="Test",
            git_email="test@test.com",
            ssh_key=valid_ssh_key,
        )
        assert profile.id is not None
        assert isinstance(profile.id, UUID)

    def test_profile_auto_generates_created_at(self, valid_ssh_key: SSHKey) -> None:
        """Profile should auto-generate created_at timestamp."""
        before = datetime.now()
        profile = Profile(
            name="Test",
            git_username="Test",
            git_email="test@test.com",
            ssh_key=valid_ssh_key,
        )
        after = datetime.now()
        assert before <= profile.created_at <= after

    def test_empty_name_raises(self, valid_ssh_key: SSHKey) -> None:
        """Profile should reject empty name."""
        with pytest.raises(ValueError, match="Profile name is required"):
            Profile(
                name="",
                git_username="John",
                git_email="john@test.com",
                ssh_key=valid_ssh_key,
            )

    def test_whitespace_name_raises(self, valid_ssh_key: SSHKey) -> None:
        """Profile should reject whitespace-only name."""
        with pytest.raises(ValueError, match="Profile name is required"):
            Profile(
                name="   ",
                git_username="John",
                git_email="john@test.com",
                ssh_key=valid_ssh_key,
            )

    def test_empty_username_raises(self, valid_ssh_key: SSHKey) -> None:
        """Profile should reject empty git username."""
        with pytest.raises(ValueError, match="Git username is required"):
            Profile(
                name="Test",
                git_username="",
                git_email="test@test.com",
                ssh_key=valid_ssh_key,
            )

    def test_empty_email_raises(self, valid_ssh_key: SSHKey) -> None:
        """Profile should reject empty git email."""
        with pytest.raises(ValueError, match="Git email is required"):
            Profile(
                name="Test",
                git_username="Test",
                git_email="",
                ssh_key=valid_ssh_key,
            )

    def test_invalid_email_raises(self, valid_ssh_key: SSHKey) -> None:
        """Profile should reject invalid email format."""
        with pytest.raises(ValueError, match="Invalid email format"):
            Profile(
                name="Test",
                git_username="Test",
                git_email="not-an-email",
                ssh_key=valid_ssh_key,
            )

    def test_profile_without_ssh_key_is_valid(self) -> None:
        """Profile should accept None SSH key."""
        profile = Profile(
            name="Test",
            git_username="Test",
            git_email="test@test.com",
            ssh_key=None,
        )
        assert profile.ssh_key is None
        assert profile.has_ssh_key is False

    def test_profile_with_ssh_key_has_property(self, valid_ssh_key: SSHKey) -> None:
        """Profile should report has_ssh_key correctly when key is present."""
        profile = Profile(
            name="Test",
            git_username="Test",
            git_email="test@test.com",
            ssh_key=valid_ssh_key,
        )
        assert profile.ssh_key is not None
        assert profile.has_ssh_key is True

    def test_valid_email_formats(self, valid_ssh_key: SSHKey) -> None:
        """Profile should accept various valid email formats."""
        valid_emails = [
            "simple@example.com",
            "name.surname@company.org",
            "user+tag@domain.co.uk",
            "test123@sub.domain.com",
        ]
        for email in valid_emails:
            profile = Profile(
                name="Test",
                git_username="Test",
                git_email=email,
                ssh_key=valid_ssh_key,
            )
            assert profile.git_email == email

    def test_profile_with_gpg_key(self, valid_ssh_key: SSHKey) -> None:
        """Profile should accept GPG key configuration."""
        gpg_key = GPGKey(
            enabled=True,
            key_id="ABCD1234",
            private_key_encrypted=b"encrypted",
        )
        profile = Profile(
            name="Test",
            git_username="Test",
            git_email="test@test.com",
            ssh_key=valid_ssh_key,
            gpg_key=gpg_key,
        )
        assert profile.gpg_key.enabled is True
        assert profile.gpg_key.key_id == "ABCD1234"


# =============================================================================
# Repository Tests
# =============================================================================


class TestRepository:
    """Tests for the Repository dataclass."""

    def test_valid_repository(self, tmp_path: Path) -> None:
        """Repository should accept valid absolute path."""
        repo_path = tmp_path / "my-repo"
        repo_path.mkdir()
        repo = Repository(path=repo_path)
        assert repo.path == repo_path
        assert repo.name == "my-repo"

    def test_repository_auto_generates_name(self, tmp_path: Path) -> None:
        """Repository should use folder name as default name."""
        repo_path = tmp_path / "awesome-project"
        repo_path.mkdir()
        repo = Repository(path=repo_path)
        assert repo.name == "awesome-project"

    def test_repository_custom_name(self, tmp_path: Path) -> None:
        """Repository should accept custom name."""
        repo_path = tmp_path / "project"
        repo_path.mkdir()
        repo = Repository(path=repo_path, name="Custom Name")
        assert repo.name == "Custom Name"

    def test_repository_auto_generates_id(self, tmp_path: Path) -> None:
        """Repository should auto-generate UUID."""
        repo = Repository(path=tmp_path)
        assert repo.id is not None
        assert isinstance(repo.id, UUID)

    def test_relative_path_raises(self) -> None:
        """Repository should reject relative paths."""
        with pytest.raises(ValueError, match="Repository path must be absolute"):
            Repository(path=Path("relative/path"))

    def test_is_valid_git_repo_true(self, tmp_path: Path) -> None:
        """is_valid_git_repo should return True for valid git repo."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        repo = Repository(path=tmp_path)
        assert repo.is_valid_git_repo() is True

    def test_is_valid_git_repo_false(self, tmp_path: Path) -> None:
        """is_valid_git_repo should return False for non-git folder."""
        repo = Repository(path=tmp_path)
        assert repo.is_valid_git_repo() is False

    def test_repository_with_profile_assignment(self, tmp_path: Path) -> None:
        """Repository should accept profile assignment."""
        profile_id = uuid4()
        repo = Repository(path=tmp_path, assigned_profile_id=profile_id)
        assert repo.assigned_profile_id == profile_id

    def test_use_local_config_default(self, tmp_path: Path) -> None:
        """Repository use_local_config should default to True."""
        repo = Repository(path=tmp_path)
        assert repo.use_local_config is True


# =============================================================================
# Settings Tests
# =============================================================================


class TestSettings:
    """Tests for the Settings dataclass."""

    def test_default_settings(self) -> None:
        """Settings should have sensible defaults."""
        settings = Settings()
        assert settings.start_with_windows is False
        assert settings.start_minimized is True
        assert settings.auto_lock_timeout == 15
        assert settings.show_notifications is True
        assert settings.confirm_before_switch is False
        assert settings.clear_ssh_agent_on_switch is True

    def test_custom_settings(self) -> None:
        """Settings should accept custom values."""
        settings = Settings(
            start_with_windows=True,
            start_minimized=False,
            auto_lock_timeout=30,
            show_notifications=False,
            confirm_before_switch=True,
            clear_ssh_agent_on_switch=False,
        )
        assert settings.start_with_windows is True
        assert settings.start_minimized is False
        assert settings.auto_lock_timeout == 30
        assert settings.show_notifications is False
        assert settings.confirm_before_switch is True
        assert settings.clear_ssh_agent_on_switch is False

    def test_negative_timeout_raises(self) -> None:
        """Settings should reject negative timeout."""
        with pytest.raises(ValueError, match="Auto-lock timeout cannot be negative"):
            Settings(auto_lock_timeout=-1)

    def test_excessive_timeout_raises(self) -> None:
        """Settings should reject timeout exceeding 24 hours."""
        with pytest.raises(ValueError, match="Auto-lock timeout cannot exceed 24 hours"):
            Settings(auto_lock_timeout=1441)

    def test_max_timeout_allowed(self) -> None:
        """Settings should allow timeout up to 24 hours (1440 minutes)."""
        settings = Settings(auto_lock_timeout=1440)
        assert settings.auto_lock_timeout == 1440

    def test_zero_timeout_allowed(self) -> None:
        """Settings should allow zero timeout (disabled)."""
        settings = Settings(auto_lock_timeout=0)
        assert settings.auto_lock_timeout == 0


# =============================================================================
# MasterKeyConfig Tests
# =============================================================================


class TestMasterKeyConfig:
    """Tests for the MasterKeyConfig dataclass."""

    def test_valid_config(self) -> None:
        """MasterKeyConfig should accept valid values."""
        config = MasterKeyConfig(
            salt=b"0" * 32,
            verification_hash=b"H" * 32,
            iterations=100_000,
        )
        assert len(config.salt) == 32
        assert len(config.verification_hash) == 32
        assert config.iterations == 100_000

    def test_default_iterations(self) -> None:
        """MasterKeyConfig should default to 100,000 iterations."""
        config = MasterKeyConfig(
            salt=b"0" * 32,
            verification_hash=b"H" * 32,
        )
        assert config.iterations == 100_000

    def test_short_salt_raises(self) -> None:
        """MasterKeyConfig should reject salt shorter than 32 bytes."""
        with pytest.raises(ValueError, match="Salt must be 32 bytes"):
            MasterKeyConfig(
                salt=b"0" * 16,
                verification_hash=b"H" * 32,
            )

    def test_long_salt_raises(self) -> None:
        """MasterKeyConfig should reject salt longer than 32 bytes."""
        with pytest.raises(ValueError, match="Salt must be 32 bytes"):
            MasterKeyConfig(
                salt=b"0" * 64,
                verification_hash=b"H" * 32,
            )

    def test_short_verification_hash_raises(self) -> None:
        """MasterKeyConfig should reject hash shorter than 32 bytes."""
        with pytest.raises(ValueError, match="Verification hash must be 32 bytes"):
            MasterKeyConfig(
                salt=b"0" * 32,
                verification_hash=b"H" * 16,
            )

    def test_insufficient_iterations_raises(self) -> None:
        """MasterKeyConfig should reject iterations below 100,000."""
        with pytest.raises(ValueError, match="Iterations must be at least 100,000"):
            MasterKeyConfig(
                salt=b"0" * 32,
                verification_hash=b"H" * 32,
                iterations=99_999,
            )

    def test_higher_iterations_allowed(self) -> None:
        """MasterKeyConfig should allow iterations above minimum."""
        config = MasterKeyConfig(
            salt=b"0" * 32,
            verification_hash=b"H" * 32,
            iterations=200_000,
        )
        assert config.iterations == 200_000


# =============================================================================
# Serialization Tests
# =============================================================================


class TestGitSwitchEncoder:
    """Tests for the GitSwitchEncoder JSON encoder."""

    def test_encode_uuid(self) -> None:
        """GitSwitchEncoder should encode UUID to string."""
        test_id = uuid4()
        result = json.dumps({"id": test_id}, cls=GitSwitchEncoder)
        assert str(test_id) in result

    def test_encode_datetime(self) -> None:
        """GitSwitchEncoder should encode datetime to ISO format."""
        dt = datetime(2026, 1, 17, 12, 30, 0)
        result = json.dumps({"timestamp": dt}, cls=GitSwitchEncoder)
        assert "2026-01-17T12:30:00" in result

    def test_encode_path(self) -> None:
        """GitSwitchEncoder should encode Path to string."""
        path = Path("/home/user/repo")
        result = json.dumps({"path": path}, cls=GitSwitchEncoder)
        data = json.loads(result)
        assert data["path"] in ["/home/user/repo", "\\home\\user\\repo"]

    def test_encode_bytes(self) -> None:
        """GitSwitchEncoder should encode bytes to base64."""
        data = b"Hello, World!"
        result = json.dumps({"data": data}, cls=GitSwitchEncoder)
        parsed = json.loads(result)
        assert parsed["data"] == "SGVsbG8sIFdvcmxkIQ=="

    def test_serialize_function(self) -> None:
        """serialize function should produce JSON string."""
        data = {"key": "value", "number": 42}
        result = serialize(data)
        assert '"key": "value"' in result or '"key":"value"' in result

    def test_serialize_with_indent(self) -> None:
        """serialize should support indentation."""
        data = {"key": "value"}
        result = serialize(data, indent=2)
        assert "\n" in result


class TestDeserialization:
    """Tests for deserialization functions."""

    def test_deserialize_bytes(self) -> None:
        """deserialize_bytes should decode base64."""
        encoded = "SGVsbG8sIFdvcmxkIQ=="
        result = deserialize_bytes(encoded)
        assert result == b"Hello, World!"

    def test_deserialize_uuid(self) -> None:
        """deserialize_uuid should parse UUID string."""
        uuid_str = "12345678-1234-5678-1234-567812345678"
        result = deserialize_uuid(uuid_str)
        assert isinstance(result, UUID)
        assert str(result) == uuid_str

    def test_deserialize_datetime(self) -> None:
        """deserialize_datetime should parse ISO format."""
        dt_str = "2026-01-17T12:30:00"
        result = deserialize_datetime(dt_str)
        assert result.year == 2026
        assert result.month == 1
        assert result.day == 17
        assert result.hour == 12
        assert result.minute == 30

    def test_deserialize_path(self) -> None:
        """deserialize_path should create Path object."""
        path_str = "/home/user/repo"
        result = deserialize_path(path_str)
        assert isinstance(result, Path)
