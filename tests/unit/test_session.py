"""Unit tests for SessionManager.

These tests verify session management functionality including:
- Master password setup and verification
- Session unlock/lock operations
- Encryption key management
- Auto-lock timer behavior

TDD Note: These tests are written before the SessionManager implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from src.core.session import SessionManager


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def crypto_service() -> MagicMock:
    """Create a mock CryptoService."""
    mock = MagicMock()
    mock.generate_salt.return_value = b"S" * 32
    mock.derive_key.return_value = b"K" * 32
    mock.create_verification_hash.return_value = b"H" * 32
    mock.verify_password.return_value = True
    return mock


@pytest.fixture
def session_manager(crypto_service: MagicMock, temp_dir: Path) -> "SessionManager":
    """Create a SessionManager instance for testing."""
    from src.core.session import SessionManager

    # Patch the master key path to use temp directory
    with patch("src.core.session.get_master_key_path") as mock_path:
        mock_path.return_value = temp_dir / "master.json"
        manager = SessionManager(crypto_service, auto_lock_timeout=15)
        yield manager


@pytest.fixture
def session_manager_with_password(
    crypto_service: MagicMock, temp_dir: Path
) -> "SessionManager":
    """Create a SessionManager with an existing master password."""
    import base64

    from src.core.session import SessionManager

    # Create master.json with stored password config
    # Use proper base64-encoded 32-byte values
    master_path = temp_dir / "master.json"
    salt_bytes = b"S" * 32  # 32 bytes
    hash_bytes = b"H" * 32  # 32 bytes
    master_config = {
        "salt": base64.b64encode(salt_bytes).decode("ascii"),
        "verification_hash": base64.b64encode(hash_bytes).decode("ascii"),
        "iterations": 100000,
    }
    master_path.write_text(json.dumps(master_config))

    with patch("src.core.session.get_master_key_path") as mock_path:
        mock_path.return_value = master_path
        manager = SessionManager(crypto_service, auto_lock_timeout=15)
        yield manager


# =============================================================================
# Master Password Existence Tests
# =============================================================================


class TestHasMasterPassword:
    """Tests for has_master_password() method."""

    def test_has_master_password_returns_false_when_no_config(
        self, session_manager: "SessionManager"
    ) -> None:
        """has_master_password should return False when no master.json exists."""
        assert session_manager.has_master_password() is False

    def test_has_master_password_returns_true_when_config_exists(
        self, session_manager_with_password: "SessionManager"
    ) -> None:
        """has_master_password should return True when master.json exists."""
        assert session_manager_with_password.has_master_password() is True


# =============================================================================
# Master Password Setup Tests
# =============================================================================


class TestSetupMasterPassword:
    """Tests for setup_master_password() method."""

    def test_setup_master_password_creates_master_json(
        self, session_manager: "SessionManager", temp_dir: Path
    ) -> None:
        """setup_master_password should create master.json file."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            master_path = temp_dir / "master.json"
            mock_path.return_value = master_path

            session_manager.setup_master_password("TestPassword123!")

            assert master_path.exists()

    def test_setup_master_password_stores_salt_and_hash(
        self, session_manager: "SessionManager", temp_dir: Path, crypto_service: MagicMock
    ) -> None:
        """setup_master_password should store salt and verification hash."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            master_path = temp_dir / "master.json"
            mock_path.return_value = master_path

            session_manager.setup_master_password("TestPassword123!")

            # Verify crypto service was called
            crypto_service.generate_salt.assert_called_once()
            crypto_service.derive_key.assert_called_once()
            crypto_service.create_verification_hash.assert_called_once()

            # Verify file contains expected structure
            config = json.loads(master_path.read_text())
            assert "salt" in config
            assert "verification_hash" in config
            assert "iterations" in config


# =============================================================================
# Unlock Tests
# =============================================================================


class TestUnlock:
    """Tests for unlock() method."""

    def test_unlock_with_correct_password_returns_true(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """unlock should return True with correct password."""
        crypto_service.verify_password.return_value = True

        result = session_manager_with_password.unlock("CorrectPassword!")

        assert result is True

    def test_unlock_with_wrong_password_returns_false(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """unlock should return False with wrong password."""
        crypto_service.verify_password.return_value = False

        result = session_manager_with_password.unlock("WrongPassword!")

        assert result is False

    def test_unlock_sets_encryption_key(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """unlock should set the encryption key when successful."""
        crypto_service.verify_password.return_value = True

        session_manager_with_password.unlock("CorrectPassword!")

        assert session_manager_with_password.encryption_key is not None


# =============================================================================
# Lock State Tests
# =============================================================================


class TestIsUnlocked:
    """Tests for is_unlocked property."""

    def test_is_unlocked_returns_false_when_locked(
        self, session_manager_with_password: "SessionManager"
    ) -> None:
        """is_unlocked should return False when session is locked."""
        assert session_manager_with_password.is_unlocked is False

    def test_is_unlocked_returns_true_after_unlock(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """is_unlocked should return True after successful unlock."""
        crypto_service.verify_password.return_value = True

        session_manager_with_password.unlock("CorrectPassword!")

        assert session_manager_with_password.is_unlocked is True


# =============================================================================
# Lock Tests
# =============================================================================


class TestLock:
    """Tests for lock() method."""

    def test_lock_clears_encryption_key(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """lock should clear the encryption key from memory."""
        crypto_service.verify_password.return_value = True
        session_manager_with_password.unlock("CorrectPassword!")
        assert session_manager_with_password.encryption_key is not None

        session_manager_with_password.lock()

        assert session_manager_with_password.encryption_key is None

    def test_encryption_key_is_none_when_locked(
        self, session_manager_with_password: "SessionManager"
    ) -> None:
        """encryption_key should be None when session is locked."""
        assert session_manager_with_password.encryption_key is None


# =============================================================================
# Change Password Tests
# =============================================================================


class TestChangeMasterPassword:
    """Tests for change_master_password() method."""

    def test_change_master_password_success(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """change_master_password should succeed with correct current password."""
        from src.models.exceptions import InvalidPasswordError

        crypto_service.verify_password.return_value = True

        # Should not raise
        session_manager_with_password.change_master_password(
            "CurrentPassword!", "NewPassword123!"
        )

    def test_change_master_password_wrong_current_raises(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """change_master_password should raise InvalidPasswordError with wrong current password."""
        from src.models.exceptions import InvalidPasswordError

        crypto_service.verify_password.return_value = False

        with pytest.raises(InvalidPasswordError):
            session_manager_with_password.change_master_password(
                "WrongCurrent!", "NewPassword123!"
            )


# =============================================================================
# Idle Timer Tests
# =============================================================================


class TestIdleTimer:
    """Tests for idle timer functionality."""

    def test_reset_idle_timer_resets_timer(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """reset_idle_timer should reset the auto-lock timer."""
        crypto_service.verify_password.return_value = True
        session_manager_with_password.unlock("Password!")

        # Should not raise - just verify method exists and can be called
        session_manager_with_password.reset_idle_timer()

    def test_set_lock_callback_stores_callback(
        self, session_manager_with_password: "SessionManager"
    ) -> None:
        """set_lock_callback should store the callback function."""
        callback_called = []

        def my_callback() -> None:
            callback_called.append(True)

        session_manager_with_password.set_lock_callback(my_callback)

        # Verify callback is stored (implementation detail)
        assert session_manager_with_password._lock_callback is not None


# =============================================================================
# Edge Cases
# =============================================================================


class TestSessionEdgeCases:
    """Tests for edge cases in session management."""

    def test_unlock_without_master_password_setup_fails(
        self, session_manager: "SessionManager"
    ) -> None:
        """unlock should fail gracefully when no master password is set up."""
        from src.models.exceptions import AuthenticationError

        with pytest.raises(AuthenticationError):
            session_manager.unlock("SomePassword!")

    def test_lock_when_already_locked_is_safe(
        self, session_manager_with_password: "SessionManager"
    ) -> None:
        """lock should be safe to call when already locked."""
        # Should not raise
        session_manager_with_password.lock()
        session_manager_with_password.lock()

    def test_multiple_unlock_attempts(
        self, session_manager_with_password: "SessionManager", crypto_service: MagicMock
    ) -> None:
        """Multiple unlock attempts should work correctly."""
        crypto_service.verify_password.return_value = False

        # First attempt fails
        assert session_manager_with_password.unlock("Wrong!") is False
        assert session_manager_with_password.is_unlocked is False

        # Second attempt succeeds
        crypto_service.verify_password.return_value = True
        assert session_manager_with_password.unlock("Correct!") is True
        assert session_manager_with_password.is_unlocked is True
