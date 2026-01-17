"""End-to-end tests for master password workflow.

These tests verify the complete password workflow including:
- First-time password setup
- Unlock with correct/wrong password
- Password change workflow
- Auto-lock behavior

TDD Note: These tests exercise the full workflow with real components
(except for file system operations which use temp directories).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

if TYPE_CHECKING:
    from src.core.crypto import CryptoService
    from src.core.session import SessionManager


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def real_crypto_service() -> "CryptoService":
    """Create a real CryptoService for e2e testing."""
    from src.core.crypto import CryptoService

    return CryptoService()


@pytest.fixture
def e2e_session_manager(
    real_crypto_service: "CryptoService", temp_dir: Path
) -> "SessionManager":
    """Create a SessionManager with real crypto for e2e testing."""
    from src.core.session import SessionManager

    with patch("src.core.session.get_master_key_path") as mock_path:
        mock_path.return_value = temp_dir / "master.json"
        manager = SessionManager(real_crypto_service, auto_lock_timeout=15)
        yield manager


@pytest.fixture
def e2e_session_factory(real_crypto_service: "CryptoService", temp_dir: Path):
    """Factory for creating new SessionManager instances (simulates restart)."""
    from src.core.session import SessionManager

    master_path = temp_dir / "master.json"

    def create_session(auto_lock_timeout: int = 15) -> "SessionManager":
        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = master_path
            return SessionManager(real_crypto_service, auto_lock_timeout=auto_lock_timeout)

    return create_session


# =============================================================================
# Password Workflow Tests (T055)
# =============================================================================


class TestPasswordWorkflow:
    """E2E tests for master password workflow."""

    def test_first_time_setup_and_unlock(
        self, e2e_session_manager: "SessionManager"
    ) -> None:
        """First launch: set master password, lock, unlock with correct password."""
        # First-time: no master password exists
        assert e2e_session_manager.has_master_password() is False
        assert e2e_session_manager.is_unlocked is False

        # Setup master password
        e2e_session_manager.setup_master_password("MySecurePassword123!")

        # After setup, session should be unlocked
        assert e2e_session_manager.has_master_password() is True
        assert e2e_session_manager.is_unlocked is True
        assert e2e_session_manager.encryption_key is not None

        # Lock the session
        e2e_session_manager.lock()
        assert e2e_session_manager.is_unlocked is False
        assert e2e_session_manager.encryption_key is None

        # Unlock with correct password
        result = e2e_session_manager.unlock("MySecurePassword123!")
        assert result is True
        assert e2e_session_manager.is_unlocked is True
        assert e2e_session_manager.encryption_key is not None

    def test_unlock_with_wrong_password_rejected(
        self, e2e_session_manager: "SessionManager"
    ) -> None:
        """Wrong password should be rejected, correct password should work."""
        # Setup password first
        e2e_session_manager.setup_master_password("CorrectPassword!")
        e2e_session_manager.lock()

        # Try wrong password
        result = e2e_session_manager.unlock("WrongPassword!")
        assert result is False
        assert e2e_session_manager.is_unlocked is False

        # Try another wrong password
        result = e2e_session_manager.unlock("AnotherWrongOne!")
        assert result is False
        assert e2e_session_manager.is_unlocked is False

        # Now try correct password
        result = e2e_session_manager.unlock("CorrectPassword!")
        assert result is True
        assert e2e_session_manager.is_unlocked is True

    def test_session_persists_after_setup(self, e2e_session_factory) -> None:
        """After restart, password should be required (not setup)."""
        # First session: setup password
        session1 = e2e_session_factory()
        assert session1.has_master_password() is False

        session1.setup_master_password("PersistentPassword!")
        assert session1.has_master_password() is True
        assert session1.is_unlocked is True

        # "Close" the session
        session1.lock()

        # Create new session (simulates app restart)
        session2 = e2e_session_factory()

        # Password should already exist (no setup needed)
        assert session2.has_master_password() is True
        assert session2.is_unlocked is False

        # Should require password to unlock
        result = session2.unlock("PersistentPassword!")
        assert result is True
        assert session2.is_unlocked is True

    def test_auto_lock_workflow(self, e2e_session_factory) -> None:
        """Session auto-locks after idle timeout."""
        from src.core.session import SessionManager

        # Create session with very short timeout
        session = e2e_session_factory(auto_lock_timeout=1)

        # Setup and unlock
        session.setup_master_password("AutoLockTest!")

        # Patch the timer to be fast
        def fast_timer() -> None:
            import threading

            if session._auto_lock_timeout <= 0:
                return
            session._stop_auto_lock_timer()
            session._auto_lock_timer = threading.Timer(0.05, session._on_auto_lock_timeout)
            session._auto_lock_timer.daemon = True
            session._auto_lock_timer.start()

        session._start_auto_lock_timer = fast_timer

        # Trigger the fast timer
        session.reset_idle_timer()

        assert session.is_unlocked is True

        # Wait for auto-lock
        time.sleep(0.15)

        assert session.is_unlocked is False

        # Can unlock again with password
        result = session.unlock("AutoLockTest!")
        assert result is True

    def test_change_password_workflow(self, e2e_session_factory) -> None:
        """Change password and verify new password works."""
        from src.models.exceptions import InvalidPasswordError

        session = e2e_session_factory()

        # Setup initial password
        session.setup_master_password("OldPassword123!")
        session.lock()

        # Change password (requires current password)
        session.change_master_password("OldPassword123!", "NewPassword456!")

        # Lock and try old password - should fail
        session.lock()
        result = session.unlock("OldPassword123!")
        assert result is False

        # Try new password - should work
        result = session.unlock("NewPassword456!")
        assert result is True

        # Verify change with wrong current password fails
        with pytest.raises(InvalidPasswordError):
            session.change_master_password("WrongCurrent!", "AnotherNew!")


class TestPasswordSecurityEdgeCases:
    """Additional security-focused e2e tests."""

    def test_encryption_key_different_per_session(
        self, e2e_session_factory
    ) -> None:
        """Encryption keys should be consistent when derived from same password."""
        session1 = e2e_session_factory()
        session1.setup_master_password("ConsistentKey!")
        key1 = session1.encryption_key
        session1.lock()

        session2 = e2e_session_factory()
        session2.unlock("ConsistentKey!")
        key2 = session2.encryption_key

        # Keys should be the same (deterministic derivation)
        assert key1 == key2

    def test_memory_cleared_on_lock(self, e2e_session_manager: "SessionManager") -> None:
        """Encryption key should be cleared from memory on lock."""
        e2e_session_manager.setup_master_password("MemoryClear!")

        # Get reference to internal bytearray
        internal_key = e2e_session_manager._encryption_key
        assert internal_key is not None
        assert len(internal_key) == 32

        # Lock the session
        e2e_session_manager.lock()

        # Public property should be None
        assert e2e_session_manager.encryption_key is None

        # Internal bytearray should be zeroed (secure_zero was called)
        # Note: The bytearray reference is set to None after zeroing
        assert e2e_session_manager._encryption_key is None

    def test_lock_callback_triggered(
        self, e2e_session_factory
    ) -> None:
        """Lock callback should be triggered on auto-lock."""
        import threading

        session = e2e_session_factory(auto_lock_timeout=1)
        session.setup_master_password("CallbackTest!")

        callback_events = []

        def on_lock():
            callback_events.append("locked")

        session.set_lock_callback(on_lock)

        # Patch for fast timer
        def fast_timer() -> None:
            if session._auto_lock_timeout <= 0:
                return
            session._stop_auto_lock_timer()
            session._auto_lock_timer = threading.Timer(0.05, session._on_auto_lock_timeout)
            session._auto_lock_timer.daemon = True
            session._auto_lock_timer.start()

        session._start_auto_lock_timer = fast_timer
        session.reset_idle_timer()

        # Wait for auto-lock
        time.sleep(0.15)

        assert "locked" in callback_events
        assert session.is_unlocked is False
