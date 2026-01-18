"""Security tests for authentication edge cases.

These tests verify security properties of the session and authentication:
- Edge case password handling
- Timing attack resistance
- Secure memory clearing
- Key and password protection

TDD Note: These tests are written before the implementation
and should FAIL until the implementation is complete.
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
def real_crypto_service() -> CryptoService:
    """Create a real CryptoService for security tests."""
    from src.core.crypto import CryptoService

    return CryptoService()


@pytest.fixture
def session_manager_real_crypto(
    real_crypto_service: CryptoService, temp_dir: Path
) -> SessionManager:
    """Create a SessionManager with real crypto for security tests."""
    from src.core.session import SessionManager

    with patch("src.core.session.get_master_key_path") as mock_path:
        mock_path.return_value = temp_dir / "master.json"
        manager = SessionManager(real_crypto_service, auto_lock_timeout=15)
        yield manager


# =============================================================================
# Password Edge Cases
# =============================================================================


class TestPasswordEdgeCases:
    """Tests for edge case password handling."""

    def test_empty_password_handled_safely(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Empty password should be handled without crashes."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            # Empty password should still work (not recommended but valid)
            session_manager_real_crypto.setup_master_password("")
            result = session_manager_real_crypto.unlock("")
            assert result is True

    def test_very_long_password_handled(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Very long password (10KB) should be handled."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            long_password = "A" * 10240  # 10KB password
            session_manager_real_crypto.setup_master_password(long_password)
            result = session_manager_real_crypto.unlock(long_password)
            assert result is True

    def test_unicode_password_works(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Unicode password with emoji, CJK, and RTL should work."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            unicode_password = "Hello世界🔐مرحبا"  # Mixed: Latin, CJK, emoji, Arabic
            session_manager_real_crypto.setup_master_password(unicode_password)
            result = session_manager_real_crypto.unlock(unicode_password)
            assert result is True

    def test_null_bytes_in_password_handled(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Password with null bytes should be handled safely."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            # While null bytes in strings are unusual, they shouldn't crash
            password_with_nulls = "pass\x00word\x00test"
            session_manager_real_crypto.setup_master_password(password_with_nulls)
            result = session_manager_real_crypto.unlock(password_with_nulls)
            assert result is True


# =============================================================================
# Timing Attack Resistance
# =============================================================================


class TestTimingAttackResistance:
    """Tests for timing attack resistance."""

    def test_timing_attack_resistance(
        self, real_crypto_service: CryptoService, temp_dir: Path
    ) -> None:
        """Password verification should use constant-time comparison."""
        from src.core.session import SessionManager

        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            manager = SessionManager(real_crypto_service, auto_lock_timeout=15)
            manager.setup_master_password("correct_password")

            # Measure timing for correct password
            correct_times = []
            for _ in range(5):
                start = time.perf_counter()
                manager.unlock("correct_password")
                end = time.perf_counter()
                correct_times.append(end - start)
                manager.lock()

            # Measure timing for wrong password (same length)
            wrong_times = []
            for _ in range(5):
                start = time.perf_counter()
                manager.unlock("incorrect_pass")  # Same length as correct
                end = time.perf_counter()
                wrong_times.append(end - start)

            # Calculate average times
            avg_correct = sum(correct_times) / len(correct_times)
            avg_wrong = sum(wrong_times) / len(wrong_times)

            # Times should be similar (within reasonable variance)
            # Allow for 10x variance due to system noise, but
            # timing difference should not be > 100ms
            time_diff = abs(avg_correct - avg_wrong)
            assert time_diff < 0.1, f"Timing difference too large: {time_diff}s"


# =============================================================================
# Secure Memory Tests
# =============================================================================


class TestSecureMemory:
    """Tests for secure memory handling."""

    def test_key_zeroed_after_lock(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Encryption key should be zeroed after lock."""

        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            session_manager_real_crypto.setup_master_password("test_password")
            session_manager_real_crypto.unlock("test_password")

            # Get reference to internal key storage
            # After lock, the key should be None
            session_manager_real_crypto.lock()

            assert session_manager_real_crypto.encryption_key is None
            assert session_manager_real_crypto._encryption_key is None or all(
                b == 0 for b in session_manager_real_crypto._encryption_key
            )

    def test_encryption_key_not_in_error_messages(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Encryption key should never appear in error messages."""
        from src.models.exceptions import AuthenticationError

        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            # Try to unlock without setup - should get error without key
            try:
                session_manager_real_crypto.unlock("some_password")
            except AuthenticationError as e:
                error_str = str(e)
                # Should not contain key bytes or base64 encoded keys
                assert "encryption_key" not in error_str.lower()
                assert b"K" * 32 not in error_str.encode()

    def test_password_not_stored_anywhere(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Password should never be stored in files."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            master_path = temp_dir / "master.json"
            mock_path.return_value = master_path

            test_password = "SecretPassword12345!"
            session_manager_real_crypto.setup_master_password(test_password)

            # Check master.json does not contain the password
            content = master_path.read_text()
            assert test_password not in content
            assert test_password.encode().hex() not in content

            # Also check that password is not in any attribute
            for attr_name in dir(session_manager_real_crypto):
                if not attr_name.startswith("_"):
                    continue
                attr_value = getattr(session_manager_real_crypto, attr_name, None)
                if isinstance(attr_value, (str, bytes)):
                    if isinstance(attr_value, str):
                        assert test_password not in attr_value
                    else:
                        assert test_password.encode() not in attr_value


# =============================================================================
# Salt Uniqueness Tests
# =============================================================================


class TestSaltUniqueness:
    """Tests for salt generation uniqueness."""

    def test_salt_is_unique_per_setup(
        self, real_crypto_service: CryptoService, temp_dir: Path
    ) -> None:
        """Each setup should generate a unique salt."""
        from src.core.session import SessionManager

        salts = []
        for i in range(5):
            with patch("src.core.session.get_master_key_path") as mock_path:
                master_path = temp_dir / f"master_{i}.json"
                mock_path.return_value = master_path

                manager = SessionManager(real_crypto_service, auto_lock_timeout=15)
                manager.setup_master_password("test_password")

                config = json.loads(master_path.read_text())
                salts.append(config["salt"])

        # All salts should be unique
        assert len(set(salts)) == 5, "Salts should be unique per setup"

    def test_verification_hash_differs_for_different_passwords(
        self, real_crypto_service: CryptoService, temp_dir: Path
    ) -> None:
        """Different passwords should produce different verification hashes."""
        from src.core.session import SessionManager

        hashes = []
        passwords = ["password1", "password2", "password3"]

        for i, password in enumerate(passwords):
            with patch("src.core.session.get_master_key_path") as mock_path:
                master_path = temp_dir / f"master_{i}.json"
                mock_path.return_value = master_path

                manager = SessionManager(real_crypto_service, auto_lock_timeout=15)
                manager.setup_master_password(password)

                config = json.loads(master_path.read_text())
                hashes.append(config["verification_hash"])

        # All hashes should be unique (due to unique salts + different passwords)
        assert len(set(hashes)) == 3, "Verification hashes should differ"


# =============================================================================
# Brute Force Protection Tests
# =============================================================================


class TestBruteForceProtection:
    """Tests for brute force resistance (via PBKDF2 iterations)."""

    def test_unlock_takes_reasonable_time(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Unlock with PBKDF2 should take measurable time (>10ms) for brute force resistance."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            session_manager_real_crypto.setup_master_password("test_password")

            # Measure unlock time
            start = time.perf_counter()
            session_manager_real_crypto.unlock("test_password")
            end = time.perf_counter()

            # With 100k PBKDF2 iterations, should take at least 10ms
            # This provides brute force resistance
            elapsed = end - start
            assert (
                elapsed >= 0.01
            ), f"Unlock too fast ({elapsed}s), may be vulnerable to brute force"


# =============================================================================
# Edge Case Handling Tests
# =============================================================================


class TestAuthEdgeCases:
    """Tests for authentication edge cases."""

    def test_setup_password_twice_overwrites(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Setting up password twice should overwrite the first."""
        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            session_manager_real_crypto.setup_master_password("first_password")
            session_manager_real_crypto.setup_master_password("second_password")

            # First password should no longer work
            assert session_manager_real_crypto.unlock("first_password") is False

            # Second password should work
            assert session_manager_real_crypto.unlock("second_password") is True

    def test_concurrent_unlock_attempts_are_safe(
        self, session_manager_real_crypto: SessionManager, temp_dir: Path
    ) -> None:
        """Concurrent unlock attempts should not cause race conditions."""
        import threading

        with patch("src.core.session.get_master_key_path") as mock_path:
            mock_path.return_value = temp_dir / "master.json"

            session_manager_real_crypto.setup_master_password("test_password")

            results = []
            errors = []

            def attempt_unlock(password: str) -> None:
                try:
                    result = session_manager_real_crypto.unlock(password)
                    results.append(result)
                except Exception as e:
                    errors.append(e)

            # Create multiple threads trying to unlock simultaneously
            threads = [
                threading.Thread(target=attempt_unlock, args=("test_password",)),
                threading.Thread(target=attempt_unlock, args=("wrong_password",)),
                threading.Thread(target=attempt_unlock, args=("test_password",)),
            ]

            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Should not have any exceptions
            assert len(errors) == 0, f"Concurrent unlock caused errors: {errors}"
            # At least one correct unlock should succeed
            assert any(r is True for r in results)
