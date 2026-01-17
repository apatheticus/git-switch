"""Unit tests for ValidationService.

These tests verify credential validation functionality including:
- SSH key format validation
- SSH connection testing
- GPG key format validation
- GPG signing capability verification

TDD Note: These tests are written before the ValidationService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

if TYPE_CHECKING:
    from src.core.validation import ValidationService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_ssh_service() -> MagicMock:
    """Create a mock SSHService for validation tests."""
    mock = MagicMock()
    mock.validate_private_key.return_value = (True, "")
    mock.test_connection.return_value = (True, "Authenticated as testuser")
    mock.get_key_fingerprint.return_value = "SHA256:abcd1234efgh5678"
    return mock


@pytest.fixture
def mock_gpg_service() -> MagicMock:
    """Create a mock GPGService for validation tests."""
    mock = MagicMock()
    mock.is_gpg_installed.return_value = True
    mock.validate_key.return_value = (True, "ABCD1234EFGH5678", "")
    mock.verify_signing_capability.return_value = True
    return mock


@pytest.fixture
def validation_service(
    mock_ssh_service: MagicMock,
    mock_gpg_service: MagicMock,
) -> "ValidationService":
    """Create a ValidationService instance for testing."""
    from src.core.validation import ValidationService

    return ValidationService(
        ssh_service=mock_ssh_service,
        gpg_service=mock_gpg_service,
    )


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
def sample_gpg_private_key() -> bytes:
    """Sample GPG private key for testing."""
    return b"""-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBGABCDEBCAC1234567890test
-----END PGP PRIVATE KEY BLOCK-----
"""


# =============================================================================
# SSH Format Validation Tests
# =============================================================================


class TestValidateSSHKey:
    """Tests for validate_ssh_key() method."""

    def test_validate_ssh_key_valid_rsa_key_returns_success(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_ssh_key should return success for valid RSA key."""
        mock_ssh_service.validate_private_key.return_value = (True, "")

        valid, message = validation_service.validate_ssh_key(
            private_key=sample_ssh_private_key,
            public_key=sample_ssh_public_key,
        )

        assert valid is True
        assert "Valid" in message or message == ""

    def test_validate_ssh_key_valid_ed25519_key_returns_success(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_ssh_key should return success for valid Ed25519 key."""
        mock_ssh_service.validate_private_key.return_value = (True, "")

        valid, message = validation_service.validate_ssh_key(
            private_key=sample_ssh_private_key,
            public_key=sample_ssh_public_key,
        )

        assert valid is True
        mock_ssh_service.validate_private_key.assert_called_once()

    def test_validate_ssh_key_invalid_format_returns_error(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_ssh_key should return error for invalid key format."""
        mock_ssh_service.validate_private_key.return_value = (
            False,
            "Invalid key format",
        )

        valid, message = validation_service.validate_ssh_key(
            private_key=b"invalid key data",
            public_key=sample_ssh_public_key,
        )

        assert valid is False
        assert "Invalid" in message or "format" in message.lower()

    def test_validate_ssh_key_with_passphrase_returns_success(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_ssh_key should accept encrypted key with correct passphrase."""
        mock_ssh_service.validate_private_key.return_value = (True, "")

        valid, message = validation_service.validate_ssh_key(
            private_key=sample_ssh_private_key,
            public_key=sample_ssh_public_key,
            passphrase="correct_passphrase",
        )

        assert valid is True
        mock_ssh_service.validate_private_key.assert_called_once_with(
            sample_ssh_private_key, "correct_passphrase"
        )

    def test_validate_ssh_key_wrong_passphrase_returns_error(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_ssh_key should return error for incorrect passphrase."""
        mock_ssh_service.validate_private_key.return_value = (
            False,
            "Key is encrypted but no passphrase provided",
        )

        valid, message = validation_service.validate_ssh_key(
            private_key=sample_ssh_private_key,
            public_key=sample_ssh_public_key,
            passphrase="wrong_passphrase",
        )

        assert valid is False
        assert "passphrase" in message.lower() or "encrypted" in message.lower()


# =============================================================================
# SSH Connection Tests
# =============================================================================


class TestValidateSSHConnection:
    """Tests for validate_ssh_connection() method."""

    def test_validate_ssh_connection_success_returns_username(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
    ) -> None:
        """validate_ssh_connection should return success with username."""
        mock_ssh_service.test_connection.return_value = (
            True,
            "Authenticated as testuser",
        )

        valid, message = validation_service.validate_ssh_connection("github.com")

        assert valid is True
        assert "testuser" in message or "Authenticated" in message

    def test_validate_ssh_connection_failure_returns_error(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
    ) -> None:
        """validate_ssh_connection should return error on failure."""
        mock_ssh_service.test_connection.return_value = (
            False,
            "Permission denied (publickey)",
        )

        valid, message = validation_service.validate_ssh_connection("github.com")

        assert valid is False
        assert "denied" in message.lower() or "Permission" in message

    def test_validate_ssh_connection_uses_specified_host(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
    ) -> None:
        """validate_ssh_connection should test against specified host."""
        mock_ssh_service.test_connection.return_value = (True, "Connected")

        validation_service.validate_ssh_connection("gitlab.com")

        mock_ssh_service.test_connection.assert_called_once_with("gitlab.com")

    def test_validate_ssh_connection_defaults_to_github(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
    ) -> None:
        """validate_ssh_connection should default to github.com."""
        mock_ssh_service.test_connection.return_value = (True, "Connected")

        validation_service.validate_ssh_connection()

        mock_ssh_service.test_connection.assert_called_once_with("github.com")


# =============================================================================
# GPG Format Validation Tests
# =============================================================================


class TestValidateGPGKey:
    """Tests for validate_gpg_key() method."""

    def test_validate_gpg_key_valid_key_returns_success(
        self,
        validation_service: "ValidationService",
        mock_gpg_service: MagicMock,
        sample_gpg_private_key: bytes,
    ) -> None:
        """validate_gpg_key should return success for valid key."""
        mock_gpg_service.validate_key.return_value = (True, "ABCD1234EFGH5678", "")

        valid, key_id, message = validation_service.validate_gpg_key(
            sample_gpg_private_key
        )

        assert valid is True
        assert key_id == "ABCD1234EFGH5678"
        assert message == "" or "Valid" in message

    def test_validate_gpg_key_invalid_format_returns_error(
        self,
        validation_service: "ValidationService",
        mock_gpg_service: MagicMock,
    ) -> None:
        """validate_gpg_key should return error for invalid format."""
        mock_gpg_service.validate_key.return_value = (
            False,
            "",
            "Invalid key format",
        )

        valid, key_id, message = validation_service.validate_gpg_key(
            b"not a valid gpg key"
        )

        assert valid is False
        assert key_id == ""
        assert "Invalid" in message or "format" in message.lower()

    def test_validate_gpg_key_returns_key_id(
        self,
        validation_service: "ValidationService",
        mock_gpg_service: MagicMock,
        sample_gpg_private_key: bytes,
    ) -> None:
        """validate_gpg_key should return the extracted key ID."""
        expected_key_id = "1234567890ABCDEF"
        mock_gpg_service.validate_key.return_value = (True, expected_key_id, "")

        valid, key_id, message = validation_service.validate_gpg_key(
            sample_gpg_private_key
        )

        assert valid is True
        assert key_id == expected_key_id

    def test_validate_gpg_key_gpg_not_installed_returns_error(
        self,
        mock_ssh_service: MagicMock,
        sample_gpg_private_key: bytes,
    ) -> None:
        """validate_gpg_key should return error when GPG is not installed."""
        from src.core.validation import ValidationService

        mock_gpg = MagicMock()
        mock_gpg.is_gpg_installed.return_value = False
        mock_gpg.validate_key.return_value = (False, "", "GPG not available")

        service = ValidationService(
            ssh_service=mock_ssh_service,
            gpg_service=mock_gpg,
        )

        valid, key_id, message = service.validate_gpg_key(sample_gpg_private_key)

        assert valid is False
        assert "GPG" in message or "not" in message.lower()


# =============================================================================
# GPG Signing Tests
# =============================================================================


class TestValidateGPGSigning:
    """Tests for validate_gpg_signing() method."""

    def test_validate_gpg_signing_capable_key_returns_success(
        self,
        validation_service: "ValidationService",
        mock_gpg_service: MagicMock,
    ) -> None:
        """validate_gpg_signing should return success for signing-capable key."""
        mock_gpg_service.verify_signing_capability.return_value = True

        valid, message = validation_service.validate_gpg_signing("ABCD1234EFGH5678")

        assert valid is True
        assert "sign" in message.lower() or valid

    def test_validate_gpg_signing_incapable_key_returns_error(
        self,
        validation_service: "ValidationService",
        mock_gpg_service: MagicMock,
    ) -> None:
        """validate_gpg_signing should return error for non-signing key."""
        mock_gpg_service.verify_signing_capability.return_value = False

        valid, message = validation_service.validate_gpg_signing("ABCD1234EFGH5678")

        assert valid is False
        assert "sign" in message.lower() or "capability" in message.lower()

    def test_validate_gpg_signing_uses_correct_key_id(
        self,
        validation_service: "ValidationService",
        mock_gpg_service: MagicMock,
    ) -> None:
        """validate_gpg_signing should verify the specified key ID."""
        key_id = "DEADBEEF12345678"
        mock_gpg_service.verify_signing_capability.return_value = True

        validation_service.validate_gpg_signing(key_id)

        mock_gpg_service.verify_signing_capability.assert_called_once_with(key_id)


# =============================================================================
# Integration Tests (Full Validation Flow)
# =============================================================================


class TestValidateAll:
    """Tests for validate_all() method - full credential validation."""

    def test_validate_all_valid_returns_all_success(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        mock_gpg_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        sample_gpg_private_key: bytes,
    ) -> None:
        """validate_all should return success for all valid credentials."""
        mock_ssh_service.validate_private_key.return_value = (True, "")
        mock_ssh_service.test_connection.return_value = (True, "Authenticated as user")
        mock_gpg_service.validate_key.return_value = (True, "ABCD1234", "")
        mock_gpg_service.verify_signing_capability.return_value = True

        results = validation_service.validate_all(
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            test_ssh_connection=True,
            gpg_private_key=sample_gpg_private_key,
            test_gpg_signing=True,
        )

        assert results["ssh_format"][0] is True
        assert results["ssh_connection"][0] is True
        assert results["gpg_format"][0] is True
        assert results["gpg_signing"][0] is True

    def test_validate_all_partial_validation_flags(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        mock_gpg_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_all should respect validation flags."""
        mock_ssh_service.validate_private_key.return_value = (True, "")

        results = validation_service.validate_all(
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            test_ssh_connection=False,  # Skip connection test
            gpg_private_key=None,  # No GPG key
            test_gpg_signing=False,
        )

        # SSH format should be validated
        assert results["ssh_format"][0] is True
        # SSH connection should be skipped
        assert "ssh_connection" not in results or results["ssh_connection"][0] is None
        # GPG should be skipped
        assert "gpg_format" not in results or results["gpg_format"][0] is None

    def test_validate_all_ssh_only(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_all should validate only SSH when no GPG key provided."""
        mock_ssh_service.validate_private_key.return_value = (True, "")
        mock_ssh_service.test_connection.return_value = (True, "Connected")

        results = validation_service.validate_all(
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            test_ssh_connection=True,
            gpg_private_key=None,
            test_gpg_signing=False,
        )

        assert results["ssh_format"][0] is True
        assert results["ssh_connection"][0] is True

    def test_validate_all_with_passphrase(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """validate_all should pass passphrase to SSH validation."""
        mock_ssh_service.validate_private_key.return_value = (True, "")

        validation_service.validate_all(
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            ssh_passphrase="test_passphrase",
            test_ssh_connection=False,
        )

        mock_ssh_service.validate_private_key.assert_called_once_with(
            sample_ssh_private_key, "test_passphrase"
        )


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestValidationErrorHandling:
    """Tests for error handling in validation operations."""

    def test_validation_handles_ssh_service_exception(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """Validation should handle SSH service exceptions gracefully."""
        mock_ssh_service.validate_private_key.side_effect = Exception("SSH error")

        valid, message = validation_service.validate_ssh_key(
            private_key=sample_ssh_private_key,
            public_key=sample_ssh_public_key,
        )

        assert valid is False
        assert "error" in message.lower() or "SSH" in message

    def test_validation_handles_gpg_service_exception(
        self,
        validation_service: "ValidationService",
        mock_gpg_service: MagicMock,
        sample_gpg_private_key: bytes,
    ) -> None:
        """Validation should handle GPG service exceptions gracefully."""
        mock_gpg_service.validate_key.side_effect = Exception("GPG error")

        valid, key_id, message = validation_service.validate_gpg_key(
            sample_gpg_private_key
        )

        assert valid is False
        assert key_id == ""
        assert "error" in message.lower() or "GPG" in message

    def test_validation_handles_connection_timeout(
        self,
        validation_service: "ValidationService",
        mock_ssh_service: MagicMock,
    ) -> None:
        """Validation should handle connection timeout gracefully."""
        mock_ssh_service.test_connection.return_value = (False, "Connection timed out")

        valid, message = validation_service.validate_ssh_connection()

        assert valid is False
        assert "timeout" in message.lower() or "timed" in message.lower()


# =============================================================================
# ProfileManager Integration Tests
# =============================================================================


class TestProfileManagerValidateCredentials:
    """Tests for ProfileManager.validate_credentials() integration."""

    @pytest.fixture
    def mock_session_manager(self) -> MagicMock:
        """Create a mock SessionManager that is unlocked."""
        mock = MagicMock()
        mock.is_unlocked = True
        mock.encryption_key = b"K" * 32
        return mock

    @pytest.fixture
    def mock_crypto_service(self) -> MagicMock:
        """Create a mock CryptoService."""
        mock = MagicMock()
        mock.encrypt.side_effect = lambda data, key: b"ENC:" + data
        mock.decrypt.side_effect = (
            lambda data, key: data[4:] if data.startswith(b"ENC:") else data
        )
        return mock

    @pytest.fixture
    def profile_manager_with_services(
        self,
        mock_session_manager: MagicMock,
        mock_crypto_service: MagicMock,
        mock_ssh_service: MagicMock,
        mock_gpg_service: MagicMock,
        temp_dir,
    ):
        """Create a ProfileManager with mock services."""
        from unittest.mock import patch

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
                ssh_service=mock_ssh_service,
                gpg_service=mock_gpg_service,
            )
            yield manager

    def test_profile_manager_validate_credentials_returns_results(
        self,
        profile_manager_with_services,
        mock_ssh_service: MagicMock,
        mock_gpg_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
    ) -> None:
        """ProfileManager.validate_credentials should return validation results."""
        mock_ssh_service.validate_private_key.return_value = (True, "")
        mock_ssh_service.test_connection.return_value = (True, "Authenticated as user")

        results = profile_manager_with_services.validate_credentials(
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            test_ssh_connection=True,
        )

        assert "ssh_format" in results
        assert results["ssh_format"][0] is True
        assert "ssh_connection" in results
        assert results["ssh_connection"][0] is True

    def test_profile_manager_validate_credentials_with_gpg(
        self,
        profile_manager_with_services,
        mock_ssh_service: MagicMock,
        mock_gpg_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        sample_gpg_private_key: bytes,
    ) -> None:
        """ProfileManager.validate_credentials should validate GPG key."""
        mock_ssh_service.validate_private_key.return_value = (True, "")
        mock_ssh_service.test_connection.return_value = (True, "Connected")
        mock_gpg_service.validate_key.return_value = (True, "ABCD1234", "")
        mock_gpg_service.verify_signing_capability.return_value = True

        results = profile_manager_with_services.validate_credentials(
            ssh_private_key=sample_ssh_private_key,
            ssh_public_key=sample_ssh_public_key,
            test_ssh_connection=True,
            gpg_private_key=sample_gpg_private_key,
            test_gpg_signing=True,
        )

        assert results["gpg_format"][0] is True
        assert results["gpg_signing"][0] is True

    def test_profile_manager_validate_credentials_without_services(
        self,
        mock_session_manager: MagicMock,
        mock_crypto_service: MagicMock,
        sample_ssh_private_key: bytes,
        sample_ssh_public_key: bytes,
        temp_dir,
    ) -> None:
        """ProfileManager.validate_credentials handles missing services gracefully."""
        from unittest.mock import patch

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

            # Create ProfileManager WITHOUT services
            manager = ProfileManager(mock_session_manager, mock_crypto_service)

            results = manager.validate_credentials(
                ssh_private_key=sample_ssh_private_key,
                ssh_public_key=sample_ssh_public_key,
                test_ssh_connection=False,
            )

            # Should return error for missing SSH service
            assert "ssh_format" in results
            assert results["ssh_format"][0] is False
            assert "not available" in results["ssh_format"][1]
