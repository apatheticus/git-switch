"""Unit tests for GPGService.

These tests verify GPG keyring operations including:
- Checking if GPG is installed
- Listing keys in keyring
- Importing/exporting keys
- Deleting keys
- Verifying signing capability
- Key validation

TDD Note: These tests are written before the GPGService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from src.services.gpg_service import GPGService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def gpg_service() -> GPGService:
    """Create a GPGService instance for testing."""
    from src.services.gpg_service import GPGService

    return GPGService()


@pytest.fixture
def sample_gpg_private_key() -> bytes:
    """Sample GPG private key for testing."""
    return b"""-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBGYtest...
-----END PGP PRIVATE KEY BLOCK-----
"""


@pytest.fixture
def sample_gpg_public_key() -> bytes:
    """Sample GPG public key for testing."""
    return b"""-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGYtest...
-----END PGP PUBLIC KEY BLOCK-----
"""


# =============================================================================
# is_gpg_installed Tests
# =============================================================================


class TestIsGPGInstalled:
    """Tests for is_gpg_installed() method."""

    def test_is_gpg_installed_returns_true_when_available(self, gpg_service: GPGService) -> None:
        """is_gpg_installed should return True when gpg is in PATH."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/gpg"

            result = gpg_service.is_gpg_installed()

            assert result is True
            mock_which.assert_called_once_with("gpg")

    def test_is_gpg_installed_returns_false_when_missing(self, gpg_service: GPGService) -> None:
        """is_gpg_installed should return False when gpg is not in PATH."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None

            result = gpg_service.is_gpg_installed()

            assert result is False


# =============================================================================
# list_keys Tests
# =============================================================================


class TestListKeys:
    """Tests for list_keys() method."""

    def test_list_keys_returns_keyring_contents(self, gpg_service: GPGService) -> None:
        """list_keys should return all keys in the GPG keyring."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_gpg.list_keys.return_value = [
                {
                    "keyid": "ABCD1234EFGH5678",
                    "fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
                    "uids": ["Test User <test@example.com>"],
                },
                {
                    "keyid": "WXYZ9876QRST4321",
                    "fingerprint": "9876543210FEDCBA9876543210FEDCBA98765432",
                    "uids": ["Work User <work@company.com>"],
                },
            ]

            result = gpg_service.list_keys()

            assert len(result) == 2
            assert result[0]["keyid"] == "ABCD1234EFGH5678"
            assert result[1]["keyid"] == "WXYZ9876QRST4321"

    def test_list_keys_returns_empty_when_no_keys(self, gpg_service: GPGService) -> None:
        """list_keys should return empty list when keyring is empty."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_gpg.list_keys.return_value = []

            result = gpg_service.list_keys()

            assert result == []


# =============================================================================
# import_key Tests
# =============================================================================


class TestImportKey:
    """Tests for import_key() method."""

    def test_import_key_imports_private_key(
        self, gpg_service: GPGService, sample_gpg_private_key: bytes
    ) -> None:
        """import_key should import a GPG private key into the keyring."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_result = MagicMock()
            mock_result.ok = True
            mock_result.fingerprints = ["0123456789ABCDEF0123456789ABCDEF01234567"]
            mock_gpg.import_keys.return_value = mock_result

            result = gpg_service.import_key(sample_gpg_private_key)

            assert result is not None
            assert len(result) >= 8  # Key IDs are typically at least 8 chars
            mock_gpg.import_keys.assert_called_once()

    def test_import_key_returns_none_on_failure(self, gpg_service: GPGService) -> None:
        """import_key should return None if import fails."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_result = MagicMock()
            mock_result.ok = False
            mock_result.fingerprints = []
            mock_gpg.import_keys.return_value = mock_result

            result = gpg_service.import_key(b"invalid key data")

            assert result is None


# =============================================================================
# export_key Tests
# =============================================================================


class TestExportKey:
    """Tests for export_key() method."""

    def test_export_key_returns_armored_key(self, gpg_service: GPGService) -> None:
        """export_key should return an ASCII-armored key by default."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            armored_key = (
                b"-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
            )
            mock_gpg.export_keys.return_value = armored_key.decode("utf-8")

            result = gpg_service.export_key("ABCD1234EFGH5678", armor=True)

            assert result is not None
            assert b"BEGIN PGP" in result

    def test_export_key_returns_none_for_nonexistent_key(self, gpg_service: GPGService) -> None:
        """export_key should return None if key doesn't exist."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_gpg.export_keys.return_value = ""

            result = gpg_service.export_key("NONEXISTENT_KEY")

            assert result is None


# =============================================================================
# delete_key Tests
# =============================================================================


class TestDeleteKey:
    """Tests for delete_key() method."""

    def test_delete_key_removes_from_keyring(self, gpg_service: GPGService) -> None:
        """delete_key should remove the specified key from the keyring."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_result = MagicMock()
            mock_result.ok = True
            mock_gpg.delete_keys.return_value = mock_result

            result = gpg_service.delete_key("ABCD1234EFGH5678")

            assert result is True
            mock_gpg.delete_keys.assert_called()

    def test_delete_key_returns_false_for_nonexistent_key(self, gpg_service: GPGService) -> None:
        """delete_key should return False if key doesn't exist."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_result = MagicMock()
            mock_result.ok = False
            mock_gpg.delete_keys.return_value = mock_result

            result = gpg_service.delete_key("NONEXISTENT_KEY")

            assert result is False


# =============================================================================
# verify_signing_capability Tests
# =============================================================================


class TestVerifySigningCapability:
    """Tests for verify_signing_capability() method."""

    def test_verify_signing_capability_returns_true_for_signing_key(
        self, gpg_service: GPGService
    ) -> None:
        """verify_signing_capability should return True for keys that can sign."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            # Simulate a key with signing capability
            mock_gpg.list_keys.return_value = [
                {
                    "keyid": "ABCD1234EFGH5678",
                    "cap": "es",  # encrypt, sign
                }
            ]

            result = gpg_service.verify_signing_capability("ABCD1234EFGH5678")

            assert result is True

    def test_verify_signing_capability_returns_false_for_encrypt_only_key(
        self, gpg_service: GPGService
    ) -> None:
        """verify_signing_capability should return False for keys without sign capability."""
        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_gpg.list_keys.return_value = [
                {
                    "keyid": "ABCD1234EFGH5678",
                    "cap": "e",  # encrypt only
                }
            ]

            result = gpg_service.verify_signing_capability("ABCD1234EFGH5678")

            assert result is False


# =============================================================================
# validate_key Tests
# =============================================================================


class TestValidateKey:
    """Tests for validate_key() method."""

    def test_validate_key_extracts_key_id(
        self, gpg_service: GPGService, sample_gpg_private_key: bytes
    ) -> None:
        """validate_key should extract key ID from a valid GPG key."""
        # Skip if GPG is not available
        if gpg_service._gpg is None:
            pytest.skip("GPG not available")

        # Mock the gnupg.GPG class to avoid actual GPG operations
        # The validate_key method creates a new GPG instance in a temp dir
        mock_result = MagicMock()
        mock_result.ok = True
        mock_result.fingerprints = ["0123456789ABCDEF0123456789ABCDEF01234567"]

        mock_gpg_instance = MagicMock()
        mock_gpg_instance.import_keys.return_value = mock_result

        with patch("gnupg.GPG", return_value=mock_gpg_instance):
            valid, key_id, error = gpg_service.validate_key(sample_gpg_private_key)

        assert valid is True
        assert key_id == "89ABCDEF01234567"  # Last 16 chars of fingerprint
        assert error == ""

    def test_validate_key_rejects_invalid_key(self, gpg_service: GPGService) -> None:
        """validate_key should reject invalid GPG key data."""
        # Skip if GPG is not available
        if gpg_service._gpg is None:
            pytest.skip("GPG not available")

        # Mock the gnupg.GPG class to simulate import failure
        mock_result = MagicMock()
        mock_result.ok = False
        mock_result.fingerprints = []

        mock_gpg_instance = MagicMock()
        mock_gpg_instance.import_keys.return_value = mock_result

        with patch("gnupg.GPG", return_value=mock_gpg_instance):
            valid, key_id, error = gpg_service.validate_key(b"invalid key data")

        assert valid is False
        assert key_id == ""
        assert error != ""

    def test_validate_key_returns_error_when_gpg_unavailable(
        self,
    ) -> None:
        """validate_key should return error when GPG is not available."""
        from src.services.gpg_service import GPGService

        service = GPGService()
        # Force GPG to be unavailable
        service._gpg = None

        valid, key_id, error = service.validate_key(b"test key data")

        assert valid is False
        assert key_id == ""
        assert "GPG not available" in error


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestGPGServiceErrorHandling:
    """Tests for error handling in GPGService."""

    def test_list_keys_handles_gpg_error(self, gpg_service: GPGService) -> None:
        """list_keys should handle GPG errors gracefully."""
        from src.models.exceptions import GPGServiceError

        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_gpg.list_keys.side_effect = Exception("GPG error")

            with pytest.raises(GPGServiceError):
                gpg_service.list_keys()

    def test_import_key_handles_gpg_error(self, gpg_service: GPGService) -> None:
        """import_key should handle GPG errors gracefully."""
        from src.models.exceptions import GPGServiceError

        with patch.object(gpg_service, "_gpg") as mock_gpg:
            mock_gpg.import_keys.side_effect = Exception("Import failed")

            with pytest.raises(GPGServiceError):
                gpg_service.import_key(b"test key")
