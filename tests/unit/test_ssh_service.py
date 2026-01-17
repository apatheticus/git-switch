"""Unit tests for SSHService.

These tests verify Windows OpenSSH ssh-agent operations including:
- Checking/starting ssh-agent service
- Managing keys in the agent
- Testing SSH connections
- Key validation and fingerprint calculation

TDD Note: These tests are written before the SSHService implementation
and should FAIL until the implementation is complete.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from src.services.ssh_service import SSHService


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def ssh_service() -> "SSHService":
    """Create an SSHService instance for testing."""
    from src.services.ssh_service import SSHService

    return SSHService()


@pytest.fixture
def sample_ed25519_private_key() -> bytes:
    """Sample Ed25519 private key for testing."""
    # This is a test-only key, not for production use
    return b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBtest1234567890abcdefghijklmnopqrstuvwxyzAAAAHHRlc3RAZXhh
bXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"""


@pytest.fixture
def sample_ed25519_public_key() -> bytes:
    """Sample Ed25519 public key for testing."""
    return b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBtest1234567890 test@example.com"


# =============================================================================
# is_agent_running Tests
# =============================================================================


class TestIsAgentRunning:
    """Tests for is_agent_running() method."""

    def test_is_agent_running_returns_true_when_service_running(
        self, ssh_service: "SSHService"
    ) -> None:
        """is_agent_running should return True when ssh-agent service is running."""
        with patch("subprocess.run") as mock_run:
            # Simulate Windows service query showing RUNNING status
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="SERVICE_NAME: ssh-agent\n        STATE              : 4  RUNNING\n",
                stderr="",
            )

            result = ssh_service.is_agent_running()

            assert result is True

    def test_is_agent_running_returns_false_when_service_stopped(
        self, ssh_service: "SSHService"
    ) -> None:
        """is_agent_running should return False when ssh-agent is not running."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="SERVICE_NAME: ssh-agent\n        STATE              : 1  STOPPED\n",
                stderr="",
            )

            result = ssh_service.is_agent_running()

            assert result is False


# =============================================================================
# start_agent Tests
# =============================================================================


class TestStartAgent:
    """Tests for start_agent() method."""

    def test_start_agent_starts_ssh_agent_service(
        self, ssh_service: "SSHService"
    ) -> None:
        """start_agent should start the ssh-agent Windows service."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = ssh_service.start_agent()

            assert result is True
            # Verify net start or sc start was called
            assert mock_run.called

    def test_start_agent_returns_false_on_failure(
        self, ssh_service: "SSHService"
    ) -> None:
        """start_agent should return False if service fails to start."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Access denied",
            )

            result = ssh_service.start_agent()

            assert result is False


# =============================================================================
# list_keys Tests
# =============================================================================


class TestListKeys:
    """Tests for list_keys() method."""

    def test_list_keys_returns_loaded_fingerprints(
        self, ssh_service: "SSHService"
    ) -> None:
        """list_keys should return fingerprints of keys in the agent."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="256 SHA256:abcd1234efgh5678 test@example.com (ED25519)\n"
                "2048 SHA256:wxyz9876qrst4321 work@company.com (RSA)\n",
                stderr="",
            )

            result = ssh_service.list_keys()

            assert len(result) == 2
            assert "SHA256:abcd1234efgh5678" in result
            assert "SHA256:wxyz9876qrst4321" in result

    def test_list_keys_returns_empty_when_no_keys(
        self, ssh_service: "SSHService"
    ) -> None:
        """list_keys should return empty list when no keys are loaded."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="The agent has no identities.",
            )

            result = ssh_service.list_keys()

            assert result == []


# =============================================================================
# add_key Tests
# =============================================================================


class TestAddKey:
    """Tests for add_key() method."""

    def test_add_key_adds_private_key_to_agent(
        self, ssh_service: "SSHService", temp_dir: Path
    ) -> None:
        """add_key should add a private key file to the ssh-agent."""
        key_path = temp_dir / "test_key"
        key_path.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Identity added", stderr="")

            result = ssh_service.add_key(key_path)

            assert result is True
            # Verify ssh-add was called with key path
            assert mock_run.called

    def test_add_key_with_passphrase(
        self, ssh_service: "SSHService", temp_dir: Path
    ) -> None:
        """add_key should handle passphrase-protected keys."""
        key_path = temp_dir / "test_key"
        key_path.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nencrypted\n-----END OPENSSH PRIVATE KEY-----")

        with (
            patch("subprocess.Popen") as mock_popen,
            patch.object(ssh_service, "_add_key_with_passphrase") as mock_add,
        ):
            mock_add.return_value = True

            result = ssh_service.add_key(key_path, passphrase="secret123")

            assert result is True


# =============================================================================
# remove_all_keys Tests
# =============================================================================


class TestRemoveAllKeys:
    """Tests for remove_all_keys() method."""

    def test_remove_all_keys_clears_agent(
        self, ssh_service: "SSHService"
    ) -> None:
        """remove_all_keys should remove all keys from the ssh-agent."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="All identities removed.",
                stderr="",
            )

            result = ssh_service.remove_all_keys()

            assert result is True
            # Verify ssh-add -D was called
            calls = mock_run.call_args_list
            assert any("-D" in str(call) for call in calls)


# =============================================================================
# test_connection Tests
# =============================================================================


class TestTestConnection:
    """Tests for test_connection() method."""

    def test_test_connection_success_returns_username(
        self, ssh_service: "SSHService"
    ) -> None:
        """test_connection should return success with username on successful connection."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,  # GitHub returns 1 even on success
                stdout="",
                stderr="Hi testuser! You've successfully authenticated",
            )

            success, message = ssh_service.test_connection("github.com")

            assert success is True
            assert "testuser" in message

    def test_test_connection_failure_returns_error(
        self, ssh_service: "SSHService"
    ) -> None:
        """test_connection should return failure with error message on failure."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=255,
                stdout="",
                stderr="Permission denied (publickey)",
            )

            success, message = ssh_service.test_connection("github.com")

            assert success is False
            assert "Permission denied" in message or "denied" in message.lower()


# =============================================================================
# get_key_fingerprint Tests
# =============================================================================


class TestGetKeyFingerprint:
    """Tests for get_key_fingerprint() method."""

    def test_get_key_fingerprint_returns_sha256_format(
        self, ssh_service: "SSHService", sample_ed25519_public_key: bytes
    ) -> None:
        """get_key_fingerprint should return fingerprint in SHA256:xxx format."""
        # The implementation uses base64 decoding and hashlib directly
        # which doesn't require paramiko for basic public key formats
        result = ssh_service.get_key_fingerprint(sample_ed25519_public_key)

        assert result.startswith("SHA256:")


# =============================================================================
# validate_private_key Tests
# =============================================================================


class TestValidatePrivateKey:
    """Tests for validate_private_key() method."""

    def test_validate_private_key_accepts_valid_key(
        self, ssh_service: "SSHService"
    ) -> None:
        """validate_private_key should accept a valid unencrypted private key."""
        # Valid Ed25519 private key structure (test only)
        valid_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBtest1234567890abcdefghijklmnopqrstuvwxyzAAAAHHRlc3RAZXhh
bXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"""
        # The basic validation checks for PEM format markers
        # which works without paramiko installed
        valid, error = ssh_service.validate_private_key(valid_key)

        # Should be valid based on format (has BEGIN/END markers)
        assert valid is True
        assert error == ""

    def test_validate_private_key_rejects_invalid_format(
        self, ssh_service: "SSHService"
    ) -> None:
        """validate_private_key should reject keys with invalid format."""
        invalid_key = b"not a valid ssh key format"

        valid, error = ssh_service.validate_private_key(invalid_key)

        assert valid is False
        assert error != ""

    def test_validate_private_key_with_correct_passphrase(
        self, ssh_service: "SSHService"
    ) -> None:
        """validate_private_key should accept encrypted key with correct passphrase."""
        # For basic format validation, the key just needs to have PEM markers
        encrypted_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB
-----END OPENSSH PRIVATE KEY-----
"""
        # Basic validation checks format, not actual passphrase correctness
        # when paramiko is not available
        valid, error = ssh_service.validate_private_key(
            encrypted_key, passphrase="correct_passphrase"
        )

        assert valid is True
