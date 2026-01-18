"""Shared pytest fixtures for Git-Switch tests.

This module provides common fixtures used across unit, integration,
security, and e2e tests.
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# =============================================================================
# Path Fixtures
# =============================================================================


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files.

    Yields:
        Path to a temporary directory that is cleaned up after the test.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def app_data_dir(temp_dir: Path) -> Path:
    """Create a mock application data directory.

    Args:
        temp_dir: Temporary directory fixture.

    Returns:
        Path to the mock app data directory.
    """
    app_dir = temp_dir / "GitProfileSwitcher"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "keys").mkdir(exist_ok=True)
    return app_dir


@pytest.fixture
def mock_git_repo(temp_dir: Path) -> Path:
    """Create a mock Git repository for testing.

    Args:
        temp_dir: Temporary directory fixture.

    Returns:
        Path to the mock repository root.
    """
    repo_dir = temp_dir / "test-repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    git_dir = repo_dir / ".git"
    git_dir.mkdir(exist_ok=True)
    # Create minimal git config
    (git_dir / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    return repo_dir


# =============================================================================
# Cryptography Fixtures
# =============================================================================


@pytest.fixture
def test_password() -> str:
    """Provide a test master password.

    Returns:
        A test password string.
    """
    return "TestPassword123!"


@pytest.fixture
def test_salt() -> bytes:
    """Provide a fixed test salt for deterministic testing.

    Returns:
        32 bytes of deterministic salt.
    """
    return b"0" * 32


@pytest.fixture
def test_key() -> bytes:
    """Provide a fixed test encryption key.

    Returns:
        32 bytes representing a test AES-256 key.
    """
    return b"K" * 32


# =============================================================================
# SSH Key Fixtures
# =============================================================================


@pytest.fixture
def sample_ssh_private_key() -> bytes:
    """Provide a sample SSH private key for testing.

    This is a test-only key, never use in production.

    Returns:
        Bytes of a sample OpenSSH private key.
    """
    # This is a generated test key, not for real use
    return b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBtest1234567890abcdefghijklmnopqrstuvwxyzAAAAHHRlc3RAZXhh
bXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"""


@pytest.fixture
def sample_ssh_public_key() -> bytes:
    """Provide a sample SSH public key for testing.

    Returns:
        Bytes of a sample OpenSSH public key.
    """
    return b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBtest1234567890 test@example.com"


# =============================================================================
# Mock Service Fixtures
# =============================================================================


@pytest.fixture
def mock_git_service() -> MagicMock:
    """Create a mock GitService.

    Returns:
        A MagicMock configured as a GitService.
    """
    mock = MagicMock()
    mock.is_git_installed.return_value = True
    mock.get_global_config.return_value = {
        "user.name": "Test User",
        "user.email": "test@example.com",
    }
    return mock


@pytest.fixture
def mock_ssh_service() -> MagicMock:
    """Create a mock SSHService.

    Returns:
        A MagicMock configured as an SSHService.
    """
    mock = MagicMock()
    mock.is_agent_running.return_value = True
    mock.list_keys.return_value = []
    mock.add_key.return_value = True
    mock.remove_all_keys.return_value = True
    mock.test_connection.return_value = (True, "Hi testuser!")
    return mock


@pytest.fixture
def mock_gpg_service() -> MagicMock:
    """Create a mock GPGService.

    Returns:
        A MagicMock configured as a GPGService.
    """
    mock = MagicMock()
    mock.is_gpg_installed.return_value = True
    mock.list_keys.return_value = []
    mock.verify_signing_capability.return_value = True
    return mock


@pytest.fixture
def mock_credential_service() -> MagicMock:
    """Create a mock CredentialService.

    Returns:
        A MagicMock configured as a CredentialService.
    """
    mock = MagicMock()
    mock.list_git_credentials.return_value = []
    mock.clear_git_credentials.return_value = []
    return mock


@pytest.fixture
def mock_crypto_service() -> MagicMock:
    """Create a mock CryptoService.

    Returns:
        A MagicMock configured as a CryptoService.
    """
    mock = MagicMock()
    mock.generate_salt.return_value = b"0" * 32
    mock.derive_key.return_value = b"K" * 32
    mock.create_verification_hash.return_value = b"H" * 32
    mock.verify_password.return_value = True
    # Make encrypt/decrypt return predictable values
    mock.encrypt.side_effect = lambda data, key: b"ENC:" + data
    mock.decrypt.side_effect = lambda data, key: data[4:] if data.startswith(b"ENC:") else data
    return mock


# =============================================================================
# Environment Fixtures
# =============================================================================


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove Git-related environment variables for clean testing.

    Args:
        monkeypatch: pytest monkeypatch fixture.
    """
    env_vars = [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "GNUPGHOME",
    ]
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)


# =============================================================================
# Marker Configuration
# =============================================================================


def pytest_configure(config: pytest.Config) -> None:
    """Configure custom pytest markers.

    Args:
        config: pytest configuration object.
    """
    config.addinivalue_line("markers", "unit: Unit tests with mocked dependencies")
    config.addinivalue_line("markers", "integration: Integration tests with real services")
    config.addinivalue_line("markers", "security: Security-focused tests")
    config.addinivalue_line("markers", "e2e: End-to-end workflow tests")
    config.addinivalue_line("markers", "slow: Tests that take longer to run")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Automatically mark tests based on their location.

    Args:
        config: pytest configuration object.
        items: List of collected test items.
    """
    for item in items:
        # Get the path relative to tests directory
        rel_path = str(item.fspath)

        if "tests/unit" in rel_path or "tests\\unit" in rel_path:
            item.add_marker(pytest.mark.unit)
        elif "tests/integration" in rel_path or "tests\\integration" in rel_path:
            item.add_marker(pytest.mark.integration)
        elif "tests/security" in rel_path or "tests\\security" in rel_path:
            item.add_marker(pytest.mark.security)
        elif "tests/e2e" in rel_path or "tests\\e2e" in rel_path:
            item.add_marker(pytest.mark.e2e)
