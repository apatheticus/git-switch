"""Dependency injection container for Git-Switch.

This module provides the ServiceContainer for managing service dependencies
and factory functions for creating production and test containers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.protocols import (
        CryptoServiceProtocol,
        ProfileManagerProtocol,
        RepositoryManagerProtocol,
        SessionManagerProtocol,
    )
    from src.services.protocols import (
        CredentialServiceProtocol,
        GitServiceProtocol,
        GPGServiceProtocol,
        SSHServiceProtocol,
    )


@dataclass
class ServiceContainer:
    """Dependency injection container for all services.

    This container holds references to all service implementations,
    enabling loose coupling between layers and facilitating testing.

    Attributes:
        git_service: Git configuration service.
        ssh_service: SSH agent service.
        gpg_service: GPG keyring service.
        credential_service: Windows Credential Manager service.
        crypto_service: Encryption/decryption service.
        session_manager: Session and auto-lock manager.
        profile_manager: Profile CRUD operations.
        repository_manager: Repository registration service.
    """

    # Services layer
    git_service: GitServiceProtocol
    ssh_service: SSHServiceProtocol
    gpg_service: GPGServiceProtocol
    credential_service: CredentialServiceProtocol

    # Core layer
    crypto_service: CryptoServiceProtocol
    session_manager: SessionManagerProtocol
    profile_manager: ProfileManagerProtocol
    repository_manager: RepositoryManagerProtocol


def create_container() -> ServiceContainer:
    """Create production service container with real implementations.

    Returns:
        ServiceContainer configured with production service implementations.
    """
    # Import concrete implementations
    from src.core.crypto import CryptoService
    from src.core.profile_manager import ProfileManager
    from src.core.repository_manager import RepositoryManager
    from src.core.session import SessionManager
    from src.core.settings_manager import SettingsManager
    from src.services.credential_service import CredentialService
    from src.services.git_service import GitService
    from src.services.gpg_service import GPGService
    from src.services.ssh_service import SSHService

    # Load settings to get auto-lock timeout
    settings_manager = SettingsManager()
    settings = settings_manager.load_settings()

    # Create service instances (order matters for dependencies)
    git_service = GitService()
    ssh_service = SSHService()
    gpg_service = GPGService()
    credential_service = CredentialService()
    crypto_service = CryptoService()

    # Create session manager with crypto service
    session_manager = SessionManager(
        crypto_service=crypto_service,
        auto_lock_timeout=settings.auto_lock_timeout,
    )

    # Create profile manager with all dependencies
    profile_manager = ProfileManager(
        crypto_service=crypto_service,
        session_manager=session_manager,
        git_service=git_service,
        ssh_service=ssh_service,
        gpg_service=gpg_service,
        credential_service=credential_service,
    )

    # Create repository manager
    repository_manager = RepositoryManager(
        git_service=git_service,
        profile_manager=profile_manager,
    )

    return ServiceContainer(
        git_service=git_service,
        ssh_service=ssh_service,
        gpg_service=gpg_service,
        credential_service=credential_service,
        crypto_service=crypto_service,
        session_manager=session_manager,
        profile_manager=profile_manager,
        repository_manager=repository_manager,
    )


def create_test_container(
    git_service: GitServiceProtocol | None = None,
    ssh_service: SSHServiceProtocol | None = None,
    gpg_service: GPGServiceProtocol | None = None,
    credential_service: CredentialServiceProtocol | None = None,
    crypto_service: CryptoServiceProtocol | None = None,
    session_manager: SessionManagerProtocol | None = None,
    profile_manager: ProfileManagerProtocol | None = None,
    repository_manager: RepositoryManagerProtocol | None = None,
) -> ServiceContainer:
    """Create test container with mock implementations.

    All parameters are optional. When not provided, a basic mock
    implementation will be used. This allows tests to override
    only the services they need.

    Args:
        git_service: Mock GitService override.
        ssh_service: Mock SSHService override.
        gpg_service: Mock GPGService override.
        credential_service: Mock CredentialService override.
        crypto_service: Mock CryptoService override.
        session_manager: Mock SessionManager override.
        profile_manager: Mock ProfileManager override.
        repository_manager: Mock RepositoryManager override.

    Returns:
        ServiceContainer configured with mock service implementations.

    Note:
        This function will be fully implemented when mock service
        classes are available. Currently raises NotImplementedError
        if any required service is not provided.
    """
    # Ensure all services are provided for now
    if any(
        s is None
        for s in [
            git_service,
            ssh_service,
            gpg_service,
            credential_service,
            crypto_service,
            session_manager,
            profile_manager,
            repository_manager,
        ]
    ):
        raise NotImplementedError(
            "Test container requires all mock services to be provided. "
            "Default mocks will be implemented in a future phase."
        )

    return ServiceContainer(
        git_service=git_service,  # type: ignore[arg-type]
        ssh_service=ssh_service,  # type: ignore[arg-type]
        gpg_service=gpg_service,  # type: ignore[arg-type]
        credential_service=credential_service,  # type: ignore[arg-type]
        crypto_service=crypto_service,  # type: ignore[arg-type]
        session_manager=session_manager,  # type: ignore[arg-type]
        profile_manager=profile_manager,  # type: ignore[arg-type]
        repository_manager=repository_manager,  # type: ignore[arg-type]
    )


__all__ = [
    "ServiceContainer",
    "create_container",
    "create_test_container",
]
