"""External service integrations for Git-Switch.

This module contains service implementations for Git configuration,
SSH agent, GPG keyring, and Windows Credential Manager operations.
"""

from src.services.container import (
    ServiceContainer,
    create_container,
    create_test_container,
)
from src.services.credential_service import CredentialService
from src.services.git_service import GitService
from src.services.gpg_service import GPGService
from src.services.protocols import (
    CredentialServiceProtocol,
    GitServiceProtocol,
    GPGServiceProtocol,
    SSHServiceProtocol,
)
from src.services.ssh_service import SSHService

__all__ = [
    # Service Implementations
    "CredentialService",
    "GitService",
    "GPGService",
    "SSHService",
    # Protocols
    "CredentialServiceProtocol",
    "GitServiceProtocol",
    "GPGServiceProtocol",
    "SSHServiceProtocol",
    # Container
    "ServiceContainer",
    "create_container",
    "create_test_container",
]
