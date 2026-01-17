"""External service integrations for Git-Switch.

This module contains service implementations for Git configuration,
SSH agent, GPG keyring, and Windows Credential Manager operations.
"""

from src.services.container import (
    ServiceContainer,
    create_container,
    create_test_container,
)
from src.services.protocols import (
    CredentialServiceProtocol,
    GitServiceProtocol,
    GPGServiceProtocol,
    SSHServiceProtocol,
)

__all__ = [
    "CredentialServiceProtocol",
    "GPGServiceProtocol",
    # Protocols
    "GitServiceProtocol",
    "SSHServiceProtocol",
    # Container
    "ServiceContainer",
    "create_container",
    "create_test_container",
]
