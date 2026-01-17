"""Settings data models for Git-Switch.

This module contains dataclasses for application Settings
and MasterKeyConfig for password verification.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Settings:
    """Application settings.

    All settings are non-sensitive and stored unencrypted.

    Attributes:
        start_with_windows: Whether to auto-start on Windows login.
        start_minimized: Whether to start to system tray if auto-start enabled.
        auto_lock_timeout: Minutes until auto-lock (0 = disabled).
        show_notifications: Whether to show toast notifications.
        confirm_before_switch: Whether to require confirmation before profile switch.
        clear_ssh_agent_on_switch: Whether to clear other keys from ssh-agent on switch.
    """

    start_with_windows: bool = False
    start_minimized: bool = True
    auto_lock_timeout: int = 15
    show_notifications: bool = True
    confirm_before_switch: bool = False
    clear_ssh_agent_on_switch: bool = True

    def __post_init__(self) -> None:
        """Validate settings values after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate settings values.

        Raises:
            ValueError: If any setting value is invalid.
        """
        if self.auto_lock_timeout < 0:
            raise ValueError("Auto-lock timeout cannot be negative")
        if self.auto_lock_timeout > 1440:
            raise ValueError("Auto-lock timeout cannot exceed 24 hours")


@dataclass
class MasterKeyConfig:
    """Master password configuration for verification.

    This stores only the verification data, never the actual password.

    Attributes:
        salt: 32 bytes, unique per installation.
        verification_hash: HMAC-SHA256 of known constant "GIT-SWITCH-VERIFY".
        iterations: PBKDF2 iterations (minimum 100,000).
    """

    salt: bytes
    verification_hash: bytes
    iterations: int = 100_000

    def __post_init__(self) -> None:
        """Validate master key configuration after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate master key configuration.

        Raises:
            ValueError: If any value is invalid.
        """
        if len(self.salt) != 32:
            raise ValueError("Salt must be 32 bytes")
        if len(self.verification_hash) != 32:
            raise ValueError("Verification hash must be 32 bytes")
        if self.iterations < 100_000:
            raise ValueError("Iterations must be at least 100,000")


__all__ = [
    "MasterKeyConfig",
    "Settings",
]
