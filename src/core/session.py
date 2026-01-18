"""Session management for Git-Switch.

Manages master password authentication, session state, and auto-lock.
"""

from __future__ import annotations

import base64
import json
import threading
from typing import TYPE_CHECKING

from src.core.crypto import secure_zero
from src.models.exceptions import AuthenticationError, InvalidPasswordError
from src.models.settings import MasterKeyConfig
from src.utils.paths import get_master_key_path

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.core.protocols import CryptoServiceProtocol


class SessionManager:
    """Manages application session and auto-lock.

    This class handles:
    - Master password setup and verification
    - Session unlock/lock state
    - Encryption key management
    - Auto-lock timer (prepared for Phase 5)

    Attributes:
        is_unlocked: Whether the session is currently unlocked.
        encryption_key: The current session encryption key (None if locked).
    """

    def __init__(
        self,
        crypto_service: CryptoServiceProtocol,
        auto_lock_timeout: int = 15,  # minutes, 0 = disabled
    ) -> None:
        """Initialize the session manager.

        Args:
            crypto_service: Service for cryptographic operations.
            auto_lock_timeout: Minutes until auto-lock (0 = disabled).
        """
        self._crypto = crypto_service
        self._auto_lock_timeout = auto_lock_timeout
        self._encryption_key: bytearray | None = None  # bytearray for secure zeroing
        self._lock_callback: Callable[[], None] | None = None
        self._auto_lock_timer: threading.Timer | None = None
        self._master_config: MasterKeyConfig | None = None
        self._lock = threading.Lock()

    @property
    def is_unlocked(self) -> bool:
        """Whether the session is currently unlocked."""
        return self._encryption_key is not None

    @property
    def encryption_key(self) -> bytes | None:
        """Current session encryption key (None if locked)."""
        if self._encryption_key is None:
            return None
        return bytes(self._encryption_key)

    def has_master_password(self) -> bool:
        """Check if master password has been set up.

        Returns:
            True if master password exists, False for first-time setup.
        """
        master_path = get_master_key_path()
        return master_path.exists()

    def _load_master_config(self) -> MasterKeyConfig:
        """Load master key configuration from file.

        Returns:
            MasterKeyConfig loaded from master.json.

        Raises:
            AuthenticationError: If config file doesn't exist or is invalid.
        """
        master_path = get_master_key_path()
        if not master_path.exists():
            raise AuthenticationError("No master password configured")

        try:
            content = json.loads(master_path.read_text(encoding="utf-8"))
            return MasterKeyConfig(
                salt=base64.b64decode(content["salt"]),
                verification_hash=base64.b64decode(content["verification_hash"]),
                iterations=content["iterations"],
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise AuthenticationError(f"Invalid master key configuration: {e}") from e

    def _save_master_config(self, config: MasterKeyConfig) -> None:
        """Save master key configuration to file.

        Args:
            config: Configuration to save.
        """
        master_path = get_master_key_path()
        content = {
            "salt": base64.b64encode(config.salt).decode("ascii"),
            "verification_hash": base64.b64encode(config.verification_hash).decode("ascii"),
            "iterations": config.iterations,
        }
        master_path.write_text(json.dumps(content, indent=2), encoding="utf-8")

    def setup_master_password(self, password: str) -> None:
        """Set up master password for first-time use.

        Args:
            password: New master password.

        Raises:
            AuthenticationError: If setup fails.
        """
        try:
            # Generate new salt
            salt = self._crypto.generate_salt()

            # Derive key from password
            key = self._crypto.derive_key(password, salt)

            # Create verification hash
            verification_hash = self._crypto.create_verification_hash(key)

            # Store encryption key
            self._encryption_key = bytearray(key)

            # Create and save config
            config = MasterKeyConfig(
                salt=salt,
                verification_hash=verification_hash,
                iterations=100_000,
            )
            self._save_master_config(config)
            self._master_config = config

            # Start auto-lock timer if enabled
            self._start_auto_lock_timer()

        except Exception as e:
            raise AuthenticationError("Failed to setup master password") from e

    def unlock(self, password: str) -> bool:
        """Unlock the session with master password.

        Args:
            password: Master password.

        Returns:
            True if unlocked successfully, False if wrong password.

        Raises:
            AuthenticationError: If no master password is configured.
        """
        with self._lock:
            # Load master config if not already loaded
            if self._master_config is None:
                self._master_config = self._load_master_config()

            # Verify password
            is_valid = self._crypto.verify_password(
                password,
                self._master_config.salt,
                self._master_config.verification_hash,
            )

            if not is_valid:
                return False

            # Derive and store encryption key
            key = self._crypto.derive_key(password, self._master_config.salt)
            self._encryption_key = bytearray(key)

            # Start auto-lock timer if enabled
            self._start_auto_lock_timer()

            return True

    def lock(self) -> None:
        """Lock the session and clear encryption key from memory."""
        with self._lock:
            # Stop auto-lock timer
            self._stop_auto_lock_timer()

            # Securely zero the encryption key
            if self._encryption_key is not None:
                secure_zero(self._encryption_key)
                self._encryption_key = None

    def change_master_password(
        self,
        current_password: str,
        new_password: str,
    ) -> None:
        """Change the master password.

        Args:
            current_password: Current master password.
            new_password: New master password.

        Raises:
            InvalidPasswordError: If current password is wrong.
            AuthenticationError: If change fails.
        """
        # Load master config
        if self._master_config is None:
            self._master_config = self._load_master_config()

        # Verify current password
        is_valid = self._crypto.verify_password(
            current_password,
            self._master_config.salt,
            self._master_config.verification_hash,
        )

        if not is_valid:
            raise InvalidPasswordError("Current password is incorrect")

        # Generate new salt and key for new password
        new_salt = self._crypto.generate_salt()
        new_key = self._crypto.derive_key(new_password, new_salt)
        new_verification_hash = self._crypto.create_verification_hash(new_key)

        # Create and save new config
        new_config = MasterKeyConfig(
            salt=new_salt,
            verification_hash=new_verification_hash,
            iterations=100_000,
        )
        self._save_master_config(new_config)
        self._master_config = new_config

        # Update encryption key if session is unlocked
        if self._encryption_key is not None:
            secure_zero(self._encryption_key)
            self._encryption_key = bytearray(new_key)

    def reset_idle_timer(self) -> None:
        """Reset the idle timer (call on user activity)."""
        if self._auto_lock_timeout > 0 and self.is_unlocked:
            self._start_auto_lock_timer()

    def set_lock_callback(self, callback: Callable[[], None]) -> None:
        """Set callback to invoke when auto-lock triggers.

        Args:
            callback: Function to call when session auto-locks.
        """
        self._lock_callback = callback

    def _start_auto_lock_timer(self) -> None:
        """Start or restart the auto-lock timer."""
        if self._auto_lock_timeout <= 0:
            return

        self._stop_auto_lock_timer()

        # Convert minutes to seconds
        timeout_seconds = self._auto_lock_timeout * 60

        self._auto_lock_timer = threading.Timer(timeout_seconds, self._on_auto_lock_timeout)
        self._auto_lock_timer.daemon = True
        self._auto_lock_timer.start()

    def _stop_auto_lock_timer(self) -> None:
        """Stop the auto-lock timer if running."""
        if self._auto_lock_timer is not None:
            self._auto_lock_timer.cancel()
            self._auto_lock_timer = None

    def _on_auto_lock_timeout(self) -> None:
        """Handle auto-lock timeout."""
        self.lock()
        if self._lock_callback is not None:
            self._lock_callback()


__all__ = [
    "SessionManager",
]
