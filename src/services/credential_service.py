"""Windows Credential Manager service for Git-Switch.

This module provides functionality for managing Git credentials in the
Windows Credential Manager.
"""

from __future__ import annotations

import ctypes
import logging
from ctypes import byref, wintypes
from typing import Any

from src.models.exceptions import CredentialServiceError

logger = logging.getLogger(__name__)

# Windows Credential Manager API constants
CRED_TYPE_GENERIC = 1
CRED_ENUMERATE_ALL_CREDENTIALS = 1


class SSHService:
    """Placeholder for type hint compatibility."""


class CredentialService:
    """Windows Credential Manager operations.

    This service handles:
    - Listing Git-related credentials
    - Deleting specific credentials
    - Clearing all Git credentials
    - Checking credential existence
    """

    # Git-related credential patterns
    GIT_CREDENTIAL_PATTERNS = (
        "git:",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "dev.azure.com",
        "LegacyGeneric:target=git:",
    )

    def __init__(self) -> None:
        """Initialize the credential service."""
        self._advapi32 = None
        self._load_windows_api()

    def _load_windows_api(self) -> None:
        """Load Windows Credential Manager API."""
        try:
            self._advapi32 = ctypes.windll.advapi32
        except Exception as e:
            logger.warning(f"Failed to load Windows API: {e}")
            self._advapi32 = None

    def list_git_credentials(self) -> list[str]:
        """List Git-related credential targets.

        Returns:
            List of credential target names (e.g., "git:https://github.com").
        """
        all_creds = self._enumerate_credentials()
        return [
            cred
            for cred in all_creds
            if any(pattern.lower() in cred.lower() for pattern in self.GIT_CREDENTIAL_PATTERNS)
        ]

    def delete_credential(self, target: str) -> bool:
        """Delete a specific credential.

        Args:
            target: Credential target name.

        Returns:
            True if deleted successfully, False if not found.

        Raises:
            CredentialServiceError: If deletion fails.
        """
        return self._delete_credential_impl(target)

    def clear_git_credentials(self) -> list[str]:
        """Clear all Git/GitHub cached credentials.

        Returns:
            List of credential targets that were cleared.

        Raises:
            CredentialServiceError: If clearing fails.
        """
        git_creds = self.list_git_credentials()
        cleared = []

        for target in git_creds:
            try:
                if self.delete_credential(target):
                    cleared.append(target)
            except CredentialServiceError as e:
                logger.warning(f"Failed to delete credential {target}: {e}")

        return cleared

    def has_credential(self, target: str) -> bool:
        """Check if a credential exists.

        Args:
            target: Credential target name.

        Returns:
            True if credential exists, False otherwise.
        """
        cred = self._get_credential(target)
        return cred is not None

    def _enumerate_credentials(self) -> list[str]:
        """Enumerate all credentials from Windows Credential Manager.

        Returns:
            List of credential target names.
        """
        if self._advapi32 is None:
            return self._enumerate_credentials_cmdlet()

        try:
            return self._enumerate_credentials_ctypes()
        except Exception as e:
            logger.debug(f"ctypes enumeration failed: {e}, falling back to cmdlet")
            return self._enumerate_credentials_cmdlet()

    def _enumerate_credentials_ctypes(self) -> list[str]:
        """Enumerate credentials using ctypes.

        Returns:
            List of credential target names.
        """

        # Define credential structure
        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        count = wintypes.DWORD()
        creds = ctypes.POINTER(ctypes.POINTER(CREDENTIAL))()

        try:
            result = self._advapi32.CredEnumerateW(
                None,  # Filter (None for all)
                CRED_ENUMERATE_ALL_CREDENTIALS,
                byref(count),
                byref(creds),
            )

            if not result:
                error = ctypes.get_last_error()
                if error == 1168:  # ERROR_NOT_FOUND - no credentials
                    return []
                raise CredentialServiceError(f"CredEnumerateW failed: {error}")

            targets = []
            for i in range(count.value):
                if creds[i].contents.TargetName:
                    targets.append(creds[i].contents.TargetName)

            return targets

        finally:
            if creds:
                self._advapi32.CredFree(creds)

    def _enumerate_credentials_cmdlet(self) -> list[str]:
        """Enumerate credentials using cmdkey command.

        Returns:
            List of credential target names.
        """
        import subprocess

        try:
            process = subprocess.run(
                ["cmdkey", "/list"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            targets = []
            for line in process.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Target:"):
                    target = line.replace("Target:", "").strip()
                    targets.append(target)

            return targets

        except Exception as e:
            logger.warning(f"cmdkey enumeration failed: {e}")
            return []

    def _delete_credential_impl(self, target: str) -> bool:
        """Delete a credential using Windows API or cmdkey.

        Args:
            target: Credential target name.

        Returns:
            True if deleted, False if not found.

        Raises:
            CredentialServiceError: If deletion fails.
        """
        if self._advapi32 is None:
            return self._delete_credential_cmdlet(target)

        try:
            return self._delete_credential_ctypes(target)
        except Exception as e:
            logger.debug(f"ctypes delete failed: {e}, falling back to cmdlet")
            return self._delete_credential_cmdlet(target)

    def _delete_credential_ctypes(self, target: str) -> bool:
        """Delete credential using ctypes.

        Args:
            target: Credential target name.

        Returns:
            True if deleted, False if not found.
        """
        result = self._advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0)

        if not result:
            error = ctypes.get_last_error()
            if error == 1168:  # ERROR_NOT_FOUND
                return False
            raise CredentialServiceError(f"CredDeleteW failed: {error}")

        return True

    def _delete_credential_cmdlet(self, target: str) -> bool:
        """Delete credential using cmdkey command.

        Args:
            target: Credential target name.

        Returns:
            True if deleted, False if not found.

        Raises:
            CredentialServiceError: If target contains invalid characters.
        """
        import subprocess

        # Validate target to prevent command injection
        # cmdkey targets should not contain shell metacharacters
        if any(c in target for c in ("&", "|", ";", "$", "`", "\n", "\r", '"', "'")):
            raise CredentialServiceError(f"Invalid credential target format: {target}")

        try:
            process = subprocess.run(
                ["cmdkey", "/delete:" + target],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if "deleted successfully" in process.stdout.lower():
                return True
            if "not found" in process.stderr.lower():
                return False

            return process.returncode == 0

        except Exception as e:
            raise CredentialServiceError(f"Failed to delete credential: {e}") from e

    def _get_credential(self, target: str) -> dict[str, Any] | None:
        """Get a specific credential.

        Args:
            target: Credential target name.

        Returns:
            Credential info dict or None if not found.
        """
        # Check if credential exists in enumerated list
        all_creds = self._enumerate_credentials()
        if target in all_creds:
            return {"target": target}
        return None


__all__ = ["CredentialService"]
