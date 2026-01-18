"""SSH agent service for Git-Switch.

This module provides functionality for managing SSH keys in the Windows
OpenSSH ssh-agent service.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import logging
import os
import subprocess
import tempfile
from typing import TYPE_CHECKING

from src.models.exceptions import SSHServiceError

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class SSHService:
    """Windows OpenSSH ssh-agent operations.

    This service handles:
    - Checking if ssh-agent service is running
    - Starting the ssh-agent service
    - Adding/removing SSH keys from the agent
    - Testing SSH connections
    - Validating SSH keys
    """

    def is_agent_running(self) -> bool:
        """Check if Windows ssh-agent service is running.

        Returns:
            True if ssh-agent service is running, False otherwise.
        """
        try:
            process = subprocess.run(
                ["sc", "query", "ssh-agent"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "RUNNING" in process.stdout
        except Exception as e:
            logger.debug(f"Failed to query ssh-agent service: {e}")
            return False

    def start_agent(self) -> bool:
        """Attempt to start the ssh-agent service.

        Returns:
            True if service started successfully, False otherwise.

        Note:
            May require elevated privileges.
        """
        try:
            process = subprocess.run(
                ["net", "start", "ssh-agent"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if process.returncode == 0:
                return True

            # Check if already running
            if "already been started" in process.stderr.lower():
                return True

            logger.warning(f"Failed to start ssh-agent: {process.stderr}")
            return False
        except Exception as e:
            logger.exception(f"Failed to start ssh-agent service: {e}")
            return False

    def list_keys(self) -> list[str]:
        """List fingerprints of keys currently loaded in ssh-agent.

        Returns:
            List of key fingerprints (SHA256:xxx format).

        Raises:
            SSHServiceError: If ssh-add command fails.
        """
        try:
            process = subprocess.run(
                ["ssh-add", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Return code 1 with "no identities" is normal for empty agent
            if process.returncode == 1:
                if "no identities" in process.stderr.lower():
                    return []
                if "no identities" in process.stdout.lower():
                    return []

            if process.returncode not in {0, 1}:
                raise SSHServiceError(f"ssh-add -l failed: {process.stderr}")

            # Parse fingerprints from output
            # Format: "256 SHA256:xxx comment (TYPE)"
            fingerprints = []
            for line in process.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    # The fingerprint is the second part
                    fp = parts[1]
                    if fp.startswith(("SHA256:", "MD5:")):
                        fingerprints.append(fp)

            return fingerprints

        except subprocess.TimeoutExpired as e:
            raise SSHServiceError(f"ssh-add command timed out: {e}") from e
        except SSHServiceError:
            raise
        except Exception as e:
            raise SSHServiceError(f"Failed to list keys: {e}") from e

    def add_key(
        self,
        private_key_path: Path,
        passphrase: str | None = None,
    ) -> bool:
        """Add an SSH private key to the agent.

        Args:
            private_key_path: Path to the private key file.
            passphrase: Key passphrase if the key is protected.

        Returns:
            True if key was added successfully, False otherwise.

        Raises:
            SSHServiceError: If ssh-add command fails.
        """
        if passphrase:
            return self._add_key_with_passphrase(private_key_path, passphrase)

        try:
            process = subprocess.run(
                ["ssh-add", str(private_key_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if process.returncode != 0:
                raise SSHServiceError(f"ssh-add failed: {process.stderr}")

            return True

        except subprocess.TimeoutExpired as e:
            raise SSHServiceError(f"ssh-add command timed out: {e}") from e
        except SSHServiceError:
            raise
        except Exception as e:
            raise SSHServiceError(f"Failed to add key: {e}") from e

    def _add_key_with_passphrase(
        self,
        private_key_path: Path,
        passphrase: str,
    ) -> bool:
        """Add a passphrase-protected key to the agent.

        Args:
            private_key_path: Path to the private key file.
            passphrase: Key passphrase.

        Returns:
            True if key was added successfully, False otherwise.

        Raises:
            SSHServiceError: If adding key fails.
        """
        try:
            # Use environment variable to pass passphrase to ssh-add
            # via SSH_ASKPASS mechanism
            env = os.environ.copy()

            # Create a temporary script to echo the passphrase
            with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as f:
                f.write(f"@echo off\necho {passphrase}\n")
                askpass_script = f.name

            try:
                env["SSH_ASKPASS"] = askpass_script
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env["DISPLAY"] = ":0"

                process = subprocess.run(
                    ["ssh-add", str(private_key_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env,
                    stdin=subprocess.DEVNULL,
                )

                if process.returncode != 0:
                    raise SSHServiceError(f"ssh-add failed: {process.stderr}")

                return True
            finally:
                # Clean up askpass script
                with contextlib.suppress(Exception):
                    os.unlink(askpass_script)

        except SSHServiceError:
            raise
        except Exception as e:
            raise SSHServiceError(f"Failed to add key with passphrase: {e}") from e

    def remove_all_keys(self) -> bool:
        """Remove all keys from the ssh-agent.

        Returns:
            True if keys were removed successfully, False otherwise.

        Raises:
            SSHServiceError: If ssh-add command fails.
        """
        try:
            process = subprocess.run(
                ["ssh-add", "-D"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if process.returncode != 0:
                # It's OK if there were no identities
                if "no identities" not in process.stderr.lower():
                    raise SSHServiceError(f"ssh-add -D failed: {process.stderr}")

            return True

        except subprocess.TimeoutExpired as e:
            raise SSHServiceError(f"ssh-add command timed out: {e}") from e
        except SSHServiceError:
            raise
        except Exception as e:
            raise SSHServiceError(f"Failed to remove keys: {e}") from e

    def test_connection(self, host: str = "github.com") -> tuple[bool, str]:
        """Test SSH connection to a host.

        Args:
            host: Host to test connection to (default: github.com).

        Returns:
            Tuple of (success: bool, message: str).
            Message contains username on success or error details on failure.
        """
        try:
            process = subprocess.run(
                ["ssh", "-T", f"git@{host}", "-o", "StrictHostKeyChecking=no"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            # GitHub returns exit code 1 even on successful auth
            output = process.stderr + process.stdout

            if "successfully authenticated" in output.lower():
                # Extract username from "Hi username!" message
                for line in output.split("\n"):
                    if "Hi " in line and "!" in line:
                        username = line.split("Hi ")[1].split("!")[0]
                        return True, f"Authenticated as {username}"
                return True, "Successfully authenticated"

            if "permission denied" in output.lower():
                return False, "Permission denied (publickey)"

            return False, output.strip() or "Connection failed"

        except subprocess.TimeoutExpired:
            return False, "Connection timed out"
        except Exception as e:
            return False, str(e)

    def get_key_fingerprint(self, public_key: bytes) -> str:
        """Calculate SHA256 fingerprint of a public key.

        Args:
            public_key: SSH public key bytes.

        Returns:
            Fingerprint in SHA256:xxx format.
        """
        try:
            # Parse the public key
            key_str = public_key.decode("utf-8").strip()
            parts = key_str.split()

            if len(parts) < 2:
                raise ValueError("Invalid public key format")

            key_data = base64.b64decode(parts[1])

            # Calculate SHA256 fingerprint
            fingerprint = hashlib.sha256(key_data).digest()
            fp_base64 = base64.b64encode(fingerprint).decode("ascii").rstrip("=")

            return f"SHA256:{fp_base64}"
        except ValueError:
            raise SSHServiceError("Invalid public key format") from None
        except Exception as e:
            raise SSHServiceError(f"Failed to calculate fingerprint: {e}") from e

    def validate_private_key(
        self,
        private_key: bytes,
        passphrase: str | None = None,
    ) -> tuple[bool, str]:
        """Validate SSH private key format and passphrase.

        Args:
            private_key: Private key bytes.
            passphrase: Passphrase to test if key is encrypted.

        Returns:
            Tuple of (valid: bool, error_message: str).
            error_message is empty on success.
        """
        try:
            import paramiko

            key_file = io.BytesIO(private_key)

            # Try different key types
            key_types = [
                paramiko.Ed25519Key,
                paramiko.RSAKey,
                paramiko.ECDSAKey,
            ]

            for key_class in key_types:
                try:
                    key_file.seek(0)
                    if passphrase:
                        key_class.from_private_key(key_file, password=passphrase)
                    else:
                        key_class.from_private_key(key_file)
                    return True, ""
                except paramiko.ssh_exception.PasswordRequiredException:
                    return False, "Key is encrypted but no passphrase provided"
                except paramiko.ssh_exception.SSHException:
                    continue
                except Exception:
                    continue

            return False, "Invalid key format or unsupported key type"

        except ImportError:
            # Basic validation without paramiko
            key_str = private_key.decode("utf-8", errors="ignore")
            if "-----BEGIN" in key_str and "PRIVATE KEY" in key_str:
                return True, ""
            return False, "Invalid key format"
        except Exception as e:
            return False, str(e)


__all__ = ["SSHService"]
