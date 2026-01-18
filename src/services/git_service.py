"""Git configuration service for Git-Switch.

This module provides functionality for reading and writing Git configuration,
both globally and for specific repositories.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import TYPE_CHECKING

from src.models.exceptions import GitServiceError, InvalidRepositoryError

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class GitService:
    """Git configuration operations using subprocess.

    This service handles:
    - Checking if Git is installed
    - Reading/writing global Git configuration
    - Reading/writing local (repository) Git configuration
    """

    # Configuration keys we manage
    CONFIG_KEYS = ("user.name", "user.email", "user.signingkey", "commit.gpgsign")

    def is_git_installed(self) -> bool:
        """Check if Git is available in PATH.

        Returns:
            True if git command is available, False otherwise.
        """
        return shutil.which("git") is not None

    def get_global_config(self) -> dict[str, str]:
        """Read current Git global configuration (base values only).

        Note: This returns only the base global config values, not including
        any [include] directives. Use get_effective_config() to get the
        merged/effective configuration.

        Returns:
            Dictionary with keys: user.name, user.email, user.signingkey, commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
        """
        if not self.is_git_installed():
            raise GitServiceError("Git is not installed or not in PATH")

        result: dict[str, str] = {}

        for key in self.CONFIG_KEYS:
            try:
                process = subprocess.run(
                    ["git", "config", "--global", "--get", key],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if process.returncode == 0:
                    result[key] = process.stdout.strip()
                else:
                    result[key] = ""
            except subprocess.TimeoutExpired as e:
                raise GitServiceError(f"Git command timed out: {e}") from e
            except Exception as e:
                logger.warning(f"Failed to get git config {key}: {e}")
                result[key] = ""

        return result

    def get_effective_config(self) -> dict[str, str]:
        """Read the effective Git configuration (merged from all sources).

        This returns the actual effective config values after processing
        all [include] and [includeIf] directives in the gitconfig.

        Returns:
            Dictionary with keys: user.name, user.email, user.signingkey, commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
        """
        if not self.is_git_installed():
            raise GitServiceError("Git is not installed or not in PATH")

        result: dict[str, str] = {}

        for key in self.CONFIG_KEYS:
            try:
                # Use --get without --global to get effective/merged config
                process = subprocess.run(
                    ["git", "config", "--get", key],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if process.returncode == 0:
                    result[key] = process.stdout.strip()
                else:
                    result[key] = ""
            except subprocess.TimeoutExpired as e:
                raise GitServiceError(f"Git command timed out: {e}") from e
            except Exception as e:
                logger.warning(f"Failed to get effective git config {key}: {e}")
                result[key] = ""

        return result

    def set_global_config(
        self,
        username: str,
        email: str,
        signing_key: str | None = None,
        gpg_sign: bool = False,
    ) -> None:
        """Update Git global configuration.

        Args:
            username: Value for user.name
            email: Value for user.email
            signing_key: GPG key ID for user.signingkey (None to unset)
            gpg_sign: Whether to enable commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
        """
        if not self.is_git_installed():
            raise GitServiceError("Git is not installed or not in PATH")

        try:
            # Set user.name
            self._run_git_config("--global", "user.name", username)

            # Set user.email
            self._run_git_config("--global", "user.email", email)

            # Handle signing key
            if signing_key:
                self._run_git_config("--global", "user.signingkey", signing_key)
                self._run_git_config("--global", "commit.gpgsign", "true")
            else:
                # Unset signing config
                self._run_git_config_unset("--global", "user.signingkey")
                self._run_git_config("--global", "commit.gpgsign", "true" if gpg_sign else "false")

        except subprocess.TimeoutExpired as e:
            raise GitServiceError(f"Git command timed out: {e}") from e
        except GitServiceError:
            raise
        except Exception as e:
            raise GitServiceError(f"Failed to set global config: {e}") from e

    def get_local_config(self, repo_path: Path) -> dict[str, str]:
        """Read Git local configuration for a specific repository.

        Args:
            repo_path: Path to the repository root.

        Returns:
            Dictionary with keys: user.name, user.email, user.signingkey, commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
            InvalidRepositoryError: If repo_path is not a valid Git repository.
        """
        self._validate_repository(repo_path)

        result: dict[str, str] = {}

        for key in self.CONFIG_KEYS:
            try:
                process = subprocess.run(
                    ["git", "config", "--local", "--get", key],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=str(repo_path),
                )
                if process.returncode == 0:
                    result[key] = process.stdout.strip()
                else:
                    result[key] = ""
            except subprocess.TimeoutExpired as e:
                raise GitServiceError(f"Git command timed out: {e}") from e
            except Exception as e:
                logger.warning(f"Failed to get local git config {key}: {e}")
                result[key] = ""

        return result

    def set_local_config(
        self,
        repo_path: Path,
        username: str,
        email: str,
        signing_key: str | None = None,
        gpg_sign: bool = False,
    ) -> None:
        """Update Git local configuration for a specific repository.

        Args:
            repo_path: Path to the repository root.
            username: Value for user.name
            email: Value for user.email
            signing_key: GPG key ID for user.signingkey (None to unset)
            gpg_sign: Whether to enable commit.gpgsign

        Raises:
            GitServiceError: If git command fails.
            InvalidRepositoryError: If repo_path is not a valid Git repository.
        """
        self._validate_repository(repo_path)

        try:
            # Set user.name
            self._run_git_config("--local", "user.name", username, cwd=repo_path)

            # Set user.email
            self._run_git_config("--local", "user.email", email, cwd=repo_path)

            # Handle signing key
            if signing_key:
                self._run_git_config("--local", "user.signingkey", signing_key, cwd=repo_path)
                self._run_git_config("--local", "commit.gpgsign", "true", cwd=repo_path)
            else:
                # Unset signing config
                self._run_git_config_unset("--local", "user.signingkey", cwd=repo_path)
                self._run_git_config(
                    "--local",
                    "commit.gpgsign",
                    "true" if gpg_sign else "false",
                    cwd=repo_path,
                )

        except subprocess.TimeoutExpired as e:
            raise GitServiceError(f"Git command timed out: {e}") from e
        except (GitServiceError, InvalidRepositoryError):
            raise
        except Exception as e:
            raise GitServiceError(f"Failed to set local config: {e}") from e

    def _validate_repository(self, repo_path: Path) -> None:
        """Validate that a path is a Git repository.

        Args:
            repo_path: Path to validate.

        Raises:
            InvalidRepositoryError: If path is not a valid Git repository.
        """
        if not repo_path.exists():
            raise InvalidRepositoryError(f"Path does not exist: {repo_path}")

        git_dir = repo_path / ".git"
        if not git_dir.exists():
            raise InvalidRepositoryError(f"Not a Git repository: {repo_path}")

    def _run_git_config(
        self,
        scope: str,
        key: str,
        value: str,
        cwd: Path | None = None,
    ) -> None:
        """Run a git config set command.

        Args:
            scope: Config scope (--global or --local)
            key: Configuration key
            value: Configuration value
            cwd: Working directory for the command

        Raises:
            GitServiceError: If the command fails.
        """
        cmd = ["git", "config", scope, key, value]
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(cwd) if cwd else None,
            )
            if process.returncode != 0:
                raise GitServiceError(f"Failed to set {key}: {process.stderr.strip()}")
        except subprocess.TimeoutExpired as e:
            raise GitServiceError(f"Git command timed out: {e}") from e

    def _run_git_config_unset(
        self,
        scope: str,
        key: str,
        cwd: Path | None = None,
    ) -> None:
        """Run a git config unset command.

        Args:
            scope: Config scope (--global or --local)
            key: Configuration key to unset
            cwd: Working directory for the command

        Note:
            Does not raise error if key doesn't exist.
        """
        cmd = ["git", "config", scope, "--unset", key]
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(cwd) if cwd else None,
            )
            # Don't check return code - unset may fail if key doesn't exist
        except subprocess.TimeoutExpired as e:
            raise GitServiceError(f"Git command timed out: {e}") from e
        except Exception as e:
            logger.debug(f"Failed to unset {key}: {e}")


__all__ = ["GitService"]
