"""Repository management for Git-Switch.

Handles repository registration, profile assignment, and local Git config application.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from src.models.exceptions import InvalidRepositoryError, RepositoryError
from src.models.repository import Repository
from src.utils.paths import get_repositories_path

if TYPE_CHECKING:
    from src.core.protocols import ProfileManagerProtocol
    from src.services.protocols import GitServiceProtocol

logger = logging.getLogger(__name__)


# repositories.json version
REPOSITORIES_VERSION = 1


class RepositoryManager:
    """Manages registered Git repositories.

    This class handles:
    - Registering and unregistering repositories
    - Assigning profiles to repositories
    - Applying profiles as local Git configuration
    - Persistence to repositories.json
    """

    def __init__(
        self,
        profile_manager: ProfileManagerProtocol,
        git_service: GitServiceProtocol,
        repositories_path: Path | None = None,
    ) -> None:
        """Initialize the repository manager.

        Args:
            profile_manager: Service for profile operations.
            git_service: Service for Git configuration operations.
            repositories_path: Path to repositories.json (optional, uses default).
        """
        self._profile_manager = profile_manager
        self._git_service = git_service
        self._repositories_path = repositories_path or get_repositories_path()
        self._repositories: list[Repository] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Ensure repositories are loaded from disk."""
        if not self._loaded:
            self._load_repositories()
            self._loaded = True

    def _load_repositories(self) -> None:
        """Load repositories from repositories.json file."""
        if not self._repositories_path.exists():
            self._repositories = []
            return

        try:
            data = json.loads(self._repositories_path.read_text(encoding="utf-8"))

            # Check version
            version = data.get("version", 0)
            if version != REPOSITORIES_VERSION:
                # Future: handle version migration
                logger.warning(
                    f"Unknown repositories.json version {version}, starting fresh"
                )
                self._repositories = []
                return

            # Deserialize repositories
            self._repositories = []
            for repo_data in data.get("repositories", []):
                repo = self._deserialize_repository(repo_data)
                if repo:
                    self._repositories.append(repo)

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to load repositories.json: {e}")
            self._repositories = []

    def _save_repositories(self) -> None:
        """Save repositories to repositories.json file."""
        data = {
            "version": REPOSITORIES_VERSION,
            "repositories": [
                self._serialize_repository(repo) for repo in self._repositories
            ],
        }

        self._repositories_path.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def _serialize_repository(self, repo: Repository) -> dict[str, Any]:
        """Serialize a repository to dictionary for JSON storage.

        Args:
            repo: Repository to serialize.

        Returns:
            Dictionary representation.
        """
        return {
            "id": str(repo.id),
            "path": str(repo.path),
            "name": repo.name,
            "assigned_profile_id": (
                str(repo.assigned_profile_id) if repo.assigned_profile_id else None
            ),
            "use_local_config": repo.use_local_config,
        }

    def _deserialize_repository(self, data: dict[str, Any]) -> Repository | None:
        """Deserialize a repository from dictionary.

        Args:
            data: Dictionary from JSON.

        Returns:
            Repository object or None if invalid.
        """
        try:
            assigned_id = data.get("assigned_profile_id")

            return Repository(
                id=UUID(data["id"]),
                path=Path(data["path"]),
                name=data.get("name", ""),
                assigned_profile_id=UUID(assigned_id) if assigned_id else None,
                use_local_config=data.get("use_local_config", True),
            )
        except (ValueError, KeyError, TypeError) as e:
            logger.warning(f"Failed to deserialize repository: {e}")
            return None

    def list_repositories(self) -> list[Repository]:
        """Get all registered repositories.

        Returns:
            List of Repository objects.
        """
        self._ensure_loaded()
        return list(self._repositories)

    def get_repository(self, repo_id: UUID) -> Repository | None:
        """Get a specific repository by ID.

        Args:
            repo_id: Repository UUID.

        Returns:
            Repository if found, None otherwise.
        """
        self._ensure_loaded()

        for repo in self._repositories:
            if repo.id == repo_id:
                return repo
        return None

    def add_repository(
        self,
        path: Path,
        assigned_profile_id: UUID | None = None,
    ) -> Repository:
        """Register a new repository.

        Args:
            path: Path to repository root.
            assigned_profile_id: Profile to assign (optional).

        Returns:
            Created Repository object.

        Raises:
            InvalidRepositoryError: If path is not a valid Git repository.
            RepositoryError: If repository is already registered.
        """
        self._ensure_loaded()

        # Validate path exists
        if not path.exists():
            raise InvalidRepositoryError(f"Path does not exist: {path}")

        # Validate is a Git repository
        if not self.validate_repository(path):
            raise InvalidRepositoryError(f"Path is not a valid Git repository: {path}")

        # Check for duplicates
        resolved_path = path.resolve()
        for repo in self._repositories:
            if repo.path.resolve() == resolved_path:
                raise RepositoryError(f"Repository already registered: {path}")

        # Create repository
        repo = Repository(
            path=resolved_path,
            assigned_profile_id=assigned_profile_id,
            use_local_config=True,
        )

        # Add to list and save
        self._repositories.append(repo)
        self._save_repositories()

        logger.info(f"Added repository: {repo.path}")
        return repo

    def remove_repository(self, repo_id: UUID) -> None:
        """Unregister a repository.

        Args:
            repo_id: Repository UUID.

        Raises:
            RepositoryError: If repository not found.
        """
        self._ensure_loaded()

        # Find repository
        repo_idx = None
        for i, repo in enumerate(self._repositories):
            if repo.id == repo_id:
                repo_idx = i
                break

        if repo_idx is None:
            raise RepositoryError(f"Repository not found: {repo_id}")

        # Remove and save
        removed = self._repositories.pop(repo_idx)
        self._save_repositories()

        logger.info(f"Removed repository: {removed.path}")

    def assign_profile(
        self,
        repo_id: UUID,
        profile_id: UUID | None,
    ) -> Repository:
        """Assign a profile to a repository.

        Args:
            repo_id: Repository UUID.
            profile_id: Profile UUID to assign (None to unassign).

        Returns:
            Updated Repository object.

        Raises:
            RepositoryError: If repository not found.
        """
        self._ensure_loaded()

        # Find repository
        repo_idx = None
        for i, repo in enumerate(self._repositories):
            if repo.id == repo_id:
                repo_idx = i
                break

        if repo_idx is None:
            raise RepositoryError(f"Repository not found: {repo_id}")

        old_repo = self._repositories[repo_idx]

        # Create updated repository
        updated = Repository(
            id=old_repo.id,
            path=old_repo.path,
            name=old_repo.name,
            assigned_profile_id=profile_id,
            use_local_config=old_repo.use_local_config,
        )

        # Update and save
        self._repositories[repo_idx] = updated
        self._save_repositories()

        if profile_id:
            logger.info(f"Assigned profile {profile_id} to repository {old_repo.path}")
        else:
            logger.info(f"Unassigned profile from repository {old_repo.path}")

        return updated

    def apply_profile(
        self,
        repo_id: UUID,
        scope: str = "local",
    ) -> None:
        """Apply assigned profile to repository.

        Args:
            repo_id: Repository UUID.
            scope: "local" for local config, "global" for global config.

        Raises:
            RepositoryError: If repository not found or no profile assigned.
            GitServiceError: If config update fails.
        """
        self._ensure_loaded()

        # Get repository
        repo = self.get_repository(repo_id)
        if repo is None:
            raise RepositoryError(f"Repository not found: {repo_id}")

        # Check for assigned profile
        if repo.assigned_profile_id is None:
            raise RepositoryError(
                f"Repository has no profile assigned: {repo.path}"
            )

        # Apply profile using ProfileManager
        self._profile_manager.switch_profile(
            repo.assigned_profile_id,
            scope=scope,
            repo_path=repo.path,
        )

        logger.info(
            f"Applied profile {repo.assigned_profile_id} to repository {repo.path}"
        )

    def validate_repository(self, path: Path) -> bool:
        """Check if path is a valid Git repository.

        Args:
            path: Path to check.

        Returns:
            True if valid Git repository, False otherwise.
        """
        if not path.exists():
            return False

        git_dir = path / ".git"
        return git_dir.is_dir()


__all__ = [
    "REPOSITORIES_VERSION",
    "RepositoryManager",
]
