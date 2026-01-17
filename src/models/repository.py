"""Repository data model for Git-Switch.

This module contains the Repository dataclass for registered
Git repositories with profile assignments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID, uuid4


@dataclass
class Repository:
    """A registered Git repository.

    Attributes:
        id: Unique identifier for the repository.
        path: Absolute filesystem path to the repository root.
        name: Display name (defaults to folder name).
        assigned_profile_id: UUID of the assigned profile (optional).
        use_local_config: Whether to apply as local vs global git config.
    """

    id: UUID = field(default_factory=uuid4)
    path: Path = field(default_factory=Path)
    name: str = ""
    assigned_profile_id: UUID | None = None
    use_local_config: bool = True

    def __post_init__(self) -> None:
        """Validate repository configuration after initialization."""
        self._validate()
        if not self.name:
            self.name = self.path.name

    def _validate(self) -> None:
        """Validate repository configuration.

        Raises:
            ValueError: If path is not absolute.
        """
        if not self.path or not self.path.is_absolute():
            raise ValueError("Repository path must be absolute")

    def is_valid_git_repo(self) -> bool:
        """Check if path contains a .git directory.

        Returns:
            True if the path is a valid Git repository.
        """
        return (self.path / ".git").is_dir()


__all__ = [
    "Repository",
]
