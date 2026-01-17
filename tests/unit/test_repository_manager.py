"""Unit tests for RepositoryManager.

These tests verify the repository management functionality including:
- Repository CRUD operations
- Profile assignment
- Persistence to JSON
- Repository validation
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from src.core.repository_manager import RepositoryManager
from src.models.exceptions import InvalidRepositoryError, RepositoryError


class TestListRepositories:
    """Tests for RepositoryManager.list_repositories()."""

    def test_list_repositories_empty_returns_empty_list(
        self, repository_manager: RepositoryManager
    ) -> None:
        """Empty repository list returns empty list."""
        result = repository_manager.list_repositories()
        assert result == []
        assert isinstance(result, list)


class TestAddRepository:
    """Tests for RepositoryManager.add_repository()."""

    def test_add_repository_creates_repository_with_defaults(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
    ) -> None:
        """Adding a repository creates it with default values."""
        repo = repository_manager.add_repository(mock_git_repo)

        assert repo is not None
        assert isinstance(repo.id, UUID)
        assert repo.path == mock_git_repo
        assert repo.name == mock_git_repo.name
        assert repo.assigned_profile_id is None
        assert repo.use_local_config is True

        # Verify it's in the list
        repos = repository_manager.list_repositories()
        assert len(repos) == 1
        assert repos[0].id == repo.id

    def test_add_repository_with_assigned_profile(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
        mock_profile: MagicMock,
    ) -> None:
        """Adding a repository with a profile assignment works."""
        repo = repository_manager.add_repository(
            mock_git_repo, assigned_profile_id=mock_profile.id
        )

        assert repo.assigned_profile_id == mock_profile.id

    def test_add_repository_invalid_path_raises_error(
        self,
        repository_manager: RepositoryManager,
        temp_dir: Path,
    ) -> None:
        """Adding a non-existent path raises InvalidRepositoryError."""
        invalid_path = temp_dir / "nonexistent"

        with pytest.raises(InvalidRepositoryError, match="does not exist"):
            repository_manager.add_repository(invalid_path)

    def test_add_repository_not_git_repo_raises_error(
        self,
        repository_manager: RepositoryManager,
        temp_dir: Path,
    ) -> None:
        """Adding a path without .git directory raises InvalidRepositoryError."""
        non_git_path = temp_dir / "not-a-repo"
        non_git_path.mkdir(parents=True, exist_ok=True)

        with pytest.raises(InvalidRepositoryError, match="not a valid Git repository"):
            repository_manager.add_repository(non_git_path)

    def test_add_repository_duplicate_path_raises_error(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
    ) -> None:
        """Adding the same repository path twice raises RepositoryError."""
        repository_manager.add_repository(mock_git_repo)

        with pytest.raises(RepositoryError, match="already registered"):
            repository_manager.add_repository(mock_git_repo)


class TestRemoveRepository:
    """Tests for RepositoryManager.remove_repository()."""

    def test_remove_repository_deletes_from_list(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
    ) -> None:
        """Removing a repository removes it from the list."""
        repo = repository_manager.add_repository(mock_git_repo)
        assert len(repository_manager.list_repositories()) == 1

        repository_manager.remove_repository(repo.id)

        assert len(repository_manager.list_repositories()) == 0

    def test_remove_repository_not_found_raises_error(
        self,
        repository_manager: RepositoryManager,
    ) -> None:
        """Removing a non-existent repository raises RepositoryError."""
        fake_id = uuid4()

        with pytest.raises(RepositoryError, match="not found"):
            repository_manager.remove_repository(fake_id)


class TestGetRepository:
    """Tests for RepositoryManager.get_repository()."""

    def test_get_repository_returns_repository(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
    ) -> None:
        """Getting an existing repository returns it."""
        added = repository_manager.add_repository(mock_git_repo)

        result = repository_manager.get_repository(added.id)

        assert result is not None
        assert result.id == added.id
        assert result.path == mock_git_repo

    def test_get_repository_not_found_returns_none(
        self,
        repository_manager: RepositoryManager,
    ) -> None:
        """Getting a non-existent repository returns None."""
        fake_id = uuid4()

        result = repository_manager.get_repository(fake_id)

        assert result is None


class TestAssignProfile:
    """Tests for RepositoryManager.assign_profile()."""

    def test_assign_profile_updates_repository(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
        mock_profile: MagicMock,
    ) -> None:
        """Assigning a profile updates the repository."""
        repo = repository_manager.add_repository(mock_git_repo)
        assert repo.assigned_profile_id is None

        updated = repository_manager.assign_profile(repo.id, mock_profile.id)

        assert updated.assigned_profile_id == mock_profile.id

        # Verify persistence
        fetched = repository_manager.get_repository(repo.id)
        assert fetched is not None
        assert fetched.assigned_profile_id == mock_profile.id

    def test_assign_profile_none_unassigns(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
        mock_profile: MagicMock,
    ) -> None:
        """Assigning None removes the profile assignment."""
        repo = repository_manager.add_repository(mock_git_repo, mock_profile.id)
        assert repo.assigned_profile_id == mock_profile.id

        updated = repository_manager.assign_profile(repo.id, None)

        assert updated.assigned_profile_id is None

    def test_assign_profile_repo_not_found_raises_error(
        self,
        repository_manager: RepositoryManager,
        mock_profile: MagicMock,
    ) -> None:
        """Assigning to a non-existent repository raises RepositoryError."""
        fake_repo_id = uuid4()

        with pytest.raises(RepositoryError, match="not found"):
            repository_manager.assign_profile(fake_repo_id, mock_profile.id)


class TestApplyProfile:
    """Tests for RepositoryManager.apply_profile()."""

    def test_apply_profile_calls_git_service_local(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
        mock_profile: MagicMock,
        mock_profile_manager: MagicMock,
    ) -> None:
        """Applying a profile calls ProfileManager.switch_profile with scope=local."""
        repo = repository_manager.add_repository(mock_git_repo, mock_profile.id)

        repository_manager.apply_profile(repo.id)

        mock_profile_manager.switch_profile.assert_called_once_with(
            mock_profile.id,
            scope="local",
            repo_path=mock_git_repo,
        )

    def test_apply_profile_no_assignment_raises_error(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
    ) -> None:
        """Applying to a repository without an assigned profile raises error."""
        repo = repository_manager.add_repository(mock_git_repo)
        assert repo.assigned_profile_id is None

        with pytest.raises(RepositoryError, match="no profile assigned"):
            repository_manager.apply_profile(repo.id)


class TestValidateRepository:
    """Tests for RepositoryManager.validate_repository()."""

    def test_validate_repository_true_for_git_repo(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
    ) -> None:
        """validate_repository returns True for a valid Git repository."""
        result = repository_manager.validate_repository(mock_git_repo)
        assert result is True

    def test_validate_repository_false_for_non_git_path(
        self,
        repository_manager: RepositoryManager,
        temp_dir: Path,
    ) -> None:
        """validate_repository returns False for a non-Git directory."""
        non_git_path = temp_dir / "not-a-repo"
        non_git_path.mkdir(parents=True, exist_ok=True)

        result = repository_manager.validate_repository(non_git_path)
        assert result is False

    def test_validate_repository_false_for_nonexistent(
        self,
        repository_manager: RepositoryManager,
        temp_dir: Path,
    ) -> None:
        """validate_repository returns False for a non-existent path."""
        result = repository_manager.validate_repository(temp_dir / "nonexistent")
        assert result is False


class TestPersistence:
    """Tests for repository persistence to/from JSON."""

    def test_repositories_persisted_to_json(
        self,
        repository_manager: RepositoryManager,
        mock_git_repo: Path,
        mock_profile: MagicMock,
        temp_dir: Path,
    ) -> None:
        """Adding a repository persists it to the JSON file."""
        repo = repository_manager.add_repository(mock_git_repo, mock_profile.id)

        # Read the JSON file
        repos_path = temp_dir / "repositories.json"
        assert repos_path.exists()

        data = json.loads(repos_path.read_text())
        assert "version" in data
        assert data["version"] == 1
        assert "repositories" in data
        assert len(data["repositories"]) == 1

        saved = data["repositories"][0]
        assert saved["id"] == str(repo.id)
        assert saved["path"] == str(mock_git_repo)
        assert saved["name"] == mock_git_repo.name
        assert saved["assigned_profile_id"] == str(mock_profile.id)
        assert saved["use_local_config"] is True

    def test_repositories_loaded_from_json(
        self,
        temp_dir: Path,
        mock_git_repo: Path,
        mock_profile: MagicMock,
        mock_profile_manager: MagicMock,
        mock_git_service: MagicMock,
    ) -> None:
        """RepositoryManager loads existing repositories from JSON on init."""
        # Pre-populate JSON file
        repo_id = uuid4()
        repos_path = temp_dir / "repositories.json"
        repos_data = {
            "version": 1,
            "repositories": [
                {
                    "id": str(repo_id),
                    "path": str(mock_git_repo),
                    "name": "test-repo",
                    "assigned_profile_id": str(mock_profile.id),
                    "use_local_config": True,
                }
            ],
        }
        repos_path.write_text(json.dumps(repos_data))

        # Create new manager (should load from file)
        manager = RepositoryManager(
            profile_manager=mock_profile_manager,
            git_service=mock_git_service,
            repositories_path=repos_path,
        )

        repos = manager.list_repositories()
        assert len(repos) == 1
        assert repos[0].id == repo_id
        assert repos[0].path == mock_git_repo
        assert repos[0].assigned_profile_id == mock_profile.id


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_profile() -> MagicMock:
    """Create a mock Profile for testing."""
    profile = MagicMock()
    profile.id = uuid4()
    profile.name = "Test Profile"
    profile.git_username = "testuser"
    profile.git_email = "test@example.com"
    return profile


@pytest.fixture
def mock_profile_manager(mock_profile: MagicMock) -> MagicMock:
    """Create a mock ProfileManager."""
    manager = MagicMock()
    manager.get_profile.return_value = mock_profile
    manager.switch_profile.return_value = None
    return manager


@pytest.fixture
def repository_manager(
    temp_dir: Path,
    mock_profile_manager: MagicMock,
    mock_git_service: MagicMock,
) -> RepositoryManager:
    """Create a RepositoryManager with mocked dependencies."""
    repos_path = temp_dir / "repositories.json"

    return RepositoryManager(
        profile_manager=mock_profile_manager,
        git_service=mock_git_service,
        repositories_path=repos_path,
    )
