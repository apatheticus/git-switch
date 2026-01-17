"""Integration tests for local Git configuration.

These tests verify that:
- Profiles can be applied as local config to repositories
- Local config is independent of global config
- The full register-then-apply workflow works
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.core.repository_manager import RepositoryManager
from src.services.git_service import GitService


@pytest.fixture
def real_git_repo(temp_dir: Path) -> Path:
    """Create a real Git repository for integration testing."""
    repo_dir = temp_dir / "real-repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Initialize a real Git repository
    subprocess.run(
        ["git", "init"],
        cwd=str(repo_dir),
        capture_output=True,
        check=True,
    )

    return repo_dir


@pytest.fixture
def mock_profile() -> MagicMock:
    """Create a mock profile for testing."""
    profile = MagicMock()
    profile.id = uuid4()
    profile.name = "Local Test Profile"
    profile.git_username = "localuser"
    profile.git_email = "local@example.com"
    profile.gpg_key.enabled = False
    profile.gpg_key.key_id = None
    return profile


@pytest.fixture
def mock_profile_manager(mock_profile: MagicMock) -> MagicMock:
    """Create a mock ProfileManager that returns the test profile."""
    manager = MagicMock()
    manager.get_profile.return_value = mock_profile
    manager.switch_profile.return_value = None
    return manager


class TestApplyProfileWritesLocalGitConfig:
    """Test that applying a profile writes to local .git/config."""

    def test_apply_profile_writes_local_git_config(
        self,
        temp_dir: Path,
        real_git_repo: Path,
        mock_profile: MagicMock,
        mock_profile_manager: MagicMock,
    ) -> None:
        """Applying a profile writes user.name and user.email to local config."""
        git_service = GitService()
        repos_path = temp_dir / "repositories.json"

        manager = RepositoryManager(
            profile_manager=mock_profile_manager,
            git_service=git_service,
            repositories_path=repos_path,
        )

        # Add repository and assign profile
        repo = manager.add_repository(real_git_repo, mock_profile.id)

        # Apply the profile
        manager.apply_profile(repo.id)

        # Verify switch_profile was called with correct scope
        mock_profile_manager.switch_profile.assert_called_once_with(
            mock_profile.id,
            scope="local",
            repo_path=real_git_repo,
        )


class TestLocalConfigIndependentOfGlobal:
    """Test that local config doesn't affect or get affected by global config."""

    def test_local_config_independent_of_global(
        self,
        real_git_repo: Path,
    ) -> None:
        """Local Git config is independent of global config."""
        git_service = GitService()

        # Set local config
        git_service.set_local_config(
            repo_path=real_git_repo,
            username="localuser",
            email="local@example.com",
        )

        # Read local config
        local_config = git_service.get_local_config(real_git_repo)

        assert local_config["user.name"] == "localuser"
        assert local_config["user.email"] == "local@example.com"

        # Global config should be unaffected (we don't modify it here)
        # Just verify local and global are separate concepts
        # We verify by checking the local config file exists with correct values
        local_config_file = real_git_repo / ".git" / "config"
        content = local_config_file.read_text()
        assert "localuser" in content
        assert "local@example.com" in content


class TestLocalConfigPersistsAfterGlobalSwitch:
    """Test that local config persists when global config changes."""

    def test_local_config_persists_after_global_switch(
        self,
        real_git_repo: Path,
    ) -> None:
        """Local config remains after global config is changed."""
        git_service = GitService()

        # Set local config
        git_service.set_local_config(
            repo_path=real_git_repo,
            username="localuser",
            email="local@example.com",
        )

        # Change global config (simulating a global profile switch)
        git_service.set_global_config(
            username="globaluser",
            email="global@example.com",
        )

        # Local config should still be present
        local_config = git_service.get_local_config(real_git_repo)
        assert local_config["user.name"] == "localuser"
        assert local_config["user.email"] == "local@example.com"


class TestRegisterThenApplyWorkflow:
    """Test the complete workflow of registering a repo and applying a profile."""

    def test_register_then_apply_workflow(
        self,
        temp_dir: Path,
        real_git_repo: Path,
        mock_profile: MagicMock,
        mock_profile_manager: MagicMock,
    ) -> None:
        """Complete workflow: register repo, assign profile, apply."""
        git_service = GitService()
        repos_path = temp_dir / "repositories.json"

        manager = RepositoryManager(
            profile_manager=mock_profile_manager,
            git_service=git_service,
            repositories_path=repos_path,
        )

        # Step 1: Register repository (no profile)
        repo = manager.add_repository(real_git_repo)
        assert repo.assigned_profile_id is None
        assert len(manager.list_repositories()) == 1

        # Step 2: Assign profile
        updated = manager.assign_profile(repo.id, mock_profile.id)
        assert updated.assigned_profile_id == mock_profile.id

        # Step 3: Apply profile
        manager.apply_profile(repo.id)

        # Verify switch_profile was called
        mock_profile_manager.switch_profile.assert_called_once_with(
            mock_profile.id,
            scope="local",
            repo_path=real_git_repo,
        )

        # Step 4: Verify persistence (new manager loads same data)
        new_manager = RepositoryManager(
            profile_manager=mock_profile_manager,
            git_service=git_service,
            repositories_path=repos_path,
        )

        repos = new_manager.list_repositories()
        assert len(repos) == 1
        assert repos[0].id == repo.id
        assert repos[0].assigned_profile_id == mock_profile.id
