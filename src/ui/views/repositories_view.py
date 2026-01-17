"""Repositories view for Git-Switch.

Displays registered repositories with profile assignments and
provides actions for adding, removing, and assigning profiles.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import dearpygui.dearpygui as dpg

from src.ui.dialogs.confirm_dialog import show_confirm_dialog
from src.ui.theme import (
    COLORS,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
    TAGS,
)

if TYPE_CHECKING:
    from uuid import UUID

    from src.models.profile import Profile
    from src.models.repository import Repository
    from src.services.container import ServiceContainer

logger = logging.getLogger(__name__)

# Internal tags for view elements
_REPOS_LIST = "repos_list_container"
_EMPTY_STATE = "repos_empty_state"
_FILE_DIALOG = "repos_folder_dialog"
_REPO_ITEM_PREFIX = "repo_item_"

# Container reference for service access
_container: ServiceContainer | None = None

# Repository row dimensions
_ROW_HEIGHT = 80


def create_repositories_view(container: ServiceContainer) -> int:
    """Create the repositories view content.

    Args:
        container: Service container for accessing managers.

    Returns:
        View group tag ID.
    """
    global _container
    _container = container

    logger.debug("Creating repositories view")

    # Clean up existing view if present
    if dpg.does_item_exist(TAGS["view_repos"]):
        dpg.delete_item(TAGS["view_repos"])

    with dpg.group(tag=TAGS["view_repos"], show=False) as view:
        # Section header
        dpg.add_text(
            "REPOSITORIES",
            color=COLORS["accent_cyan"],
        )
        dpg.add_separator()
        dpg.add_spacer(height=PADDING_SMALL)

        # Action bar with Add Repository button
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="+ Add Repository",
                callback=_on_add_repository,
                width=140,
            )

            dpg.add_spacer(width=PADDING_MEDIUM)

            dpg.add_button(
                label="Refresh",
                callback=lambda: refresh_repositories(),
                width=80,
            )

        dpg.add_spacer(height=PADDING_MEDIUM)

        # Empty state message (hidden when repositories exist)
        with dpg.group(tag=_EMPTY_STATE, show=True):
            dpg.add_spacer(height=PADDING_LARGE * 2)
            dpg.add_text(
                "No repositories registered yet.",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "Click '+ Add Repository' to register a Git repository.",
                color=COLORS["text_disabled"],
            )
            dpg.add_spacer(height=PADDING_SMALL)
            dpg.add_text(
                "Registered repositories can have specific profiles assigned",
                color=COLORS["text_disabled"],
            )
            dpg.add_text(
                "for local Git configuration.",
                color=COLORS["text_disabled"],
            )

        # Scrollable repository list container
        with dpg.child_window(
            tag=_REPOS_LIST,
            height=-1,
            border=False,
            show=False,
        ):
            pass  # Repositories will be added dynamically

    # Create folder dialog
    _create_folder_dialog()

    # Load initial repositories
    refresh_repositories()

    logger.debug("Repositories view created")
    return view


def refresh_repositories() -> None:
    """Reload and display the repository list."""
    global _container

    if _container is None:
        logger.warning("Cannot refresh repositories: container not set")
        return

    try:
        repositories = _container.repository_manager.list_repositories()
        profiles = _container.profile_manager.list_profiles()
        _display_repositories(repositories, profiles)
    except Exception:
        logger.exception("Failed to load repositories")
        _display_repositories([], [])


def _display_repositories(
    repositories: list[Repository],
    profiles: list[Profile],
) -> None:
    """Display repositories in the list container.

    Args:
        repositories: List of repositories to display.
        profiles: List of available profiles for assignment.
    """
    has_repos = len(repositories) > 0

    # Toggle empty state vs repository list
    if dpg.does_item_exist(_EMPTY_STATE):
        dpg.configure_item(_EMPTY_STATE, show=not has_repos)

    if dpg.does_item_exist(_REPOS_LIST):
        dpg.configure_item(_REPOS_LIST, show=has_repos)

        # Clear existing repository items
        children = dpg.get_item_children(_REPOS_LIST, 1)
        if children:
            for child in children:
                dpg.delete_item(child)

        # Create repository items
        for repo in repositories:
            _create_repository_item(repo, profiles, _REPOS_LIST)
            dpg.add_spacer(height=PADDING_SMALL, parent=_REPOS_LIST)


def _create_repository_item(
    repo: Repository,
    profiles: list[Profile],
    parent: int | str,
) -> int:
    """Create a repository list item.

    Args:
        repo: Repository to display.
        profiles: Available profiles for assignment dropdown.
        parent: Parent container tag.

    Returns:
        Item container widget tag ID.
    """
    item_tag = f"{_REPO_ITEM_PREFIX}{repo.id}"

    # Clean up existing item if present
    if dpg.does_item_exist(item_tag):
        dpg.delete_item(item_tag)

    with dpg.child_window(  # noqa: SIM117
        tag=item_tag,
        height=_ROW_HEIGHT,
        border=True,
        parent=parent,
    ) as item:
        with dpg.group(horizontal=True):
            # Left side: Repository info
            with dpg.group():
                # Repository name
                dpg.add_text(
                    repo.name,
                    color=COLORS["text_primary"],
                )

                # Repository path
                dpg.add_text(
                    str(repo.path),
                    color=COLORS["text_secondary"],
                )

                # Assigned profile status
                with dpg.group(horizontal=True):
                    dpg.add_text(
                        "Profile:",
                        color=COLORS["text_secondary"],
                    )

                    # Find assigned profile name
                    assigned_name = "None"
                    if repo.assigned_profile_id:
                        for profile in profiles:
                            if profile.id == repo.assigned_profile_id:
                                assigned_name = profile.name
                                break

                    profile_color = (
                        COLORS["accent_cyan"]
                        if assigned_name != "None"
                        else COLORS["text_disabled"]
                    )
                    dpg.add_text(
                        assigned_name,
                        color=profile_color,
                    )

            # Flexible spacer
            dpg.add_spacer(width=100)

            # Right side: Actions
            with dpg.group():
                # Profile assignment dropdown
                profile_items = ["None"] + [p.name for p in profiles]
                current_index = 0
                if repo.assigned_profile_id:
                    for i, profile in enumerate(profiles):
                        if profile.id == repo.assigned_profile_id:
                            current_index = i + 1
                            break

                combo_tag = f"repo_combo_{repo.id}"
                dpg.add_combo(
                    tag=combo_tag,
                    items=profile_items,
                    default_value=profile_items[current_index],
                    width=150,
                    callback=lambda _s, a, u: _on_assign_profile(u[0], u[1], a),
                    user_data=(repo, profiles),
                )

                dpg.add_spacer(height=2)

                # Remove button
                dpg.add_button(
                    label="Remove",
                    width=80,
                    callback=lambda _s, _a, u: _on_remove_repository(u),
                    user_data=repo,
                )

    return item


def _create_folder_dialog() -> None:
    """Create the folder browser dialog."""
    if dpg.does_item_exist(_FILE_DIALOG):
        dpg.delete_item(_FILE_DIALOG)

    with dpg.file_dialog(
        tag=_FILE_DIALOG,
        directory_selector=True,
        show=False,
        callback=_on_folder_selected,
        cancel_callback=lambda: None,
        width=500,
        height=400,
        default_path=str(Path.home()),
    ):
        pass


def _on_add_repository() -> None:
    """Handle Add Repository button click."""
    logger.debug("Add Repository button clicked")

    if dpg.does_item_exist(_FILE_DIALOG):
        dpg.show_item(_FILE_DIALOG)


def _on_folder_selected(_sender: int, app_data: dict[str, Any]) -> None:
    """Handle folder selection from browser.

    Args:
        _sender: Sender ID (unused).
        app_data: Contains 'file_path_name' key with selected path.
    """
    global _container

    if not app_data or "file_path_name" not in app_data:
        return

    folder_path = app_data["file_path_name"]
    logger.debug(f"Folder selected: {folder_path}")

    if _container is None:
        logger.error("Cannot add repository: container not set")
        return

    try:
        path = Path(folder_path)

        # Check if it's a valid Git repository
        if not (path / ".git").is_dir():
            logger.warning(f"Not a Git repository: {folder_path}")
            # Could show an error dialog here
            return

        # Register the repository
        _container.repository_manager.register_repository(path)
        logger.info(f"Registered repository: {folder_path}")
        refresh_repositories()

    except Exception:
        logger.exception("Failed to register repository")


def _on_remove_repository(repo: Repository) -> None:
    """Handle repository remove button click.

    Args:
        repo: Repository to remove.
    """
    logger.debug(f"Remove repository requested: {repo.name}")

    show_confirm_dialog(
        title="Remove Repository",
        message=f"Remove '{repo.name}' from Git-Switch?\n\n"
                "This only removes the registration. The repository "
                "files will not be affected.",
        on_confirm=lambda: _handle_repository_remove(repo),
        on_cancel=None,
        confirm_label="Remove",
        cancel_label="Cancel",
    )


def _handle_repository_remove(repo: Repository) -> None:
    """Handle confirmed repository removal.

    Args:
        repo: Repository to remove.
    """
    global _container

    if _container is None:
        logger.error("Cannot remove repository: container not set")
        return

    try:
        _container.repository_manager.unregister_repository(repo.id)
        logger.info(f"Removed repository: {repo.name}")
        refresh_repositories()

    except Exception:
        logger.exception("Failed to remove repository")


def _on_assign_profile(
    repo: Repository,
    profiles: list[Profile],
    selected_name: str,
) -> None:
    """Handle profile assignment change.

    Args:
        repo: Repository to update.
        profiles: Available profiles list.
        selected_name: Selected profile name or "None".
    """
    global _container

    if _container is None:
        logger.error("Cannot assign profile: container not set")
        return

    logger.debug(f"Assign profile '{selected_name}' to {repo.name}")

    try:
        # Find profile ID by name
        profile_id: UUID | None = None
        if selected_name != "None":
            for profile in profiles:
                if profile.name == selected_name:
                    profile_id = profile.id
                    break

        # Update repository assignment
        _container.repository_manager.assign_profile(repo.id, profile_id)
        logger.info(f"Assigned profile '{selected_name}' to {repo.name}")

        # Refresh to update display
        refresh_repositories()

    except Exception:
        logger.exception("Failed to assign profile")


__all__ = [
    "create_repositories_view",
    "refresh_repositories",
]
