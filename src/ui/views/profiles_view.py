"""Profiles view for Git-Switch.

Displays a list of configured profiles with profile cards and
provides actions for switching, editing, and deleting profiles.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import dearpygui.dearpygui as dpg

from src.ui.components.profile_card import create_profile_card
from src.ui.dialogs.confirm_dialog import show_confirm_dialog
from src.ui.dialogs.profile_dialog import show_profile_dialog
from src.ui.theme import (
    COLORS,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
    TAGS,
)

if TYPE_CHECKING:
    from typing import Any

    from src.models.profile import Profile
    from src.services.container import ServiceContainer

logger = logging.getLogger(__name__)

# Internal tags for view elements
_PROFILES_LIST = "profiles_list_container"
_EMPTY_STATE = "profiles_empty_state"

# Container reference for service access
_container: ServiceContainer | None = None


def create_profiles_view(container: ServiceContainer) -> int:
    """Create the profiles view content.

    Args:
        container: Service container for accessing managers.

    Returns:
        View group tag ID.
    """
    global _container
    _container = container

    logger.debug("Creating profiles view")

    # Clean up existing view if present
    if dpg.does_item_exist(TAGS["view_profiles"]):
        dpg.delete_item(TAGS["view_profiles"])

    with dpg.group(tag=TAGS["view_profiles"], show=True) as view:
        # Section header
        dpg.add_text(
            "PROFILES",
            color=COLORS["accent_cyan"],
        )
        dpg.add_separator()
        dpg.add_spacer(height=PADDING_SMALL)

        # Action bar with New Profile button
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="+ New Profile",
                callback=_on_new_profile,
                width=120,
            )

            dpg.add_spacer(width=PADDING_MEDIUM)

            dpg.add_button(
                label="Refresh",
                callback=lambda: refresh_profiles(),
                width=80,
            )

        dpg.add_spacer(height=PADDING_MEDIUM)

        # Empty state message (hidden when profiles exist)
        with dpg.group(tag=_EMPTY_STATE, show=True):
            dpg.add_spacer(height=PADDING_LARGE * 2)
            dpg.add_text(
                "No profiles configured yet.",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "Click '+ New Profile' to create your first Git profile.",
                color=COLORS["text_disabled"],
            )

        # Scrollable profile list container
        with dpg.child_window(
            tag=_PROFILES_LIST,
            height=-1,
            border=False,
            show=False,
        ):
            pass  # Profiles will be added dynamically

    # Load initial profiles
    refresh_profiles()

    logger.debug("Profiles view created")
    return view


def refresh_profiles() -> None:
    """Reload and display the profile list."""
    global _container

    if _container is None:
        logger.warning("Cannot refresh profiles: container not set")
        return

    try:
        profiles = _container.profile_manager.list_profiles()
        _display_profiles(profiles)
    except Exception:
        logger.exception("Failed to load profiles")
        _display_profiles([])


def _display_profiles(profiles: list[Profile]) -> None:
    """Display profiles in the list container.

    Args:
        profiles: List of profiles to display.
    """
    # Toggle empty state vs profile list
    has_profiles = len(profiles) > 0

    if dpg.does_item_exist(_EMPTY_STATE):
        dpg.configure_item(_EMPTY_STATE, show=not has_profiles)

    if dpg.does_item_exist(_PROFILES_LIST):
        dpg.configure_item(_PROFILES_LIST, show=has_profiles)

        # Clear existing profile cards
        children = dpg.get_item_children(_PROFILES_LIST, 1)
        if children:
            for child in children:
                dpg.delete_item(child)

        # Create profile cards
        for profile in profiles:
            create_profile_card(
                profile=profile,
                is_active=profile.is_active,
                on_switch=_on_switch_profile,
                on_edit=_on_edit_profile,
                on_delete=_on_delete_profile,
                parent=_PROFILES_LIST,  # type: ignore[arg-type]
            )
            # Add spacing between cards
            dpg.add_spacer(height=PADDING_SMALL, parent=_PROFILES_LIST)


def _on_new_profile() -> None:
    """Handle New Profile button click."""
    logger.debug("New Profile button clicked")

    show_profile_dialog(
        mode="create",
        profile=None,
        on_save=_handle_profile_save,
        on_cancel=None,
    )


def _on_switch_profile(profile: Profile) -> None:
    """Handle profile switch button click.

    Args:
        profile: Profile to switch to.
    """
    global _container

    if _container is None:
        logger.error("Cannot switch profile: container not set")
        return

    logger.debug(f"Switch to profile: {profile.name}")

    # Check if confirmation is needed
    try:
        # For now, switch directly - confirmation setting check can be added later
        _container.profile_manager.switch_profile(profile.id)
        refresh_profiles()

        # Update main window active profile display
        from src.ui.main_window import update_active_profile

        update_active_profile(
            name=profile.name,
            email=profile.git_email,
            organization=profile.organization,
            is_ready=True,
        )

        logger.info(f"Switched to profile: {profile.name}")

    except Exception:
        logger.exception("Failed to switch profile")


def _on_edit_profile(profile: Profile) -> None:
    """Handle profile edit button click.

    Args:
        profile: Profile to edit.
    """
    logger.debug(f"Edit profile: {profile.name}")

    show_profile_dialog(
        mode="edit",
        profile=profile,
        on_save=lambda data: _handle_profile_update(profile, data),
        on_cancel=None,
    )


def _on_delete_profile(profile: Profile) -> None:
    """Handle profile delete button click.

    Args:
        profile: Profile to delete.
    """
    logger.debug(f"Delete profile requested: {profile.name}")

    show_confirm_dialog(
        title="Delete Profile",
        message=f"Are you sure you want to delete the profile '{profile.name}'? "
        "This action cannot be undone.",
        on_confirm=lambda: _handle_profile_delete(profile),
        on_cancel=None,
        confirm_label="Delete",
        cancel_label="Cancel",
    )


def _handle_profile_save(data: dict[str, Any]) -> None:
    """Handle new profile save.

    Args:
        data: Profile data dictionary from dialog.
    """
    global _container

    if _container is None:
        logger.error("Cannot save profile: container not set")
        return

    try:
        # Extract SSH key data
        ssh_data = data.get("ssh", {})
        gpg_data = data.get("gpg", {})

        # Read SSH private key from file
        ssh_private_key = None
        ssh_private_path = ssh_data.get("private_key_path", "")
        if ssh_private_path:
            from pathlib import Path

            key_path = Path(ssh_private_path)
            if key_path.is_file():
                ssh_private_key = key_path.read_bytes()

        # Get public key
        ssh_public_key = None
        public_key_str = ssh_data.get("public_key", "")
        if public_key_str:
            ssh_public_key = public_key_str.encode("utf-8")

        # Create the profile
        _container.profile_manager.create_profile(
            name=data["name"],
            git_username=data["git_username"],
            git_email=data["git_email"],
            ssh_private_key=ssh_private_key,  # type: ignore[arg-type]
            ssh_public_key=ssh_public_key,  # type: ignore[arg-type]
            ssh_passphrase=ssh_data.get("passphrase"),
            gpg_enabled=gpg_data.get("enabled", False),
            gpg_key_id=gpg_data.get("key_id"),
        )

        logger.info(f"Created new profile: {data['name']}")
        refresh_profiles()

    except Exception:
        logger.exception("Failed to create profile")


def _handle_profile_update(profile: Profile, data: dict[str, Any]) -> None:
    """Handle profile update.

    Args:
        profile: Existing profile being updated.
        data: Updated profile data dictionary.
    """
    global _container

    if _container is None:
        logger.error("Cannot update profile: container not set")
        return

    try:
        # Extract update data
        ssh_data = data.get("ssh", {})
        gpg_data = data.get("gpg", {})

        # Read SSH private key from file if path changed
        ssh_private_key = None
        ssh_private_path = ssh_data.get("private_key_path", "")
        if ssh_private_path:
            from pathlib import Path

            key_path = Path(ssh_private_path)
            if key_path.is_file():
                ssh_private_key = key_path.read_bytes()

        # Get public key
        ssh_public_key = None
        public_key_str = ssh_data.get("public_key", "")
        if public_key_str:
            ssh_public_key = public_key_str.encode("utf-8")

        # Update the profile
        _container.profile_manager.update_profile(
            profile_id=profile.id,
            name=data["name"],
            git_username=data["git_username"],
            git_email=data["git_email"],
            ssh_private_key=ssh_private_key,
            ssh_public_key=ssh_public_key,
            ssh_passphrase=ssh_data.get("passphrase"),
            gpg_enabled=gpg_data.get("enabled", False),
            gpg_key_id=gpg_data.get("key_id"),
        )

        logger.info(f"Updated profile: {data['name']}")
        refresh_profiles()

    except Exception:
        logger.exception("Failed to update profile")


def _handle_profile_delete(profile: Profile) -> None:
    """Handle confirmed profile deletion.

    Args:
        profile: Profile to delete.
    """
    global _container

    if _container is None:
        logger.error("Cannot delete profile: container not set")
        return

    try:
        _container.profile_manager.delete_profile(profile.id)
        logger.info(f"Deleted profile: {profile.name}")
        refresh_profiles()

        # If deleted profile was active, update header
        if profile.is_active:
            from src.ui.main_window import update_active_profile

            update_active_profile(
                name=None,
                email=None,
                organization=None,
                is_ready=True,
            )

    except Exception:
        logger.exception("Failed to delete profile")


__all__ = [
    "create_profiles_view",
    "refresh_profiles",
]
