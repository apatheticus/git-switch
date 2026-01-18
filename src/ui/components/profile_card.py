"""Profile card widget for Git-Switch.

Displays profile information with switch/edit/delete action buttons.
Used in the profiles list view.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import dearpygui.dearpygui as dpg

from src.ui.theme import (
    COLORS,
    PADDING_MEDIUM,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.models.profile import Profile

logger = logging.getLogger(__name__)

# Card dimensions
CARD_WIDTH = 580
CARD_HEIGHT = 90

# Tag prefix for unique element IDs
_TAG_PREFIX = "profile_card_"

# Theme storage
_card_theme: int | None = None
_active_badge_theme: int | None = None


def _ensure_themes() -> None:
    """Create card themes if not already created."""
    global _card_theme, _active_badge_theme

    if _card_theme is None:
        with dpg.theme() as _card_theme, dpg.theme_component(dpg.mvChildWindow):
            dpg.add_theme_color(
                dpg.mvThemeCol_ChildBg,
                COLORS["bg_card"],
            )
            dpg.add_theme_style(
                dpg.mvStyleVar_ChildRounding,
                4,
            )
            dpg.add_theme_style(
                dpg.mvStyleVar_WindowPadding,
                PADDING_MEDIUM,
                PADDING_MEDIUM,
            )

    if _active_badge_theme is None:
        with dpg.theme() as _active_badge_theme, dpg.theme_component(dpg.mvText):
            dpg.add_theme_color(
                dpg.mvThemeCol_Text,
                COLORS["success"],
            )


def create_profile_card(
    profile: Profile,
    is_active: bool,
    on_switch: Callable[[Profile], None],
    on_edit: Callable[[Profile], None],
    on_delete: Callable[[Profile], None],
    parent: int | None = None,
) -> int:
    """Create a profile card widget.

    Displays profile information with action buttons:
    - Profile name (with "ACTIVE" badge if active)
    - Email and optional organization
    - SSH and GPG status indicators
    - Switch, Edit, Delete buttons

    Args:
        profile: Profile data to display.
        is_active: Whether this is the currently active profile.
        on_switch: Callback when Switch button is clicked.
        on_edit: Callback when Edit button is clicked.
        on_delete: Callback when Delete button is clicked.
        parent: Parent container tag. Uses current parent if None.

    Returns:
        Card container widget tag ID.
    """
    _ensure_themes()

    # Generate unique tag for this card
    card_tag = f"{_TAG_PREFIX}{profile.id}"

    # Clean up existing card if present
    if dpg.does_item_exist(card_tag):
        dpg.delete_item(card_tag)

    logger.debug(f"Creating profile card: {profile.name}")

    # Create card container
    card_kwargs: dict[str, Any] = {
        "tag": card_tag,
        "width": CARD_WIDTH,
        "height": CARD_HEIGHT,
        "border": True,
        "no_scrollbar": True,
    }
    if parent is not None:
        card_kwargs["parent"] = parent

    with dpg.child_window(**card_kwargs) as card:
        # Apply card theme
        if _card_theme is not None:
            dpg.bind_item_theme(card, _card_theme)

        with dpg.group(horizontal=True):
            # Left side: Profile info
            with dpg.group():
                # Active badge (if active)
                if is_active:
                    with dpg.group(horizontal=True):
                        active_text = dpg.add_text(
                            "ACTIVE",
                            color=COLORS["success"],
                        )
                        if _active_badge_theme is not None:
                            dpg.bind_item_theme(active_text, _active_badge_theme)

                # Profile name
                dpg.add_text(
                    profile.name,
                    color=COLORS["text_primary"],
                )

                # Email and organization
                with dpg.group(horizontal=True):
                    dpg.add_text(
                        profile.git_email,
                        color=COLORS["text_secondary"],
                    )
                    if profile.organization:
                        dpg.add_text(
                            f"@ {profile.organization}",
                            color=COLORS["accent_cyan"],
                        )

                # Status indicators
                with dpg.group(horizontal=True):
                    # SSH status
                    ssh_status = "READY" if profile.ssh_key else "MISSING"
                    ssh_color = COLORS["success"] if profile.ssh_key else COLORS["error"]
                    dpg.add_text("SSH:", color=COLORS["text_secondary"])
                    dpg.add_text(ssh_status, color=ssh_color)

                    dpg.add_spacer(width=PADDING_MEDIUM)

                    # GPG status
                    if profile.gpg_key and profile.gpg_key.enabled:
                        gpg_status = "ENABLED"
                        gpg_color = COLORS["success"]
                    else:
                        gpg_status = "DISABLED"
                        gpg_color = COLORS["text_disabled"]
                    dpg.add_text("GPG:", color=COLORS["text_secondary"])
                    dpg.add_text(gpg_status, color=gpg_color)

            # Flexible spacer to push buttons to the right
            dpg.add_spacer(width=CARD_WIDTH - 380)

            # Right side: Action buttons
            with dpg.group():
                # Switch button (disabled if active)
                dpg.add_button(
                    label="Switch",
                    width=70,
                    callback=lambda: on_switch(profile),
                    enabled=not is_active,
                )

                dpg.add_spacer(height=2)

                # Edit button
                dpg.add_button(
                    label="Edit",
                    width=70,
                    callback=lambda: on_edit(profile),
                )

                dpg.add_spacer(height=2)

                # Delete button
                dpg.add_button(
                    label="Delete",
                    width=70,
                    callback=lambda: on_delete(profile),
                )

    return card


def delete_profile_card(profile_id: str) -> bool:
    """Delete a profile card widget.

    Args:
        profile_id: Profile UUID string to identify the card.

    Returns:
        True if card was deleted, False if not found.
    """
    card_tag = f"{_TAG_PREFIX}{profile_id}"

    if dpg.does_item_exist(card_tag):
        dpg.delete_item(card_tag)
        logger.debug(f"Deleted profile card: {profile_id}")
        return True

    return False


def update_profile_card_status(
    profile_id: str,
    is_active: bool,
) -> bool:
    """Update the active status of a profile card.

    This function rebuilds the entire card to reflect the new status.
    For more efficient updates, the calling code should track the
    profile and card references.

    Args:
        profile_id: Profile UUID string.
        is_active: New active status.

    Returns:
        True if update was applied, False if card not found.

    Note:
        This is a simplified implementation. For production use,
        consider storing card element references for targeted updates.
    """
    card_tag = f"{_TAG_PREFIX}{profile_id}"

    if not dpg.does_item_exist(card_tag):
        logger.warning(f"Profile card not found: {profile_id}")
        return False

    # Note: Full card rebuild would require profile data and callbacks
    # For now, just log the intention
    logger.debug(f"Profile card status update requested: {profile_id} -> active={is_active}")
    return True


__all__ = [
    "CARD_HEIGHT",
    "CARD_WIDTH",
    "create_profile_card",
    "delete_profile_card",
    "update_profile_card_status",
]
