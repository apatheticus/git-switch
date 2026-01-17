"""Status bar component for Git-Switch.

Footer status indicators showing SSH status, GPG status, active profile,
and current scope. Provides both creation and update functions for
flexible integration with the main window.
"""

from __future__ import annotations

import logging
from typing import Final

import dearpygui.dearpygui as dpg

from src.ui.theme import (
    COLORS,
    FOOTER_HEIGHT,
    PADDING_LARGE,
)

logger = logging.getLogger(__name__)

# Status bar element tags
STATUS_BAR_TAG: Final[str] = "status_bar_container"
SSH_STATUS_TAG: Final[str] = "status_bar_ssh"
GPG_STATUS_TAG: Final[str] = "status_bar_gpg"
ACTIVE_PROFILE_TAG: Final[str] = "status_bar_active_profile"
SCOPE_TAG: Final[str] = "status_bar_scope"

# Default status values
DEFAULT_SSH_STATUS: Final[str] = "READY"
DEFAULT_GPG_STATUS: Final[str] = "DISABLED"
DEFAULT_SCOPE: Final[str] = "GLOBAL"


def create_status_bar(parent: int | None = None) -> int:
    """Create a status bar with SSH, GPG, active profile, and scope indicators.

    The status bar displays:
    - SSH agent status (READY/ERROR)
    - GPG status (READY/ERROR/DISABLED)
    - Active profile name
    - Current scope (GLOBAL/LOCAL)

    Args:
        parent: Parent container tag. Uses current parent if None.

    Returns:
        Status bar container widget tag ID.
    """
    # Clean up existing status bar if present
    if dpg.does_item_exist(STATUS_BAR_TAG):
        dpg.delete_item(STATUS_BAR_TAG)

    logger.debug("Creating status bar")

    bar_kwargs: dict = {
        "tag": STATUS_BAR_TAG,
        "height": FOOTER_HEIGHT,
        "no_scrollbar": True,
        "border": False,
    }
    if parent is not None:
        bar_kwargs["parent"] = parent

    with dpg.child_window(**bar_kwargs) as status_bar:
        with dpg.group(horizontal=True):
            # SSH status
            dpg.add_text("SSH:", color=COLORS["text_secondary"])
            dpg.add_text(
                DEFAULT_SSH_STATUS,
                tag=SSH_STATUS_TAG,
                color=COLORS["success"],
            )

            dpg.add_spacer(width=PADDING_LARGE)

            # GPG status
            dpg.add_text("GPG:", color=COLORS["text_secondary"])
            dpg.add_text(
                DEFAULT_GPG_STATUS,
                tag=GPG_STATUS_TAG,
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(width=PADDING_LARGE)

            # Active profile
            dpg.add_text("Profile:", color=COLORS["text_secondary"])
            dpg.add_text(
                "None",
                tag=ACTIVE_PROFILE_TAG,
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(width=PADDING_LARGE)

            # Scope indicator
            dpg.add_text("Scope:", color=COLORS["text_secondary"])
            dpg.add_text(
                DEFAULT_SCOPE,
                tag=SCOPE_TAG,
                color=COLORS["accent_cyan"],
            )

    return status_bar


def update_ssh_status(status: str) -> None:
    """Update the SSH status indicator.

    Args:
        status: Status text (e.g., "READY", "ERROR", "CONNECTING").
    """
    if not dpg.does_item_exist(SSH_STATUS_TAG):
        logger.warning("SSH status element not found")
        return

    try:
        dpg.set_value(SSH_STATUS_TAG, status)

        # Determine color based on status
        status_upper = status.upper()
        if status_upper == "READY":
            color = COLORS["success"]
        elif status_upper in ("ERROR", "FAILED"):
            color = COLORS["error"]
        elif status_upper == "CONNECTING":
            color = COLORS["warning"]
        else:
            color = COLORS["text_secondary"]

        dpg.configure_item(SSH_STATUS_TAG, color=color)
        logger.debug(f"SSH status updated: {status}")

    except Exception as e:
        logger.warning(f"Failed to update SSH status: {e}")


def update_gpg_status(status: str) -> None:
    """Update the GPG status indicator.

    Args:
        status: Status text (e.g., "READY", "ERROR", "DISABLED").
    """
    if not dpg.does_item_exist(GPG_STATUS_TAG):
        logger.warning("GPG status element not found")
        return

    try:
        dpg.set_value(GPG_STATUS_TAG, status)

        # Determine color based on status
        status_upper = status.upper()
        if status_upper in ("READY", "ENABLED"):
            color = COLORS["success"]
        elif status_upper in ("ERROR", "FAILED"):
            color = COLORS["error"]
        elif status_upper == "DISABLED":
            color = COLORS["text_disabled"]
        else:
            color = COLORS["text_secondary"]

        dpg.configure_item(GPG_STATUS_TAG, color=color)
        logger.debug(f"GPG status updated: {status}")

    except Exception as e:
        logger.warning(f"Failed to update GPG status: {e}")


def update_active_profile(name: str | None) -> None:
    """Update the active profile name display.

    Args:
        name: Profile name or None if no profile is active.
    """
    if not dpg.does_item_exist(ACTIVE_PROFILE_TAG):
        logger.warning("Active profile element not found")
        return

    try:
        if name:
            dpg.set_value(ACTIVE_PROFILE_TAG, name)
            dpg.configure_item(ACTIVE_PROFILE_TAG, color=COLORS["accent_cyan"])
        else:
            dpg.set_value(ACTIVE_PROFILE_TAG, "None")
            dpg.configure_item(ACTIVE_PROFILE_TAG, color=COLORS["text_disabled"])

        logger.debug(f"Active profile updated: {name or 'None'}")

    except Exception as e:
        logger.warning(f"Failed to update active profile: {e}")


def update_scope(scope: str) -> None:
    """Update the scope indicator.

    Args:
        scope: Scope text (e.g., "GLOBAL", "LOCAL").
    """
    if not dpg.does_item_exist(SCOPE_TAG):
        logger.warning("Scope element not found")
        return

    try:
        dpg.set_value(SCOPE_TAG, scope)

        # Determine color based on scope
        scope_upper = scope.upper()
        if scope_upper == "GLOBAL":
            color = COLORS["accent_cyan"]
        elif scope_upper == "LOCAL":
            color = COLORS["warning"]
        else:
            color = COLORS["text_secondary"]

        dpg.configure_item(SCOPE_TAG, color=color)
        logger.debug(f"Scope updated: {scope}")

    except Exception as e:
        logger.warning(f"Failed to update scope: {e}")


def update_all_status(
    ssh_status: str | None = None,
    gpg_status: str | None = None,
    active_profile: str | None = None,
    scope: str | None = None,
) -> None:
    """Update multiple status indicators at once.

    Only updates the indicators for which values are provided.

    Args:
        ssh_status: SSH status text or None to skip update.
        gpg_status: GPG status text or None to skip update.
        active_profile: Profile name or None to skip update.
            Pass empty string "" to show "None".
        scope: Scope text or None to skip update.
    """
    if ssh_status is not None:
        update_ssh_status(ssh_status)

    if gpg_status is not None:
        update_gpg_status(gpg_status)

    if active_profile is not None:
        # Empty string means "no profile", not "skip update"
        update_active_profile(active_profile if active_profile else None)

    if scope is not None:
        update_scope(scope)


__all__ = [
    # Tags for external reference
    "ACTIVE_PROFILE_TAG",
    "GPG_STATUS_TAG",
    "SCOPE_TAG",
    "SSH_STATUS_TAG",
    "STATUS_BAR_TAG",
    # Creation function
    "create_status_bar",
    # Individual update functions
    "update_active_profile",
    "update_all_status",
    "update_gpg_status",
    "update_scope",
    "update_ssh_status",
]
