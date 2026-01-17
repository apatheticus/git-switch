"""Main window layout for Git-Switch.

This module provides the main window construction and navigation
management for the Git-Switch user interface.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import dearpygui.dearpygui as dpg

from src.ui.theme import (
    APP_HEIGHT,
    APP_WIDTH,
    COLORS,
    FOOTER_HEIGHT,
    HEADER_HEIGHT,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
    SIDEBAR_WIDTH,
    TAGS,
    create_active_nav_button_theme,
    create_nav_button_theme,
    create_status_theme,
)

if TYPE_CHECKING:
    from src.services.container import ServiceContainer

logger = logging.getLogger(__name__)

# Navigation button state tracking
_active_view: str = TAGS["view_profiles"]
_nav_button_theme: int | None = None
_nav_button_active_theme: int | None = None
_status_success_theme: int | None = None
_status_warning_theme: int | None = None

# Navigation buttons registry for theme updates
_nav_buttons: dict[str, int] = {}


def create_main_window(container: ServiceContainer) -> int:
    """Create the main application window with all sections.

    Args:
        container: Service container for accessing managers.

    Returns:
        Window tag ID.
    """
    global _nav_button_theme, _nav_button_active_theme
    global _status_success_theme, _status_warning_theme

    logger.debug("Creating main window layout")

    # Create themes for navigation buttons
    _nav_button_theme = create_nav_button_theme()
    _nav_button_active_theme = create_active_nav_button_theme()
    _status_success_theme = create_status_theme("success")
    _status_warning_theme = create_status_theme("warning")

    # Calculate content area height
    content_height = APP_HEIGHT - HEADER_HEIGHT - FOOTER_HEIGHT

    with dpg.window(
        tag=TAGS["win"],
        label="Git-Switch",
        no_title_bar=True,
        no_resize=True,
        no_move=True,
        no_scrollbar=True,
        no_collapse=True,
        width=APP_WIDTH,
        height=APP_HEIGHT,
    ):
        # Header section
        _build_header(container)

        # Separator line
        dpg.add_separator()

        # Main content area (sidebar + content)
        with dpg.group(horizontal=True):
            # Sidebar
            _build_sidebar()

            # Vertical separator
            dpg.add_child_window(
                width=1,
                height=content_height - PADDING_MEDIUM,
                no_scrollbar=True,
            )

            # Content area
            _build_content_area(content_height)

        # Footer section
        dpg.add_separator()
        _build_footer(container)

    # Set initial view
    show_view(TAGS["view_profiles"])

    logger.debug("Main window layout created")
    return dpg.last_item()


def _build_header(container: ServiceContainer) -> None:
    """Build the header section with logo and active profile card.

    Args:
        container: Service container for profile information.
    """
    with dpg.child_window(
        height=HEADER_HEIGHT - PADDING_MEDIUM,
        no_scrollbar=True,
        border=False,
    ):
        with dpg.group(horizontal=True):
            # Left side: Logo
            with dpg.group():
                dpg.add_spacer(height=PADDING_LARGE)
                dpg.add_text(
                    "GIT",
                    color=COLORS["text_primary"],
                )
                dpg.add_same_line(spacing=0)
                dpg.add_text(
                    "-SWITCH",
                    color=COLORS["accent_cyan"],
                )
                dpg.add_text(
                    "Profile Manager",
                    color=COLORS["text_secondary"],
                )

            dpg.add_spacer(width=PADDING_LARGE * 3)

            # Right side: Active profile card
            with dpg.child_window(
                tag=TAGS["active_profile_card"],
                width=400,
                height=HEADER_HEIGHT - PADDING_LARGE * 2,
                border=True,
            ):
                with dpg.group(horizontal=True):
                    # Profile info
                    with dpg.group():
                        dpg.add_text(
                            "ACTIVE PROFILE",
                            color=COLORS["text_secondary"],
                        )
                        dpg.add_text(
                            "No profile active",
                            tag=TAGS["profile_name"],
                            color=COLORS["text_primary"],
                        )
                        with dpg.group(horizontal=True):
                            dpg.add_text(
                                "---",
                                tag=TAGS["profile_email"],
                                color=COLORS["text_secondary"],
                            )
                            dpg.add_text(
                                "",
                                tag=TAGS["profile_org"],
                                color=COLORS["accent_cyan"],
                            )

                    dpg.add_spacer(width=PADDING_LARGE * 2)

                    # Online indicator
                    with dpg.group():
                        dpg.add_spacer(height=PADDING_SMALL)
                        with dpg.group(horizontal=True):
                            dpg.add_text(
                                "O",  # Circle indicator (will be styled)
                                tag=TAGS["online_indicator"],
                                color=COLORS["success"],
                            )
                            dpg.add_text(
                                "READY",
                                color=COLORS["success"],
                            )


def _build_sidebar() -> None:
    """Build the navigation sidebar."""
    global _nav_buttons

    with dpg.child_window(
        width=SIDEBAR_WIDTH,
        border=False,
        no_scrollbar=True,
    ):
        dpg.add_spacer(height=PADDING_SMALL)

        # NAV header
        dpg.add_text(
            "NAV",
            color=COLORS["text_secondary"],
        )

        dpg.add_spacer(height=PADDING_SMALL)

        # Navigation buttons
        nav_items = [
            (TAGS["view_profiles"], "Profiles", "profiles"),
            (TAGS["view_repos"], "Repositories", "repos"),
            (TAGS["view_settings"], "Settings", "settings"),
            (TAGS["view_import"], "Import/Export", "import"),
        ]

        for view_tag, label, key in nav_items:
            btn = dpg.add_button(
                label=f"  {label}",
                width=SIDEBAR_WIDTH - PADDING_MEDIUM,
                height=32,
                callback=lambda s, a, u: show_view(u),
                user_data=view_tag,
            )
            _nav_buttons[view_tag] = btn

            # Apply default nav theme
            if _nav_button_theme is not None:
                dpg.bind_item_theme(btn, _nav_button_theme)

        dpg.add_spacer(height=PADDING_LARGE * 4)

        # Tip text
        dpg.add_text(
            "TIP",
            color=COLORS["text_secondary"],
        )
        dpg.add_text(
            "Use the system tray",
            color=COLORS["text_disabled"],
            wrap=SIDEBAR_WIDTH - PADDING_LARGE,
        )
        dpg.add_text(
            "icon for quick profile",
            color=COLORS["text_disabled"],
            wrap=SIDEBAR_WIDTH - PADDING_LARGE,
        )
        dpg.add_text(
            "switching.",
            color=COLORS["text_disabled"],
            wrap=SIDEBAR_WIDTH - PADDING_LARGE,
        )


def _build_content_area(height: int) -> None:
    """Build the main content area with view placeholders.

    Args:
        height: Available height for content area.
    """
    content_width = APP_WIDTH - SIDEBAR_WIDTH - PADDING_LARGE * 2

    with dpg.child_window(
        tag=TAGS["content_stack"],
        width=content_width,
        height=height - PADDING_MEDIUM,
        border=False,
        no_scrollbar=False,
    ):
        # Profiles view (default view)
        with dpg.group(tag=TAGS["view_profiles"], show=True):
            dpg.add_text(
                "PROFILES",
                color=COLORS["accent_cyan"],
            )
            dpg.add_separator()
            dpg.add_spacer(height=PADDING_LARGE)
            dpg.add_text(
                "Profile management will be implemented in T097.",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "This view will display a list of configured profiles",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "with options to add, edit, delete, and switch profiles.",
                color=COLORS["text_secondary"],
            )

        # Repositories view
        with dpg.group(tag=TAGS["view_repos"], show=False):
            dpg.add_text(
                "REPOSITORIES",
                color=COLORS["accent_cyan"],
            )
            dpg.add_separator()
            dpg.add_spacer(height=PADDING_LARGE)
            dpg.add_text(
                "Repository management will be implemented in T098.",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "This view will display registered repositories",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "with profile assignment options.",
                color=COLORS["text_secondary"],
            )

        # Settings view
        with dpg.group(tag=TAGS["view_settings"], show=False):
            dpg.add_text(
                "SETTINGS",
                color=COLORS["accent_cyan"],
            )
            dpg.add_separator()
            dpg.add_spacer(height=PADDING_LARGE)
            dpg.add_text(
                "Settings management will be implemented in T099.",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "This view will include auto-lock timer,",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "master password change, and application preferences.",
                color=COLORS["text_secondary"],
            )

        # Import/Export view
        with dpg.group(tag=TAGS["view_import"], show=False):
            dpg.add_text(
                "IMPORT / EXPORT",
                color=COLORS["accent_cyan"],
            )
            dpg.add_separator()
            dpg.add_spacer(height=PADDING_LARGE)
            dpg.add_text(
                "Import/Export functionality will be implemented in T100.",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "This view will allow exporting profiles",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "and importing from backup files.",
                color=COLORS["text_secondary"],
            )


def _build_footer(container: ServiceContainer) -> None:
    """Build the footer section with status indicators.

    Args:
        container: Service container for status information.
    """
    with dpg.child_window(
        height=FOOTER_HEIGHT,
        no_scrollbar=True,
        border=False,
    ):
        with dpg.group(horizontal=True):
            # SSH status
            dpg.add_text(
                "SSH:",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "READY",
                tag=TAGS["status_ssh"],
                color=COLORS["success"],
            )

            dpg.add_spacer(width=PADDING_LARGE)

            # GPG status
            dpg.add_text(
                "GPG:",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "READY",
                tag=TAGS["status_gpg"],
                color=COLORS["success"],
            )

            dpg.add_spacer(width=PADDING_LARGE)

            # Scope indicator
            dpg.add_text(
                "Scope:",
                color=COLORS["text_secondary"],
            )
            dpg.add_text(
                "GLOBAL",
                tag=TAGS["status_scope"],
                color=COLORS["accent_cyan"],
            )

            # Flexible spacer to push lock button to the right
            dpg.add_spacer(width=APP_WIDTH - 450)

            # Lock button
            dpg.add_button(
                label="Lock",
                width=80,
                callback=_on_lock_clicked,
            )


def _on_lock_clicked() -> None:
    """Handle lock button click."""
    logger.debug("Lock button clicked")
    # Note: The actual lock action will be wired in GitSwitchApp
    # For now, this is a placeholder


def show_view(view_tag: str) -> None:
    """Switch to the specified view in the content area.

    Args:
        view_tag: Tag of the view to show.
    """
    global _active_view

    logger.debug(f"Switching to view: {view_tag}")

    # List of all view tags
    view_tags = [
        TAGS["view_profiles"],
        TAGS["view_repos"],
        TAGS["view_settings"],
        TAGS["view_import"],
    ]

    # Hide all views, show only the requested one
    for tag in view_tags:
        try:
            if dpg.does_item_exist(tag):
                dpg.configure_item(tag, show=(tag == view_tag))
        except Exception as e:
            logger.warning(f"Failed to configure view {tag}: {e}")

    # Update navigation button themes
    _update_nav_button_themes(view_tag)

    _active_view = view_tag


def _update_nav_button_themes(active_view_tag: str) -> None:
    """Update navigation button themes based on active view.

    Args:
        active_view_tag: Tag of the currently active view.
    """
    for view_tag, btn_id in _nav_buttons.items():
        try:
            if not dpg.does_item_exist(btn_id):
                continue

            if view_tag == active_view_tag:
                if _nav_button_active_theme is not None:
                    dpg.bind_item_theme(btn_id, _nav_button_active_theme)
            else:
                if _nav_button_theme is not None:
                    dpg.bind_item_theme(btn_id, _nav_button_theme)
        except Exception as e:
            logger.warning(f"Failed to update nav button theme: {e}")


def update_active_profile(
    name: str | None,
    email: str | None,
    organization: str | None = None,
    is_ready: bool = True,
) -> None:
    """Update the active profile display in the header.

    Args:
        name: Profile name or None if no profile.
        email: Profile email or None.
        organization: Optional organization name.
        is_ready: Whether the profile status is ready.
    """
    try:
        if name:
            dpg.set_value(TAGS["profile_name"], name)
            dpg.set_value(TAGS["profile_email"], email or "---")
            if organization:
                dpg.set_value(TAGS["profile_org"], f"@ {organization}")
            else:
                dpg.set_value(TAGS["profile_org"], "")
        else:
            dpg.set_value(TAGS["profile_name"], "No profile active")
            dpg.set_value(TAGS["profile_email"], "---")
            dpg.set_value(TAGS["profile_org"], "")

        # Update status indicator color
        color = COLORS["success"] if is_ready else COLORS["warning"]
        dpg.configure_item(TAGS["online_indicator"], color=color)

    except Exception as e:
        logger.warning(f"Failed to update active profile display: {e}")


def update_status(
    ssh_status: str = "READY",
    gpg_status: str = "READY",
    scope: str = "GLOBAL",
) -> None:
    """Update the footer status indicators.

    Args:
        ssh_status: SSH agent status text.
        gpg_status: GPG status text.
        scope: Current scope (GLOBAL/LOCAL).
    """
    try:
        dpg.set_value(TAGS["status_ssh"], ssh_status)
        dpg.set_value(TAGS["status_gpg"], gpg_status)
        dpg.set_value(TAGS["status_scope"], scope)

        # Update colors based on status
        ssh_color = COLORS["success"] if ssh_status == "READY" else COLORS["warning"]
        gpg_color = COLORS["success"] if gpg_status == "READY" else COLORS["warning"]

        dpg.configure_item(TAGS["status_ssh"], color=ssh_color)
        dpg.configure_item(TAGS["status_gpg"], color=gpg_color)

    except Exception as e:
        logger.warning(f"Failed to update status indicators: {e}")


__all__ = [
    "create_main_window",
    "show_view",
    "update_active_profile",
    "update_status",
]
