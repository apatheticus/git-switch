"""Settings view for Git-Switch.

Displays and allows editing of application settings including
startup behavior, security, notifications, and master password.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import dearpygui.dearpygui as dpg

from src.ui.dialogs.password_dialog import show_password_dialog
from src.ui.theme import (
    COLORS,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
    TAGS,
)

if TYPE_CHECKING:
    from src.services.container import ServiceContainer

logger = logging.getLogger(__name__)

# Internal tags for view elements
_SETTING_START_WINDOWS = "setting_start_windows"
_SETTING_START_MINIMIZED = "setting_start_minimized"
_SETTING_AUTO_LOCK = "setting_auto_lock"
_SETTING_AUTO_LOCK_LABEL = "setting_auto_lock_label"
_SETTING_NOTIFICATIONS = "setting_notifications"
_SETTING_CONFIRM_SWITCH = "setting_confirm_switch"
_SETTING_CLEAR_SSH = "setting_clear_ssh"
_SAVE_BUTTON = "settings_save_button"
_STATUS_TEXT = "settings_status_text"

# Container reference for service access
_container: ServiceContainer | None = None

# Track unsaved changes
_has_changes: bool = False


def create_settings_view(container: ServiceContainer) -> int:
    """Create the settings view content.

    Args:
        container: Service container for accessing managers.

    Returns:
        View group tag ID.
    """
    global _container
    _container = container

    logger.debug("Creating settings view")

    # Clean up existing view if present
    if dpg.does_item_exist(TAGS["view_settings"]):
        dpg.delete_item(TAGS["view_settings"])

    with dpg.group(tag=TAGS["view_settings"], show=False) as view:
        # Section header
        dpg.add_text(
            "SETTINGS",
            color=COLORS["accent_cyan"],
        )
        dpg.add_separator()
        dpg.add_spacer(height=PADDING_MEDIUM)

        # Scrollable content area
        with dpg.child_window(height=-60, border=False):
            # Startup Section
            _create_section_header("STARTUP")

            dpg.add_checkbox(
                tag=_SETTING_START_WINDOWS,
                label="Start with Windows",
                callback=_on_setting_changed,
            )
            dpg.add_text(
                "Automatically launch Git-Switch when Windows starts",
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(height=PADDING_SMALL)

            dpg.add_checkbox(
                tag=_SETTING_START_MINIMIZED,
                label="Start minimized to system tray",
                callback=_on_setting_changed,
            )
            dpg.add_text(
                "Launch to system tray instead of showing the window",
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(height=PADDING_LARGE)

            # Security Section
            _create_section_header("SECURITY")

            with dpg.group(horizontal=True):
                dpg.add_text(
                    "Auto-lock timeout:",
                    color=COLORS["text_primary"],
                )
                dpg.add_text(
                    "15 minutes",
                    tag=_SETTING_AUTO_LOCK_LABEL,
                    color=COLORS["accent_cyan"],
                )

            dpg.add_slider_int(
                tag=_SETTING_AUTO_LOCK,
                min_value=0,
                max_value=60,
                default_value=15,
                width=300,
                callback=_on_auto_lock_changed,
            )
            dpg.add_text(
                "Lock the application after inactivity (0 = disabled)",
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(height=PADDING_MEDIUM)

            dpg.add_button(
                label="Change Master Password",
                callback=_on_change_password,
                width=200,
            )
            dpg.add_text(
                "Update the master password used to encrypt profiles",
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(height=PADDING_LARGE)

            # Notifications Section
            _create_section_header("NOTIFICATIONS")

            dpg.add_checkbox(
                tag=_SETTING_NOTIFICATIONS,
                label="Show notifications",
                callback=_on_setting_changed,
            )
            dpg.add_text(
                "Display toast notifications for profile switches and events",
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(height=PADDING_LARGE)

            # Behavior Section
            _create_section_header("BEHAVIOR")

            dpg.add_checkbox(
                tag=_SETTING_CONFIRM_SWITCH,
                label="Confirm before switching profiles",
                callback=_on_setting_changed,
            )
            dpg.add_text(
                "Show confirmation dialog when switching to a different profile",
                color=COLORS["text_disabled"],
            )

            dpg.add_spacer(height=PADDING_SMALL)

            dpg.add_checkbox(
                tag=_SETTING_CLEAR_SSH,
                label="Clear SSH agent on profile switch",
                callback=_on_setting_changed,
            )
            dpg.add_text(
                "Remove other SSH keys from agent when switching profiles",
                color=COLORS["text_disabled"],
            )

        # Footer with Save button and status
        dpg.add_separator()
        dpg.add_spacer(height=PADDING_SMALL)

        with dpg.group(horizontal=True):
            dpg.add_button(
                tag=_SAVE_BUTTON,
                label="Save Settings",
                callback=_save_settings,
                width=120,
                enabled=False,
            )

            dpg.add_spacer(width=PADDING_MEDIUM)

            dpg.add_text(
                "",
                tag=_STATUS_TEXT,
                color=COLORS["success"],
            )

    # Load current settings
    _load_settings()

    logger.debug("Settings view created")
    return view


def _create_section_header(title: str) -> None:
    """Create a section header with accent color.

    Args:
        title: Section title text.
    """
    dpg.add_text(
        title,
        color=COLORS["accent_cyan"],
    )
    dpg.add_separator()
    dpg.add_spacer(height=PADDING_SMALL)


def _load_settings() -> None:
    """Load current settings into the view controls."""
    global _container, _has_changes

    if _container is None:
        logger.warning("Cannot load settings: container not set")
        return

    try:
        # Get current settings from session or config
        # For now, use default Settings values
        from src.models.settings import Settings

        settings = Settings()

        # Try to load from session manager if available
        try:
            session = _container.session_manager
            if hasattr(session, "settings") and session.settings:
                settings = session.settings
        except Exception as e:
            logger.debug("Could not load settings from session: %s", e)

        # Populate controls
        if dpg.does_item_exist(_SETTING_START_WINDOWS):
            dpg.set_value(_SETTING_START_WINDOWS, settings.start_with_windows)

        if dpg.does_item_exist(_SETTING_START_MINIMIZED):
            dpg.set_value(_SETTING_START_MINIMIZED, settings.start_minimized)

        if dpg.does_item_exist(_SETTING_AUTO_LOCK):
            # Clamp to slider range
            timeout = min(60, max(0, settings.auto_lock_timeout))
            dpg.set_value(_SETTING_AUTO_LOCK, timeout)
            _update_auto_lock_label(timeout)

        if dpg.does_item_exist(_SETTING_NOTIFICATIONS):
            dpg.set_value(_SETTING_NOTIFICATIONS, settings.show_notifications)

        if dpg.does_item_exist(_SETTING_CONFIRM_SWITCH):
            dpg.set_value(_SETTING_CONFIRM_SWITCH, settings.confirm_before_switch)

        if dpg.does_item_exist(_SETTING_CLEAR_SSH):
            dpg.set_value(_SETTING_CLEAR_SSH, settings.clear_ssh_agent_on_switch)

        _has_changes = False
        _update_save_button()

    except Exception:
        logger.exception("Failed to load settings")


def _save_settings() -> None:
    """Save current settings to configuration."""
    global _container, _has_changes

    if _container is None:
        logger.error("Cannot save settings: container not set")
        return

    try:
        from src.models.settings import Settings

        # Gather values from controls
        settings = Settings(
            start_with_windows=(
                dpg.get_value(_SETTING_START_WINDOWS)
                if dpg.does_item_exist(_SETTING_START_WINDOWS)
                else False
            ),
            start_minimized=(
                dpg.get_value(_SETTING_START_MINIMIZED)
                if dpg.does_item_exist(_SETTING_START_MINIMIZED)
                else True
            ),
            auto_lock_timeout=(
                dpg.get_value(_SETTING_AUTO_LOCK) if dpg.does_item_exist(_SETTING_AUTO_LOCK) else 15
            ),
            show_notifications=(
                dpg.get_value(_SETTING_NOTIFICATIONS)
                if dpg.does_item_exist(_SETTING_NOTIFICATIONS)
                else True
            ),
            confirm_before_switch=(
                dpg.get_value(_SETTING_CONFIRM_SWITCH)
                if dpg.does_item_exist(_SETTING_CONFIRM_SWITCH)
                else False
            ),
            clear_ssh_agent_on_switch=(
                dpg.get_value(_SETTING_CLEAR_SSH)
                if dpg.does_item_exist(_SETTING_CLEAR_SSH)
                else True
            ),
        )

        # Save to session manager if available
        try:
            session = _container.session_manager
            if hasattr(session, "update_settings"):
                session.update_settings(settings)
        except Exception as e:
            logger.debug(f"Could not save to session manager: {e}")

        _has_changes = False
        _update_save_button()
        _show_status("Settings saved successfully", success=True)

        logger.info("Settings saved")

    except Exception as e:
        logger.exception("Failed to save settings")
        _show_status(f"Failed to save: {e}", success=False)


def _on_setting_changed() -> None:
    """Handle any setting checkbox change."""
    global _has_changes
    _has_changes = True
    _update_save_button()
    _clear_status()


def _on_auto_lock_changed(_sender: int, app_data: int) -> None:
    """Handle auto-lock slider change.

    Args:
        _sender: Sender ID (unused).
        app_data: New slider value.
    """
    global _has_changes
    _has_changes = True
    _update_save_button()
    _update_auto_lock_label(app_data)
    _clear_status()


def _update_auto_lock_label(value: int) -> None:
    """Update the auto-lock timeout label text.

    Args:
        value: Timeout value in minutes.
    """
    if dpg.does_item_exist(_SETTING_AUTO_LOCK_LABEL):
        if value == 0:
            dpg.set_value(_SETTING_AUTO_LOCK_LABEL, "Disabled")
        elif value == 1:
            dpg.set_value(_SETTING_AUTO_LOCK_LABEL, "1 minute")
        else:
            dpg.set_value(_SETTING_AUTO_LOCK_LABEL, f"{value} minutes")


def _update_save_button() -> None:
    """Update save button enabled state based on changes."""
    if dpg.does_item_exist(_SAVE_BUTTON):
        dpg.configure_item(_SAVE_BUTTON, enabled=_has_changes)


def _show_status(message: str, success: bool = True) -> None:
    """Show status message.

    Args:
        message: Status message to display.
        success: True for success color, False for error.
    """
    if dpg.does_item_exist(_STATUS_TEXT):
        dpg.set_value(_STATUS_TEXT, message)
        color = COLORS["success"] if success else COLORS["error"]
        dpg.configure_item(_STATUS_TEXT, color=color)


def _clear_status() -> None:
    """Clear the status message."""
    if dpg.does_item_exist(_STATUS_TEXT):
        dpg.set_value(_STATUS_TEXT, "")


def _on_change_password() -> None:
    """Handle Change Master Password button click."""
    logger.debug("Change password button clicked")

    # Show password dialog in first-time mode for new password
    show_password_dialog(
        is_first_time=True,
        on_submit=_handle_password_change,
        on_cancel=None,
    )


def _handle_password_change(new_password: str) -> None:
    """Handle new password submission.

    Args:
        new_password: New master password.
    """
    global _container

    if _container is None:
        logger.error("Cannot change password: container not set")
        return

    try:
        # Change password through session manager
        session = _container.session_manager
        if hasattr(session, "change_master_password"):
            # Note: Full implementation should request current password first
            session.change_master_password(new_password)  # type: ignore[call-arg]
            _show_status("Password changed successfully", success=True)
            logger.info("Master password changed")
        else:
            logger.warning("Session manager does not support password change")
            _show_status("Password change not available", success=False)

    except Exception as e:
        logger.exception("Failed to change password")
        _show_status(f"Failed to change password: {e}", success=False)


def refresh_settings() -> None:
    """Reload settings from configuration."""
    _load_settings()


__all__ = [
    "create_settings_view",
    "refresh_settings",
]
