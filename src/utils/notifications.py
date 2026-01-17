"""Toast notification utilities for Git-Switch.

This module provides Windows toast notification functionality
using the win10toast library.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Default notification settings
DEFAULT_DURATION = 5  # seconds
APP_NAME = "Git-Switch"


def show_notification(
    title: str,
    message: str,
    icon_path: Path | None = None,
    duration: int = DEFAULT_DURATION,
) -> bool:
    """Show a Windows toast notification.

    Args:
        title: Notification title.
        message: Notification body text.
        icon_path: Optional path to icon file (.ico).
        duration: How long to show notification in seconds.

    Returns:
        True if notification was shown, False on error.

    Note:
        Notifications are shown asynchronously (threaded=True) to
        avoid blocking the main application thread.
    """
    try:
        from win10toast import ToastNotifier

        notifier = ToastNotifier()
        notifier.show_toast(
            title,
            message,
            icon_path=str(icon_path) if icon_path else None,
            duration=duration,
            threaded=True,
        )
        return True
    except ImportError:
        logger.warning("win10toast not available, notifications disabled")
        return False
    except Exception as e:
        logger.exception(f"Failed to show notification: {e}")
        return False


def show_profile_switch_notification(
    profile_name: str,
    organization: str | None = None,
    icon_path: Path | None = None,
) -> bool:
    """Show notification for profile switch.

    Args:
        profile_name: Name of the profile that was switched to.
        organization: Optional organization name.
        icon_path: Optional path to icon file.

    Returns:
        True if notification was shown, False on error.
    """
    title = f"{APP_NAME} - Profile Switched"
    if organization:
        message = f"Now using: {profile_name}\n({organization})"
    else:
        message = f"Now using: {profile_name}"

    return show_notification(title, message, icon_path)


def show_error_notification(
    error_message: str,
    icon_path: Path | None = None,
) -> bool:
    """Show error notification.

    Args:
        error_message: Error message to display.
        icon_path: Optional path to icon file.

    Returns:
        True if notification was shown, False on error.
    """
    title = f"{APP_NAME} - Error"
    return show_notification(title, error_message, icon_path)


def show_lock_notification(icon_path: Path | None = None) -> bool:
    """Show notification when session is locked.

    Args:
        icon_path: Optional path to icon file.

    Returns:
        True if notification was shown, False on error.
    """
    title = f"{APP_NAME} - Session Locked"
    message = "Your session has been locked due to inactivity."
    return show_notification(title, message, icon_path, duration=3)


def is_notifications_available() -> bool:
    """Check if notifications are available.

    Returns:
        True if win10toast is installed and can show notifications.
    """
    try:
        from win10toast import ToastNotifier

        # Try to create notifier instance
        ToastNotifier()
        return True
    except Exception:
        return False


__all__ = [
    "APP_NAME",
    "DEFAULT_DURATION",
    "is_notifications_available",
    "show_error_notification",
    "show_lock_notification",
    "show_notification",
    "show_profile_switch_notification",
]
