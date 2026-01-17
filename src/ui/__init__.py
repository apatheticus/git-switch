"""DearPyGui presentation layer for Git-Switch.

This module contains the main application controller, views,
dialogs, and reusable UI components.
"""

from src.ui.app import GitSwitchApp, run_application
from src.ui.main_window import (
    create_main_window,
    show_view,
    update_active_profile,
    update_status,
)
from src.ui.system_tray import SystemTrayIcon
from src.ui.theme import (
    APP_HEIGHT,
    APP_WIDTH,
    COLORS,
    FOOTER_HEIGHT,
    HEADER_HEIGHT,
    SIDEBAR_WIDTH,
    TAGS,
    create_theme,
)

__all__ = [
    # App
    "GitSwitchApp",
    "run_application",
    # Main window
    "create_main_window",
    "show_view",
    "update_active_profile",
    "update_status",
    # System tray
    "SystemTrayIcon",
    # Theme
    "APP_HEIGHT",
    "APP_WIDTH",
    "COLORS",
    "FOOTER_HEIGHT",
    "HEADER_HEIGHT",
    "SIDEBAR_WIDTH",
    "TAGS",
    "create_theme",
]
