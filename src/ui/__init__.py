"""DearPyGui presentation layer for Git-Switch.

This module contains the main application controller, views,
dialogs, and reusable UI components.

Note: Imports are lazy to allow importing submodules without
requiring DearPyGui to be installed (useful for testing).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Lazy imports to avoid requiring dearpygui at import time
# This allows tests to mock dependencies before importing specific modules


def __getattr__(name: str):
    """Lazy import handler for module attributes."""
    if name == "GitSwitchApp":
        from src.ui.app import GitSwitchApp
        return GitSwitchApp
    elif name == "run_application":
        from src.ui.app import run_application
        return run_application
    elif name == "create_main_window":
        from src.ui.main_window import create_main_window
        return create_main_window
    elif name == "show_view":
        from src.ui.main_window import show_view
        return show_view
    elif name == "update_active_profile":
        from src.ui.main_window import update_active_profile
        return update_active_profile
    elif name == "update_status":
        from src.ui.main_window import update_status
        return update_status
    elif name == "SystemTrayIcon":
        from src.ui.system_tray import SystemTrayIcon
        return SystemTrayIcon
    elif name == "APP_HEIGHT":
        from src.ui.theme import APP_HEIGHT
        return APP_HEIGHT
    elif name == "APP_WIDTH":
        from src.ui.theme import APP_WIDTH
        return APP_WIDTH
    elif name == "COLORS":
        from src.ui.theme import COLORS
        return COLORS
    elif name == "FOOTER_HEIGHT":
        from src.ui.theme import FOOTER_HEIGHT
        return FOOTER_HEIGHT
    elif name == "HEADER_HEIGHT":
        from src.ui.theme import HEADER_HEIGHT
        return HEADER_HEIGHT
    elif name == "SIDEBAR_WIDTH":
        from src.ui.theme import SIDEBAR_WIDTH
        return SIDEBAR_WIDTH
    elif name == "TAGS":
        from src.ui.theme import TAGS
        return TAGS
    elif name == "create_theme":
        from src.ui.theme import create_theme
        return create_theme
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
