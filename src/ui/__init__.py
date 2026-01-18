"""DearPyGui presentation layer for Git-Switch.

This module contains the main application controller, views,
dialogs, and reusable UI components.

Note: Imports are lazy to allow importing submodules without
requiring DearPyGui to be installed (useful for testing).
"""

from __future__ import annotations

from typing import Any

# Lazy imports to avoid requiring dearpygui at import time
# This allows tests to mock dependencies before importing specific modules


def __getattr__(name: str) -> Any:
    """Lazy import handler for module attributes."""
    if name == "GitSwitchApp":
        from src.ui.app import GitSwitchApp

        return GitSwitchApp
    if name == "run_application":
        from src.ui.app import run_application

        return run_application
    if name == "create_main_window":
        from src.ui.main_window import create_main_window

        return create_main_window
    if name == "show_view":
        from src.ui.main_window import show_view

        return show_view
    if name == "update_active_profile":
        from src.ui.main_window import update_active_profile

        return update_active_profile
    if name == "update_status":
        from src.ui.main_window import update_status

        return update_status
    if name == "SystemTrayIcon":
        from src.ui.system_tray import SystemTrayIcon

        return SystemTrayIcon
    if name == "APP_HEIGHT":
        from src.ui.theme import APP_HEIGHT

        return APP_HEIGHT
    if name == "APP_WIDTH":
        from src.ui.theme import APP_WIDTH

        return APP_WIDTH
    if name == "COLORS":
        from src.ui.theme import COLORS

        return COLORS
    if name == "FOOTER_HEIGHT":
        from src.ui.theme import FOOTER_HEIGHT

        return FOOTER_HEIGHT
    if name == "HEADER_HEIGHT":
        from src.ui.theme import HEADER_HEIGHT

        return HEADER_HEIGHT
    if name == "SIDEBAR_WIDTH":
        from src.ui.theme import SIDEBAR_WIDTH

        return SIDEBAR_WIDTH
    if name == "TAGS":
        from src.ui.theme import TAGS

        return TAGS
    if name == "create_theme":
        from src.ui.theme import create_theme

        return create_theme
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Theme
    "APP_HEIGHT",
    "APP_WIDTH",
    "COLORS",
    "FOOTER_HEIGHT",
    "HEADER_HEIGHT",
    "SIDEBAR_WIDTH",
    "TAGS",
    # App
    "GitSwitchApp",
    # System tray
    "SystemTrayIcon",
    # Main window
    "create_main_window",
    "create_theme",
    "run_application",
    "show_view",
    "update_active_profile",
    "update_status",
]
