"""View modules for Git-Switch UI.

Views are the main content areas accessed via sidebar navigation:
- Profiles view: Manage Git profiles
- Repositories view: Register and assign profiles to repositories
- Settings view: Configure application settings
- Import/Export view: Backup and restore profiles

Note: Imports are lazy to allow importing without requiring DearPyGui.
"""

from __future__ import annotations

from typing import Any


def __getattr__(name: str) -> Any:
    """Lazy import handler for module attributes."""
    if name == "create_import_export_view":
        from src.ui.views.import_export_view import create_import_export_view

        return create_import_export_view
    if name == "create_profiles_view":
        from src.ui.views.profiles_view import create_profiles_view

        return create_profiles_view
    if name == "refresh_profiles":
        from src.ui.views.profiles_view import refresh_profiles

        return refresh_profiles
    if name == "create_repositories_view":
        from src.ui.views.repositories_view import create_repositories_view

        return create_repositories_view
    if name == "refresh_repositories":
        from src.ui.views.repositories_view import refresh_repositories

        return refresh_repositories
    if name == "create_settings_view":
        from src.ui.views.settings_view import create_settings_view

        return create_settings_view
    if name == "refresh_settings":
        from src.ui.views.settings_view import refresh_settings

        return refresh_settings
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "create_import_export_view",
    "create_profiles_view",
    "create_repositories_view",
    "create_settings_view",
    "refresh_profiles",
    "refresh_repositories",
    "refresh_settings",
]
