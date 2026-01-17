"""Settings management for Git-Switch.

This module provides the SettingsManager class for loading and saving
application settings from config.json.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING

from src.models.settings import Settings
from src.utils.paths import get_config_path

if TYPE_CHECKING:
    from pathlib import Path


class SettingsManager:
    """Manages application settings persistence.

    This class handles loading and saving Settings to config.json,
    providing defaults when the file doesn't exist.

    Attributes:
        settings: The current loaded settings (None until load_settings called).
    """

    def __init__(self) -> None:
        """Initialize the settings manager."""
        self._settings: Settings | None = None

    @property
    def settings(self) -> Settings | None:
        """Get the currently loaded settings."""
        return self._settings

    def load_settings(self) -> Settings:
        """Load settings from config.json or return defaults.

        Returns:
            Settings instance loaded from file or defaults.

        Note:
            If the config file doesn't exist or is invalid,
            default settings are returned.
        """
        config_path = get_config_path()
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text(encoding="utf-8"))
                # Filter to only valid Settings fields
                valid_fields = {
                    "start_with_windows",
                    "start_minimized",
                    "auto_lock_timeout",
                    "show_notifications",
                    "confirm_before_switch",
                    "clear_ssh_agent_on_switch",
                }
                filtered_data = {k: v for k, v in data.items() if k in valid_fields}
                self._settings = Settings(**filtered_data)
            except (json.JSONDecodeError, TypeError, ValueError):
                self._settings = Settings()
        else:
            self._settings = Settings()
        return self._settings

    def save_settings(self, settings: Settings) -> None:
        """Save settings to config.json.

        Args:
            settings: Settings instance to save.
        """
        config_path = get_config_path()
        config_path.write_text(
            json.dumps(asdict(settings), indent=2),
            encoding="utf-8",
        )
        self._settings = settings

    def get_auto_lock_timeout(self) -> int:
        """Get auto_lock_timeout for SessionManager construction.

        Returns:
            Auto-lock timeout in minutes.

        Note:
            Loads settings if not already loaded.
        """
        if self._settings is None:
            self.load_settings()
        return self._settings.auto_lock_timeout if self._settings else 15

    def update_setting(self, key: str, value: object) -> None:
        """Update a single setting value.

        Args:
            key: Setting name to update.
            value: New value for the setting.

        Raises:
            ValueError: If the key is not a valid setting name.
        """
        if self._settings is None:
            self.load_settings()

        if not hasattr(self._settings, key):
            raise ValueError(f"Invalid setting key: {key}")

        # Create new settings with updated value
        current_dict = asdict(self._settings)
        current_dict[key] = value
        self._settings = Settings(**current_dict)
        self.save_settings(self._settings)


__all__ = [
    "SettingsManager",
]
