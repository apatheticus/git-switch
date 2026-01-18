"""Unit tests for SettingsManager.

These tests verify settings management functionality including:
- Loading settings from config.json
- Saving settings to config.json
- Default values when no config exists
- Handling of invalid config files
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

if TYPE_CHECKING:
    from src.core.settings_manager import SettingsManager


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def settings_manager(temp_dir: Path) -> SettingsManager:
    """Create a SettingsManager with temp directory for config."""
    from src.core.settings_manager import SettingsManager

    with patch("src.core.settings_manager.get_config_path") as mock_path:
        mock_path.return_value = temp_dir / "config.json"
        manager = SettingsManager()
        yield manager


@pytest.fixture
def settings_manager_with_config(temp_dir: Path) -> SettingsManager:
    """Create a SettingsManager with existing config file."""
    from src.core.settings_manager import SettingsManager

    config_path = temp_dir / "config.json"
    config_data = {
        "start_with_windows": True,
        "start_minimized": False,
        "auto_lock_timeout": 30,
        "show_notifications": False,
        "confirm_before_switch": True,
        "clear_ssh_agent_on_switch": False,
    }
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    with patch("src.core.settings_manager.get_config_path") as mock_path:
        mock_path.return_value = config_path
        manager = SettingsManager()
        yield manager


# =============================================================================
# Load Settings Tests
# =============================================================================


class TestLoadSettings:
    """Tests for load_settings() method."""

    def test_load_settings_returns_defaults_when_no_config(
        self, settings_manager: SettingsManager
    ) -> None:
        """load_settings should return default Settings when no config exists."""
        settings = settings_manager.load_settings()

        assert settings.start_with_windows is False
        assert settings.start_minimized is True
        assert settings.auto_lock_timeout == 15
        assert settings.show_notifications is True
        assert settings.confirm_before_switch is False
        assert settings.clear_ssh_agent_on_switch is True

    def test_load_settings_reads_from_config_file(
        self, settings_manager_with_config: SettingsManager
    ) -> None:
        """load_settings should read values from config.json."""
        settings = settings_manager_with_config.load_settings()

        assert settings.start_with_windows is True
        assert settings.start_minimized is False
        assert settings.auto_lock_timeout == 30
        assert settings.show_notifications is False
        assert settings.confirm_before_switch is True
        assert settings.clear_ssh_agent_on_switch is False

    def test_load_settings_handles_invalid_json(self, temp_dir: Path) -> None:
        """load_settings should return defaults for invalid JSON."""
        from src.core.settings_manager import SettingsManager

        config_path = temp_dir / "config.json"
        config_path.write_text("{ invalid json }", encoding="utf-8")

        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = config_path
            manager = SettingsManager()
            settings = manager.load_settings()

        # Should return defaults
        assert settings.auto_lock_timeout == 15

    def test_load_settings_handles_invalid_values(self, temp_dir: Path) -> None:
        """load_settings should return defaults for invalid setting values."""
        from src.core.settings_manager import SettingsManager

        config_path = temp_dir / "config.json"
        # Invalid: negative timeout
        config_data = {"auto_lock_timeout": -5}
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = config_path
            manager = SettingsManager()
            settings = manager.load_settings()

        # Should return defaults due to validation error
        assert settings.auto_lock_timeout == 15

    def test_load_settings_ignores_unknown_fields(self, temp_dir: Path) -> None:
        """load_settings should ignore unknown fields in config."""
        from src.core.settings_manager import SettingsManager

        config_path = temp_dir / "config.json"
        config_data = {
            "auto_lock_timeout": 20,
            "unknown_field": "ignored",
            "another_unknown": 123,
        }
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = config_path
            manager = SettingsManager()
            settings = manager.load_settings()

        assert settings.auto_lock_timeout == 20


# =============================================================================
# Save Settings Tests
# =============================================================================


class TestSaveSettings:
    """Tests for save_settings() method."""

    def test_save_settings_creates_config_file(
        self, settings_manager: SettingsManager, temp_dir: Path
    ) -> None:
        """save_settings should create config.json."""
        from src.models.settings import Settings

        config_path = temp_dir / "config.json"

        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = config_path
            settings = Settings(auto_lock_timeout=25)
            settings_manager.save_settings(settings)

        assert config_path.exists()
        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data["auto_lock_timeout"] == 25

    def test_save_settings_updates_internal_state(
        self, settings_manager: SettingsManager, temp_dir: Path
    ) -> None:
        """save_settings should update internal settings reference."""
        from src.models.settings import Settings

        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = temp_dir / "config.json"
            settings = Settings(show_notifications=False)
            settings_manager.save_settings(settings)

        assert settings_manager.settings is not None
        assert settings_manager.settings.show_notifications is False

    def test_save_settings_preserves_all_fields(
        self, settings_manager: SettingsManager, temp_dir: Path
    ) -> None:
        """save_settings should save all settings fields."""
        from src.models.settings import Settings

        config_path = temp_dir / "config.json"

        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = config_path
            settings = Settings(
                start_with_windows=True,
                start_minimized=False,
                auto_lock_timeout=45,
                show_notifications=False,
                confirm_before_switch=True,
                clear_ssh_agent_on_switch=False,
            )
            settings_manager.save_settings(settings)

        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data["start_with_windows"] is True
        assert data["start_minimized"] is False
        assert data["auto_lock_timeout"] == 45
        assert data["show_notifications"] is False
        assert data["confirm_before_switch"] is True
        assert data["clear_ssh_agent_on_switch"] is False


# =============================================================================
# Get Auto Lock Timeout Tests
# =============================================================================


class TestGetAutoLockTimeout:
    """Tests for get_auto_lock_timeout() method."""

    def test_get_auto_lock_timeout_returns_default(
        self, settings_manager: SettingsManager
    ) -> None:
        """get_auto_lock_timeout should return default when no config."""
        timeout = settings_manager.get_auto_lock_timeout()
        assert timeout == 15

    def test_get_auto_lock_timeout_returns_configured_value(
        self, settings_manager_with_config: SettingsManager
    ) -> None:
        """get_auto_lock_timeout should return configured value."""
        timeout = settings_manager_with_config.get_auto_lock_timeout()
        assert timeout == 30

    def test_get_auto_lock_timeout_loads_settings_if_needed(
        self, settings_manager: SettingsManager
    ) -> None:
        """get_auto_lock_timeout should load settings if not loaded."""
        assert settings_manager.settings is None
        timeout = settings_manager.get_auto_lock_timeout()
        assert settings_manager.settings is not None


# =============================================================================
# Update Setting Tests
# =============================================================================


class TestUpdateSetting:
    """Tests for update_setting() method."""

    def test_update_setting_modifies_value(
        self, settings_manager: SettingsManager, temp_dir: Path
    ) -> None:
        """update_setting should modify and save the setting."""
        config_path = temp_dir / "config.json"

        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = config_path
            settings_manager.load_settings()
            settings_manager.update_setting("auto_lock_timeout", 60)

        assert settings_manager.settings.auto_lock_timeout == 60

        # Verify persisted
        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data["auto_lock_timeout"] == 60

    def test_update_setting_invalid_key_raises(self, settings_manager: SettingsManager) -> None:
        """update_setting should raise ValueError for invalid key."""
        settings_manager.load_settings()

        with pytest.raises(ValueError, match="Invalid setting key"):
            settings_manager.update_setting("nonexistent_key", "value")

    def test_update_setting_loads_if_needed(
        self, settings_manager: SettingsManager, temp_dir: Path
    ) -> None:
        """update_setting should load settings if not loaded."""
        with patch("src.core.settings_manager.get_config_path") as mock_path:
            mock_path.return_value = temp_dir / "config.json"
            assert settings_manager.settings is None
            settings_manager.update_setting("show_notifications", False)
            assert settings_manager.settings is not None


# =============================================================================
# Settings Property Tests
# =============================================================================


class TestSettingsProperty:
    """Tests for settings property."""

    def test_settings_property_none_before_load(self, settings_manager: SettingsManager) -> None:
        """settings property should be None before load_settings called."""
        assert settings_manager.settings is None

    def test_settings_property_returns_loaded_settings(
        self, settings_manager: SettingsManager
    ) -> None:
        """settings property should return loaded settings."""
        settings_manager.load_settings()
        assert settings_manager.settings is not None
