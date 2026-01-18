"""Unit tests for Git-Switch utility modules.

Tests verify path utilities, Windows helpers, and notification functions.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.utils.notifications import (
    APP_NAME,
    DEFAULT_DURATION,
    is_notifications_available,
    show_error_notification,
    show_lock_notification,
    show_notification,
    show_profile_switch_notification,
)
from src.utils.paths import (
    get_app_data_dir,
    get_config_path,
    get_gpg_key_path,
    get_keys_dir,
    get_master_key_path,
    get_profiles_path,
    get_repositories_path,
    get_ssh_key_path,
    get_ui_state_path,
)
from src.utils.windows import (
    get_startup_registry_key,
    is_admin,
    is_windows,
)

# =============================================================================
# Path Utilities Tests
# =============================================================================


class TestPaths:
    """Tests for path utility functions."""

    def test_get_app_data_dir_uses_appdata(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """get_app_data_dir should use APPDATA environment variable."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        result = get_app_data_dir()
        assert result == tmp_path / "GitProfileSwitcher"
        assert result.exists()

    def test_get_app_data_dir_creates_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """get_app_data_dir should create the directory if it doesn't exist."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app_dir = tmp_path / "GitProfileSwitcher"
        assert not app_dir.exists()
        get_app_data_dir()
        assert app_dir.exists()

    def test_get_profiles_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_profiles_path should return path to profiles.dat."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        result = get_profiles_path()
        assert result.name == "profiles.dat"
        assert "GitProfileSwitcher" in str(result)

    def test_get_config_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_config_path should return path to config.json."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        result = get_config_path()
        assert result.name == "config.json"

    def test_get_master_key_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_master_key_path should return path to master.json."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        result = get_master_key_path()
        assert result.name == "master.json"

    def test_get_repositories_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_repositories_path should return path to repositories.json."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        result = get_repositories_path()
        assert result.name == "repositories.json"

    def test_get_keys_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_keys_dir should return path to keys directory."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        result = get_keys_dir()
        assert result.name == "keys"
        assert result.exists()

    def test_get_ui_state_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_ui_state_path should return path to ui_state.json."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        result = get_ui_state_path()
        assert result.name == "ui_state.json"

    def test_get_ssh_key_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_ssh_key_path should return path based on profile ID."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        profile_id = "12345678-1234-5678-1234-567812345678"
        result = get_ssh_key_path(profile_id)
        assert result.name == f"{profile_id}.ssh"
        assert "keys" in str(result)

    def test_get_gpg_key_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """get_gpg_key_path should return path based on profile ID."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        profile_id = "12345678-1234-5678-1234-567812345678"
        result = get_gpg_key_path(profile_id)
        assert result.name == f"{profile_id}.gpg"
        assert "keys" in str(result)


# =============================================================================
# Windows Utilities Tests
# =============================================================================


class TestWindowsUtils:
    """Tests for Windows-specific utility functions."""

    def test_is_windows_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """is_windows should return True on Windows."""
        monkeypatch.setattr(sys, "platform", "win32")
        assert is_windows() is True

    def test_is_windows_on_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """is_windows should return False on Linux."""
        monkeypatch.setattr(sys, "platform", "linux")
        assert is_windows() is False

    def test_is_windows_on_macos(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """is_windows should return False on macOS."""
        monkeypatch.setattr(sys, "platform", "darwin")
        assert is_windows() is False

    def test_is_admin_on_non_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """is_admin should return False on non-Windows platforms."""
        monkeypatch.setattr(sys, "platform", "linux")
        assert is_admin() is False

    @patch("src.utils.windows.is_windows", return_value=True)
    def test_is_admin_with_mock(self, mock_windows: MagicMock) -> None:
        """is_admin should handle ctypes import."""
        # This test verifies the function doesn't crash
        # Actual admin status depends on runtime environment
        result = is_admin()
        assert isinstance(result, bool)

    def test_get_startup_registry_key(self) -> None:
        """get_startup_registry_key should return correct registry path."""
        result = get_startup_registry_key()
        assert "Run" in result
        assert "Microsoft" in result
        assert "Windows" in result


# =============================================================================
# Notification Utilities Tests
# =============================================================================


class TestNotifications:
    """Tests for notification utility functions."""

    def test_app_name_constant(self) -> None:
        """APP_NAME should be set correctly."""
        assert APP_NAME == "Git-Switch"

    def test_default_duration_constant(self) -> None:
        """DEFAULT_DURATION should be a reasonable value."""
        assert DEFAULT_DURATION == 5
        assert isinstance(DEFAULT_DURATION, int)

    def test_show_notification_success_with_mock(self) -> None:
        """show_notification should return True on success when win10toast is available."""
        # Create a mock win10toast module
        mock_win10toast = MagicMock()
        mock_notifier = MagicMock()
        mock_win10toast.ToastNotifier.return_value = mock_notifier

        with patch.dict("sys.modules", {"win10toast": mock_win10toast}):
            # Need to reimport after patching
            import importlib

            from src.utils import notifications

            importlib.reload(notifications)
            result = notifications.show_notification("Test", "Message")
            # Should return True since mock doesn't raise
            assert result is True
            mock_notifier.show_toast.assert_called_once()

    def test_show_notification_without_win10toast(self) -> None:
        """show_notification should return False if win10toast not installed."""
        # Mock the import to raise ImportError
        with (
            patch.dict("sys.modules", {"win10toast": None}),
            patch(
                "builtins.__import__",
                side_effect=ImportError("No module named 'win10toast'"),
            ),
        ):
            # The function should handle ImportError gracefully
            result = show_notification("Test", "Message")
            assert result is False

    def test_show_profile_switch_notification_with_org(self) -> None:
        """show_profile_switch_notification should format message with org."""
        # Mock the underlying show_notification
        with patch("src.utils.notifications.show_notification", return_value=True) as mock:
            result = show_profile_switch_notification("Work", organization="Acme Corp")
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert "Profile Switched" in call_args[0][0]  # title
            assert "Work" in call_args[0][1]  # message
            assert "Acme Corp" in call_args[0][1]

    def test_show_profile_switch_notification_without_org(self) -> None:
        """show_profile_switch_notification should work without org."""
        with patch("src.utils.notifications.show_notification", return_value=True) as mock:
            result = show_profile_switch_notification("Personal")
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert "Personal" in call_args[0][1]

    def test_show_error_notification(self) -> None:
        """show_error_notification should include error in title."""
        with patch("src.utils.notifications.show_notification", return_value=True) as mock:
            result = show_error_notification("Something went wrong")
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert "Error" in call_args[0][0]
            assert "Something went wrong" in call_args[0][1]

    def test_show_lock_notification(self) -> None:
        """show_lock_notification should mention session locked."""
        with patch("src.utils.notifications.show_notification", return_value=True) as mock:
            result = show_lock_notification()
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert "Locked" in call_args[0][0]
            assert "inactivity" in call_args[0][1]

    def test_is_notifications_available_without_win10toast(self) -> None:
        """is_notifications_available should return False without win10toast."""
        with patch(
            "builtins.__import__",
            side_effect=ImportError("No module named 'win10toast'"),
        ):
            result = is_notifications_available()
            assert result is False


# =============================================================================
# Integration Tests
# =============================================================================


class TestPathsIntegration:
    """Integration tests for path utilities working together."""

    def test_all_paths_under_app_data_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """All path functions should return paths under app data dir."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        app_dir = get_app_data_dir()

        paths = [
            get_profiles_path(),
            get_config_path(),
            get_master_key_path(),
            get_repositories_path(),
            get_ui_state_path(),
        ]

        for path in paths:
            assert str(app_dir) in str(path)

    def test_keys_dir_paths_under_keys(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """SSH and GPG key paths should be under keys directory."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        keys_dir = get_keys_dir()
        profile_id = "test-profile-id"

        ssh_path = get_ssh_key_path(profile_id)
        gpg_path = get_gpg_key_path(profile_id)

        assert str(keys_dir) in str(ssh_path)
        assert str(keys_dir) in str(gpg_path)
