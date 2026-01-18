"""Path management utilities for Git-Switch.

This module provides functions for resolving application data directories
and configuration file paths on Windows.
"""

from __future__ import annotations

import os
from pathlib import Path

# Application name for data directories
APP_NAME = "Git-Switch"


def get_app_data_dir() -> Path:
    """Get the application data directory.

    Returns the path to the application's data directory in the user's
    APPDATA folder on Windows.

    Returns:
        Path to %APPDATA%/Git-Switch/

    Note:
        Creates the directory if it doesn't exist.
    """
    appdata = os.environ.get("APPDATA")
    if appdata:
        base = Path(appdata)
    else:
        # Fallback to user's home directory
        base = Path.home() / "AppData" / "Roaming"

    app_dir = base / APP_NAME
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir


def get_profiles_path() -> Path:
    """Get the path to the encrypted profiles data file.

    Returns:
        Path to profiles.dat in the app data directory.
    """
    return get_app_data_dir() / "profiles.dat"


def get_config_path() -> Path:
    """Get the path to the application settings file.

    Returns:
        Path to config.json in the app data directory.
    """
    return get_app_data_dir() / "config.json"


def get_master_key_path() -> Path:
    """Get the path to the master key configuration file.

    Returns:
        Path to master.json in the app data directory.
    """
    return get_app_data_dir() / "master.json"


def get_repositories_path() -> Path:
    """Get the path to the repository registry file.

    Returns:
        Path to repositories.json in the app data directory.
    """
    return get_app_data_dir() / "repositories.json"


def get_keys_dir() -> Path:
    """Get the path to the encrypted keys directory.

    Returns:
        Path to keys/ subdirectory in the app data directory.

    Note:
        Creates the directory if it doesn't exist.
    """
    keys_dir = get_app_data_dir() / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    return keys_dir


def get_ui_state_path() -> Path:
    """Get the path to the UI state file.

    Returns:
        Path to ui_state.json in the app data directory.
    """
    return get_app_data_dir() / "ui_state.json"


def get_ssh_key_path(profile_id: str) -> Path:
    """Get the path to an encrypted SSH key file.

    Args:
        profile_id: UUID string of the profile.

    Returns:
        Path to {profile_id}.ssh in the keys directory.
    """
    return get_keys_dir() / f"{profile_id}.ssh"


def get_gpg_key_path(profile_id: str) -> Path:
    """Get the path to an encrypted GPG key file.

    Args:
        profile_id: UUID string of the profile.

    Returns:
        Path to {profile_id}.gpg in the keys directory.
    """
    return get_keys_dir() / f"{profile_id}.gpg"


def ensure_app_directories() -> None:
    """Ensure all application directories exist.

    Creates the app data directory and keys subdirectory if they
    don't already exist.
    """
    get_app_data_dir()
    get_keys_dir()


__all__ = [
    "APP_NAME",
    "ensure_app_directories",
    "get_app_data_dir",
    "get_config_path",
    "get_gpg_key_path",
    "get_keys_dir",
    "get_master_key_path",
    "get_profiles_path",
    "get_repositories_path",
    "get_ssh_key_path",
    "get_ui_state_path",
]
