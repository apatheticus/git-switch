"""Windows-specific utilities for Git-Switch.

This module provides Windows-specific helper functions for registry
operations, service management, and system integration.
"""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def is_windows() -> bool:
    """Check if running on Windows.

    Returns:
        True if the current platform is Windows.
    """
    return sys.platform == "win32"


def is_admin() -> bool:
    """Check if running with administrator privileges.

    Returns:
        True if running with admin rights on Windows, False otherwise.
    """
    if not is_windows():
        return False

    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_startup_registry_key() -> str:
    """Get the Windows registry key for startup applications.

    Returns:
        Registry key path for current user startup items.
    """
    return r"Software\Microsoft\Windows\CurrentVersion\Run"


def add_to_startup(app_name: str, app_path: Path) -> bool:
    """Add application to Windows startup.

    Args:
        app_name: Name for the startup entry.
        app_path: Path to the executable.

    Returns:
        True if successfully added, False otherwise.

    Note:
        Requires the application to be on Windows.
    """
    if not is_windows():
        return False

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            get_startup_registry_key(),
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, str(app_path))
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def remove_from_startup(app_name: str) -> bool:
    """Remove application from Windows startup.

    Args:
        app_name: Name of the startup entry to remove.

    Returns:
        True if successfully removed, False otherwise.

    Note:
        Requires the application to be on Windows.
    """
    if not is_windows():
        return False

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            get_startup_registry_key(),
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.DeleteValue(key, app_name)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def is_in_startup(app_name: str) -> bool:
    """Check if application is in Windows startup.

    Args:
        app_name: Name of the startup entry.

    Returns:
        True if entry exists in startup, False otherwise.
    """
    if not is_windows():
        return False

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            get_startup_registry_key(),
            0,
            winreg.KEY_READ,
        )
        try:
            winreg.QueryValueEx(key, app_name)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            winreg.CloseKey(key)
            return False
    except Exception:
        return False


def get_service_status(service_name: str) -> str | None:
    """Get the status of a Windows service.

    Args:
        service_name: Name of the service (e.g., "ssh-agent").

    Returns:
        Service status string (RUNNING, STOPPED, etc.) or None if error.
    """
    if not is_windows():
        return None

    try:
        result = subprocess.run(
            ["sc", "query", service_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "STATE" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        return parts[3]  # e.g., "RUNNING"
        return None
    except Exception:
        return None


def start_service(service_name: str) -> bool:
    """Start a Windows service.

    Args:
        service_name: Name of the service to start.

    Returns:
        True if service started or already running, False otherwise.

    Note:
        May require administrator privileges.
    """
    if not is_windows():
        return False

    try:
        result = subprocess.run(
            ["sc", "start", service_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0 or "RUNNING" in result.stdout
    except Exception:
        return False


def stop_service(service_name: str) -> bool:
    """Stop a Windows service.

    Args:
        service_name: Name of the service to stop.

    Returns:
        True if service stopped, False otherwise.

    Note:
        May require administrator privileges.
    """
    if not is_windows():
        return False

    try:
        result = subprocess.run(
            ["sc", "stop", service_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def is_ssh_agent_running() -> bool:
    """Check if the Windows ssh-agent service is running.

    Returns:
        True if ssh-agent is running, False otherwise.
    """
    status = get_service_status("ssh-agent")
    return status == "RUNNING"


def start_ssh_agent() -> bool:
    """Start the Windows ssh-agent service.

    Returns:
        True if service started successfully, False otherwise.
    """
    return start_service("ssh-agent")


__all__ = [
    "add_to_startup",
    "get_service_status",
    "get_startup_registry_key",
    "is_admin",
    "is_in_startup",
    "is_ssh_agent_running",
    "is_windows",
    "remove_from_startup",
    "start_service",
    "start_ssh_agent",
    "stop_service",
]
