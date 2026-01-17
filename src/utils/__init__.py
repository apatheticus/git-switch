"""Cross-cutting utilities for Git-Switch.

This module contains path management, Windows-specific helpers,
and notification wrappers.
"""

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
    ensure_app_directories,
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
    add_to_startup,
    get_service_status,
    get_startup_registry_key,
    is_admin,
    is_in_startup,
    is_ssh_agent_running,
    is_windows,
    remove_from_startup,
    start_service,
    start_ssh_agent,
    stop_service,
)

__all__ = [
    "APP_NAME",
    "DEFAULT_DURATION",
    "add_to_startup",
    "ensure_app_directories",
    # Paths
    "get_app_data_dir",
    "get_config_path",
    "get_gpg_key_path",
    "get_keys_dir",
    "get_master_key_path",
    "get_profiles_path",
    "get_repositories_path",
    "get_service_status",
    "get_ssh_key_path",
    "get_startup_registry_key",
    "get_ui_state_path",
    "is_admin",
    "is_in_startup",
    "is_notifications_available",
    "is_ssh_agent_running",
    # Windows
    "is_windows",
    "remove_from_startup",
    "show_error_notification",
    "show_lock_notification",
    # Notifications
    "show_notification",
    "show_profile_switch_notification",
    "start_service",
    "start_ssh_agent",
    "stop_service",
]
