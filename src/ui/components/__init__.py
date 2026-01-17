"""Reusable UI components for Git-Switch.

Components include:
- Profile card widget
- Status bar

Note: Imports are lazy to allow importing without requiring DearPyGui.
"""

from __future__ import annotations

# Profile card exports
_PROFILE_CARD_EXPORTS = {
    "CARD_HEIGHT",
    "CARD_WIDTH",
    "create_profile_card",
    "delete_profile_card",
    "update_profile_card_status",
}

# Status bar exports
_STATUS_BAR_EXPORTS = {
    "ACTIVE_PROFILE_TAG",
    "GPG_STATUS_TAG",
    "SCOPE_TAG",
    "SSH_STATUS_TAG",
    "STATUS_BAR_TAG",
    "create_status_bar",
    "update_active_profile",
    "update_all_status",
    "update_gpg_status",
    "update_scope",
    "update_ssh_status",
}


def __getattr__(name: str):
    """Lazy import handler for module attributes."""
    if name in _PROFILE_CARD_EXPORTS:
        from src.ui.components import profile_card
        return getattr(profile_card, name)
    elif name in _STATUS_BAR_EXPORTS:
        from src.ui.components import status_bar
        return getattr(status_bar, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Profile card
    "CARD_HEIGHT",
    "CARD_WIDTH",
    "create_profile_card",
    "delete_profile_card",
    "update_profile_card_status",
    # Status bar
    "ACTIVE_PROFILE_TAG",
    "GPG_STATUS_TAG",
    "SCOPE_TAG",
    "SSH_STATUS_TAG",
    "STATUS_BAR_TAG",
    "create_status_bar",
    "update_active_profile",
    "update_all_status",
    "update_gpg_status",
    "update_scope",
    "update_ssh_status",
]
