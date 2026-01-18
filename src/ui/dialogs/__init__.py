"""Modal dialog components for Git-Switch UI.

Dialogs include:
- Password dialog (master password entry)
- Profile dialog (create/edit profile form)
- Confirm dialog (generic confirmation modal)

Note: Imports are lazy to allow importing without requiring DearPyGui.
"""

from __future__ import annotations

from typing import Any


def __getattr__(name: str) -> Any:
    """Lazy import handler for module attributes."""
    if name in ("hide_confirm_dialog", "show_confirm_dialog"):
        from src.ui.dialogs.confirm_dialog import (
            hide_confirm_dialog,
            show_confirm_dialog,
        )

        return hide_confirm_dialog if name == "hide_confirm_dialog" else show_confirm_dialog
    if name in ("hide_password_dialog", "show_password_dialog"):
        from src.ui.dialogs.password_dialog import (
            hide_password_dialog,
            show_password_dialog,
        )

        return hide_password_dialog if name == "hide_password_dialog" else show_password_dialog
    if name in ("hide_profile_dialog", "show_profile_dialog"):
        from src.ui.dialogs.profile_dialog import (
            hide_profile_dialog,
            show_profile_dialog,
        )

        return hide_profile_dialog if name == "hide_profile_dialog" else show_profile_dialog
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "hide_confirm_dialog",
    "hide_password_dialog",
    "hide_profile_dialog",
    "show_confirm_dialog",
    "show_password_dialog",
    "show_profile_dialog",
]
