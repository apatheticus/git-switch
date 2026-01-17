"""Password dialog for Git-Switch.

Modal dialog for master password entry, supporting both first-time
setup (create password with confirmation) and unlock (enter password).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import dearpygui.dearpygui as dpg

from src.ui.theme import (
    COLORS,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Dialog constants
DIALOG_TAG = "password_dialog"
DIALOG_WIDTH = 400
DIALOG_HEIGHT_FIRST_TIME = 220
DIALOG_HEIGHT_UNLOCK = 160

# Input field tags
_INPUT_PASSWORD = "password_input"
_INPUT_CONFIRM = "password_confirm_input"
_ERROR_TEXT = "password_error_text"

# Callbacks storage
_on_submit_callback: Callable[[str], None] | None = None
_on_cancel_callback: Callable[[], None] | None = None
_is_first_time: bool = False


def show_password_dialog(
    is_first_time: bool,
    on_submit: Callable[[str], None],
    on_cancel: Callable[[], None] | None = None,
) -> None:
    """Show the password dialog modal.

    Args:
        is_first_time: If True, shows create password with confirmation.
                       If False, shows single password entry for unlock.
        on_submit: Called with the password when submitted successfully.
        on_cancel: Called when dialog is cancelled.
    """
    global _on_submit_callback, _on_cancel_callback, _is_first_time

    _on_submit_callback = on_submit
    _on_cancel_callback = on_cancel
    _is_first_time = is_first_time

    # Clean up existing dialog if present
    if dpg.does_item_exist(DIALOG_TAG):
        dpg.delete_item(DIALOG_TAG)

    # Calculate dialog height based on mode
    dialog_height = DIALOG_HEIGHT_FIRST_TIME if is_first_time else DIALOG_HEIGHT_UNLOCK

    # Center dialog on viewport
    viewport_width = dpg.get_viewport_width()
    viewport_height = dpg.get_viewport_height()
    pos_x = (viewport_width - DIALOG_WIDTH) // 2
    pos_y = (viewport_height - dialog_height) // 2

    logger.debug(f"Showing password dialog (first_time={is_first_time})")

    with dpg.window(
        tag=DIALOG_TAG,
        label="Master Password" if not is_first_time else "Create Master Password",
        modal=True,
        no_close=True,
        no_resize=True,
        no_move=False,
        no_collapse=True,
        width=DIALOG_WIDTH,
        height=dialog_height,
        pos=[pos_x, pos_y],
        on_close=_handle_cancel,
    ):
        dpg.add_spacer(height=PADDING_SMALL)

        if is_first_time:
            # First-time setup mode
            dpg.add_text(
                "Create a master password to secure your profiles.",
                color=COLORS["text_secondary"],
                wrap=DIALOG_WIDTH - PADDING_LARGE * 2,
            )
            dpg.add_spacer(height=PADDING_MEDIUM)

            # Password input
            dpg.add_text("Password:", color=COLORS["text_primary"])
            dpg.add_input_text(
                tag=_INPUT_PASSWORD,
                password=True,
                width=-1,
                callback=_on_input_change,
                on_enter=True,
            )

            dpg.add_spacer(height=PADDING_SMALL)

            # Confirm password input
            dpg.add_text("Confirm Password:", color=COLORS["text_primary"])
            dpg.add_input_text(
                tag=_INPUT_CONFIRM,
                password=True,
                width=-1,
                callback=_on_confirm_enter,
                on_enter=True,
            )
        else:
            # Unlock mode
            dpg.add_text(
                "Enter your master password to unlock.",
                color=COLORS["text_secondary"],
                wrap=DIALOG_WIDTH - PADDING_LARGE * 2,
            )
            dpg.add_spacer(height=PADDING_MEDIUM)

            # Password input
            dpg.add_text("Password:", color=COLORS["text_primary"])
            dpg.add_input_text(
                tag=_INPUT_PASSWORD,
                password=True,
                width=-1,
                callback=_on_input_enter,
                on_enter=True,
            )

        # Error message (hidden by default)
        dpg.add_spacer(height=PADDING_SMALL)
        dpg.add_text(
            "",
            tag=_ERROR_TEXT,
            color=COLORS["error"],
            show=False,
        )

        dpg.add_spacer(height=PADDING_MEDIUM)

        # Buttons
        with dpg.group(horizontal=True):
            dpg.add_spacer(width=DIALOG_WIDTH - 180)

            dpg.add_button(
                label="Cancel",
                width=80,
                callback=_handle_cancel,
            )

            dpg.add_button(
                label="Unlock" if not is_first_time else "Create",
                width=80,
                callback=_handle_submit,
            )

    # Focus the password input
    dpg.focus_item(_INPUT_PASSWORD)


def hide_password_dialog() -> None:
    """Hide and clean up the password dialog."""
    global _on_submit_callback, _on_cancel_callback

    if dpg.does_item_exist(DIALOG_TAG):
        dpg.delete_item(DIALOG_TAG)

    _on_submit_callback = None
    _on_cancel_callback = None

    logger.debug("Password dialog hidden")


def _on_input_change(_sender: int, _app_data: str) -> None:
    """Handle input change to clear error message."""
    if dpg.does_item_exist(_ERROR_TEXT):
        dpg.configure_item(_ERROR_TEXT, show=False)


def _on_input_enter(_sender: int, _app_data: str) -> None:
    """Handle enter key in unlock mode."""
    _handle_submit()


def _on_confirm_enter(_sender: int, _app_data: str) -> None:
    """Handle enter key on confirm field."""
    _handle_submit()


def _handle_submit() -> None:
    """Handle submit button click."""
    global _on_submit_callback

    if not dpg.does_item_exist(_INPUT_PASSWORD):
        return

    password = dpg.get_value(_INPUT_PASSWORD)

    if _is_first_time:
        # Validate confirmation matches
        if not dpg.does_item_exist(_INPUT_CONFIRM):
            return

        confirm = dpg.get_value(_INPUT_CONFIRM)

        if not password:
            _show_error("Password is required")
            return

        if len(password) < 8:
            _show_error("Password must be at least 8 characters")
            return

        if password != confirm:
            _show_error("Passwords do not match")
            return
    elif not password:
        # Unlock mode - just validate non-empty
        _show_error("Password is required")
        return

    # Success - call the callback
    callback = _on_submit_callback
    hide_password_dialog()

    if callback:
        callback(password)


def _handle_cancel() -> None:
    """Handle cancel button click."""
    global _on_cancel_callback

    callback = _on_cancel_callback
    hide_password_dialog()

    if callback:
        callback()


def _show_error(message: str) -> None:
    """Show error message in the dialog.

    Args:
        message: Error message to display.
    """
    if dpg.does_item_exist(_ERROR_TEXT):
        dpg.set_value(_ERROR_TEXT, message)
        dpg.configure_item(_ERROR_TEXT, show=True)


__all__ = [
    "hide_password_dialog",
    "show_password_dialog",
]
