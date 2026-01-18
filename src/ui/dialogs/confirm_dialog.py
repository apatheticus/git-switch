"""Confirm dialog for Git-Switch.

Generic confirmation modal for destructive actions or important decisions.
Displays a title, message, and customizable Yes/No buttons.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import dearpygui.dearpygui as dpg

from src.ui.theme import (
    COLORS,
    PADDING_LARGE,
    PADDING_SMALL,
)

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Dialog constants
DIALOG_TAG = "confirm_dialog"
DIALOG_WIDTH = 350
DIALOG_HEIGHT = 140

# Callbacks storage
_on_confirm_callback: Callable[[], None] | None = None
_on_cancel_callback: Callable[[], None] | None = None


def show_confirm_dialog(
    title: str,
    message: str,
    on_confirm: Callable[[], None],
    on_cancel: Callable[[], None] | None = None,
    confirm_label: str = "Yes",
    cancel_label: str = "No",
) -> None:
    """Show a confirmation dialog modal.

    Args:
        title: Dialog title.
        message: Message to display.
        on_confirm: Called when confirm button is clicked.
        on_cancel: Called when cancel button is clicked or dialog is closed.
        confirm_label: Label for the confirm button (default: "Yes").
        cancel_label: Label for the cancel button (default: "No").
    """
    global _on_confirm_callback, _on_cancel_callback

    _on_confirm_callback = on_confirm
    _on_cancel_callback = on_cancel

    # Clean up existing dialog if present
    if dpg.does_item_exist(DIALOG_TAG):
        dpg.delete_item(DIALOG_TAG)

    # Center dialog on viewport
    viewport_width = dpg.get_viewport_width()
    viewport_height = dpg.get_viewport_height()
    pos_x = (viewport_width - DIALOG_WIDTH) // 2
    pos_y = (viewport_height - DIALOG_HEIGHT) // 2

    logger.debug(f"Showing confirm dialog: {title}")

    with dpg.window(
        tag=DIALOG_TAG,
        label=title,
        modal=True,
        no_close=True,
        no_resize=True,
        no_move=False,
        no_collapse=True,
        width=DIALOG_WIDTH,
        height=DIALOG_HEIGHT,
        pos=[pos_x, pos_y],
        on_close=_handle_cancel,
    ):
        dpg.add_spacer(height=PADDING_SMALL)

        # Message text
        dpg.add_text(
            message,
            color=COLORS["text_primary"],
            wrap=DIALOG_WIDTH - PADDING_LARGE * 2,
        )

        dpg.add_spacer(height=PADDING_LARGE)

        # Buttons
        with dpg.group(horizontal=True):
            # Calculate spacing to right-align buttons
            button_width = 80
            total_buttons_width = button_width * 2 + PADDING_SMALL
            spacer_width = DIALOG_WIDTH - total_buttons_width - PADDING_LARGE * 2

            dpg.add_spacer(width=spacer_width)

            dpg.add_button(
                label=cancel_label,
                width=button_width,
                callback=_handle_cancel,
            )

            dpg.add_button(
                label=confirm_label,
                width=button_width,
                callback=_handle_confirm,
            )


def hide_confirm_dialog() -> None:
    """Hide and clean up the confirm dialog."""
    global _on_confirm_callback, _on_cancel_callback

    if dpg.does_item_exist(DIALOG_TAG):
        dpg.delete_item(DIALOG_TAG)

    _on_confirm_callback = None
    _on_cancel_callback = None

    logger.debug("Confirm dialog hidden")


def _handle_confirm() -> None:
    """Handle confirm button click."""
    global _on_confirm_callback

    callback = _on_confirm_callback
    hide_confirm_dialog()

    if callback:
        callback()


def _handle_cancel() -> None:
    """Handle cancel button click."""
    global _on_cancel_callback

    callback = _on_cancel_callback
    hide_confirm_dialog()

    if callback:
        callback()


__all__ = [
    "hide_confirm_dialog",
    "show_confirm_dialog",
]
