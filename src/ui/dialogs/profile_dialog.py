"""Profile dialog for Git-Switch.

Modal dialog for creating and editing Git profiles with SSH/GPG key
configuration, validation, and file browser integration.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import dearpygui.dearpygui as dpg

from src.ui.theme import (
    COLORS,
    PADDING_MEDIUM,
    PADDING_SMALL,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.models.profile import Profile

logger = logging.getLogger(__name__)

# Dialog constants
DIALOG_TAG = "profile_dialog"
DIALOG_WIDTH = 550
DIALOG_HEIGHT = 520

# Input field tags
_INPUT_NAME = "profile_name_input"
_INPUT_USERNAME = "profile_username_input"
_INPUT_EMAIL = "profile_email_input"
_INPUT_ORG = "profile_org_input"
_INPUT_SSH_PRIVATE = "profile_ssh_private_input"
_INPUT_SSH_PUBLIC = "profile_ssh_public_input"
_INPUT_SSH_PASSPHRASE = "profile_ssh_passphrase_input"
_INPUT_GPG_ENABLED = "profile_gpg_enabled_input"
_INPUT_GPG_KEY_ID = "profile_gpg_key_id_input"
_INPUT_GPG_KEY_FILE = "profile_gpg_key_file_input"
_GPG_SECTION = "profile_gpg_section"
_ERROR_TEXT = "profile_error_text"
_FILE_DIALOG = "profile_file_dialog"

# Callbacks storage
_on_save_callback: Callable[[dict[str, Any]], None] | None = None
_on_cancel_callback: Callable[[], None] | None = None
_current_mode: Literal["create", "edit"] = "create"
_current_file_target: str = ""


def show_profile_dialog(
    mode: Literal["create", "edit"],
    profile: Profile | None,
    on_save: Callable[[dict[str, Any]], None],
    on_cancel: Callable[[], None] | None = None,
) -> None:
    """Show the profile create/edit dialog.

    Args:
        mode: "create" for new profile, "edit" for existing profile.
        profile: Existing profile for edit mode, None for create mode.
        on_save: Called with profile data dict when saved successfully.
        on_cancel: Called when dialog is cancelled.
    """
    global _on_save_callback, _on_cancel_callback, _current_mode

    _on_save_callback = on_save
    _on_cancel_callback = on_cancel
    _current_mode = mode

    # Clean up existing dialog if present
    if dpg.does_item_exist(DIALOG_TAG):
        dpg.delete_item(DIALOG_TAG)

    # Center dialog on viewport
    viewport_width = dpg.get_viewport_width()
    viewport_height = dpg.get_viewport_height()
    pos_x = (viewport_width - DIALOG_WIDTH) // 2
    pos_y = (viewport_height - DIALOG_HEIGHT) // 2

    title = "Create Profile" if mode == "create" else "Edit Profile"
    logger.debug(f"Showing profile dialog: {title}")

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
        # Scrollable content area
        with dpg.child_window(
            height=DIALOG_HEIGHT - 80,
            border=False,
        ):
            # Basic Info Section
            dpg.add_text("BASIC INFO", color=COLORS["accent_cyan"])
            dpg.add_separator()
            dpg.add_spacer(height=PADDING_SMALL)

            # Profile Name
            dpg.add_text("Profile Name *", color=COLORS["text_primary"])
            dpg.add_input_text(
                tag=_INPUT_NAME,
                width=-1,
                hint="e.g., Work, Personal, Open Source",
                default_value=profile.name if profile else "",
            )

            dpg.add_spacer(height=PADDING_SMALL)

            # Git Username
            dpg.add_text("Git Username *", color=COLORS["text_primary"])
            dpg.add_input_text(
                tag=_INPUT_USERNAME,
                width=-1,
                hint="user.name for Git commits",
                default_value=profile.git_username if profile else "",
            )

            dpg.add_spacer(height=PADDING_SMALL)

            # Git Email
            dpg.add_text("Git Email *", color=COLORS["text_primary"])
            dpg.add_input_text(
                tag=_INPUT_EMAIL,
                width=-1,
                hint="user.email for Git commits",
                default_value=profile.git_email if profile else "",
            )

            dpg.add_spacer(height=PADDING_SMALL)

            # Organization (optional)
            dpg.add_text("Organization", color=COLORS["text_secondary"])
            dpg.add_input_text(
                tag=_INPUT_ORG,
                width=-1,
                hint="Optional company/org name",
                default_value=profile.organization if profile else "",
            )

            dpg.add_spacer(height=PADDING_MEDIUM)

            # SSH Key Section
            dpg.add_text("SSH KEY *", color=COLORS["accent_cyan"])
            dpg.add_separator()
            dpg.add_spacer(height=PADDING_SMALL)

            # SSH Private Key
            dpg.add_text("Private Key Path *", color=COLORS["text_primary"])
            with dpg.group(horizontal=True):
                dpg.add_input_text(
                    tag=_INPUT_SSH_PRIVATE,
                    width=-80,
                    hint="Path to private key file",
                    default_value="",
                )
                dpg.add_button(
                    label="Browse",
                    width=70,
                    callback=lambda: _show_file_dialog(_INPUT_SSH_PRIVATE),
                )

            dpg.add_spacer(height=PADDING_SMALL)

            # SSH Public Key (multiline for paste)
            dpg.add_text("Public Key", color=COLORS["text_secondary"])
            dpg.add_input_text(
                tag=_INPUT_SSH_PUBLIC,
                width=-1,
                height=50,
                multiline=True,
                hint="Paste public key or leave empty to extract from private",
                default_value="",
            )

            dpg.add_spacer(height=PADDING_SMALL)

            # SSH Passphrase (optional)
            dpg.add_text("Key Passphrase", color=COLORS["text_secondary"])
            dpg.add_input_text(
                tag=_INPUT_SSH_PASSPHRASE,
                width=-1,
                password=True,
                hint="Leave empty if key is not protected",
            )

            dpg.add_spacer(height=PADDING_MEDIUM)

            # GPG Section (collapsible)
            dpg.add_text("GPG SIGNING", color=COLORS["accent_cyan"])
            dpg.add_separator()
            dpg.add_spacer(height=PADDING_SMALL)

            # GPG Enabled toggle
            gpg_enabled = profile.gpg_key.enabled if profile and profile.gpg_key else False
            dpg.add_checkbox(
                tag=_INPUT_GPG_ENABLED,
                label="Enable GPG commit signing",
                default_value=gpg_enabled,
                callback=_on_gpg_toggle,
            )

            dpg.add_spacer(height=PADDING_SMALL)

            # GPG details (shown when enabled)
            with dpg.group(tag=_GPG_SECTION, show=gpg_enabled):
                # GPG Key ID
                dpg.add_text("GPG Key ID", color=COLORS["text_primary"])
                gpg_key_id = ""
                if profile and profile.gpg_key and profile.gpg_key.key_id:
                    gpg_key_id = profile.gpg_key.key_id
                dpg.add_input_text(
                    tag=_INPUT_GPG_KEY_ID,
                    width=-1,
                    hint="e.g., ABCD1234EFGH5678",
                    default_value=gpg_key_id,
                )

                dpg.add_spacer(height=PADDING_SMALL)

                # GPG Key File (optional)
                dpg.add_text("GPG Key File", color=COLORS["text_secondary"])
                with dpg.group(horizontal=True):
                    dpg.add_input_text(
                        tag=_INPUT_GPG_KEY_FILE,
                        width=-80,
                        hint="Path to GPG key file (optional)",
                    )
                    dpg.add_button(
                        label="Browse",
                        width=70,
                        callback=lambda: _show_file_dialog(_INPUT_GPG_KEY_FILE),
                    )

        # Error message (hidden by default)
        dpg.add_text(
            "",
            tag=_ERROR_TEXT,
            color=COLORS["error"],
            show=False,
        )

        dpg.add_spacer(height=PADDING_SMALL)

        # Buttons
        with dpg.group(horizontal=True):
            dpg.add_spacer(width=DIALOG_WIDTH - 190)

            dpg.add_button(
                label="Cancel",
                width=80,
                callback=_handle_cancel,
            )

            dpg.add_button(
                label="Save",
                width=80,
                callback=_handle_save,
            )

    # Create file dialog (hidden initially)
    _create_file_dialog()

    # Focus the name input
    dpg.focus_item(_INPUT_NAME)


def hide_profile_dialog() -> None:
    """Hide and clean up the profile dialog."""
    global _on_save_callback, _on_cancel_callback

    if dpg.does_item_exist(DIALOG_TAG):
        dpg.delete_item(DIALOG_TAG)

    if dpg.does_item_exist(_FILE_DIALOG):
        dpg.delete_item(_FILE_DIALOG)

    _on_save_callback = None
    _on_cancel_callback = None

    logger.debug("Profile dialog hidden")


def _on_gpg_toggle(_sender: int, app_data: bool) -> None:
    """Handle GPG enabled checkbox toggle."""
    if dpg.does_item_exist(_GPG_SECTION):
        dpg.configure_item(_GPG_SECTION, show=app_data)


def _create_file_dialog() -> None:
    """Create the file browser dialog."""
    if dpg.does_item_exist(_FILE_DIALOG):
        dpg.delete_item(_FILE_DIALOG)

    with dpg.file_dialog(
        tag=_FILE_DIALOG,
        directory_selector=False,
        show=False,
        callback=_on_file_selected,
        cancel_callback=lambda: None,
        width=500,
        height=400,
    ):
        # Add common key file extensions
        dpg.add_file_extension(".*", color=COLORS["text_secondary"])
        dpg.add_file_extension(".pem", color=COLORS["success"])
        dpg.add_file_extension(".pub", color=COLORS["accent_cyan"])
        dpg.add_file_extension(".key", color=COLORS["success"])
        dpg.add_file_extension(".asc", color=COLORS["warning"])
        dpg.add_file_extension(".gpg", color=COLORS["warning"])


def _show_file_dialog(target_input: str) -> None:
    """Show the file browser dialog.

    Args:
        target_input: Tag of the input field to populate with selected file.
    """
    global _current_file_target

    _current_file_target = target_input

    # Set default path to user's .ssh directory if browsing for SSH keys
    default_path = Path.home() / ".ssh"
    if "gpg" in target_input.lower():
        default_path = Path.home() / ".gnupg"

    if default_path.exists():
        dpg.set_value(_FILE_DIALOG, str(default_path))

    dpg.show_item(_FILE_DIALOG)


def _on_file_selected(_sender: int, app_data: dict[str, Any]) -> None:
    """Handle file selection from browser.

    Args:
        _sender: Sender ID (unused).
        app_data: Contains 'file_path_name' and 'file_name' keys.
    """
    global _current_file_target

    if not app_data or "file_path_name" not in app_data:
        return

    file_path = app_data["file_path_name"]

    if _current_file_target and dpg.does_item_exist(_current_file_target):
        dpg.set_value(_current_file_target, file_path)

    _current_file_target = ""


def _handle_save() -> None:
    """Handle save button click."""
    global _on_save_callback

    # Gather field values using helper function
    def _get(tag: str, default: Any = "") -> Any:
        return dpg.get_value(tag) if dpg.does_item_exist(tag) else default

    name = _get(_INPUT_NAME)
    username = _get(_INPUT_USERNAME)
    email = _get(_INPUT_EMAIL)
    org = _get(_INPUT_ORG)
    ssh_private = _get(_INPUT_SSH_PRIVATE)
    ssh_public = _get(_INPUT_SSH_PUBLIC)
    ssh_passphrase = _get(_INPUT_SSH_PASSPHRASE)
    gpg_enabled = _get(_INPUT_GPG_ENABLED, False)
    gpg_key_id = _get(_INPUT_GPG_KEY_ID)
    gpg_key_file = _get(_INPUT_GPG_KEY_FILE)

    # Validate required fields
    if not name or not name.strip():
        _show_error("Profile name is required")
        return

    if not username or not username.strip():
        _show_error("Git username is required")
        return

    if not email or not email.strip():
        _show_error("Git email is required")
        return

    # Basic email format validation
    if "@" not in email or "." not in email:
        _show_error("Invalid email format")
        return

    if not ssh_private or not ssh_private.strip():
        _show_error("SSH private key path is required")
        return

    # Validate SSH key file exists
    if not Path(ssh_private).is_file():
        _show_error("SSH private key file not found")
        return

    # Validate GPG fields if enabled
    if gpg_enabled and (not gpg_key_id or not gpg_key_id.strip()):
        _show_error("GPG key ID is required when GPG is enabled")
        return

    # Build profile data dict
    profile_data: dict[str, Any] = {
        "name": name.strip(),
        "git_username": username.strip(),
        "git_email": email.strip(),
        "organization": org.strip() if org else "",
        "ssh": {
            "private_key_path": ssh_private.strip(),
            "public_key": ssh_public.strip() if ssh_public else "",
            "passphrase": ssh_passphrase if ssh_passphrase else "",
        },
        "gpg": {
            "enabled": gpg_enabled,
            "key_id": gpg_key_id.strip() if gpg_key_id else "",
            "key_file": gpg_key_file.strip() if gpg_key_file else "",
        },
    }

    # Success - call the callback
    callback = _on_save_callback
    hide_profile_dialog()

    if callback:
        callback(profile_data)


def _handle_cancel() -> None:
    """Handle cancel button click."""
    global _on_cancel_callback

    callback = _on_cancel_callback
    hide_profile_dialog()

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
    "hide_profile_dialog",
    "show_profile_dialog",
]
