"""Import/Export view for Git-Switch.

Provides functionality to export profiles to encrypted .gps archives
and import them back with merge/replace options and conflict resolution.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import dearpygui.dearpygui as dpg

from src.ui.theme import (
    COLORS,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
    TAGS,
)

if TYPE_CHECKING:
    from src.services.container import ServiceContainer

logger = logging.getLogger(__name__)

# Internal tags for view elements (S105: these are UI tags, not passwords)
_EXPORT_FILE_DIALOG = "export_file_dialog"
_IMPORT_FILE_DIALOG = "import_file_dialog"
_EXPORT_PASSWORD = "export_password_input"
_EXPORT_CONFIRM_PASSWORD = "export_confirm_password_input"
_EXPORT_INCLUDE_REPOS = "export_include_repos"
_IMPORT_PASSWORD = "import_password_input"
_IMPORT_MODE = "import_mode_combo"
_IMPORT_CONFLICT = "import_conflict_combo"
_STATUS_TEXT = "import_export_status_text"
_RESULT_SECTION = "import_export_result_section"

# Container reference for service access
_container: ServiceContainer | None = None

# File path storage for export/import operations
_pending_export_path: Path | None = None
_pending_import_path: Path | None = None


def create_import_export_view(container: ServiceContainer) -> int:
    """Create the import/export view content.

    Args:
        container: Service container for accessing managers.

    Returns:
        View group tag ID.
    """
    global _container
    _container = container

    logger.debug("Creating import/export view")

    # Clean up existing view if present
    if dpg.does_item_exist(TAGS["view_import"]):
        dpg.delete_item(TAGS["view_import"])

    with dpg.group(tag=TAGS["view_import"], show=False) as view:
        # Section header
        dpg.add_text(
            "IMPORT / EXPORT",
            color=COLORS["accent_cyan"],
        )
        dpg.add_separator()
        dpg.add_spacer(height=PADDING_MEDIUM)

        # Scrollable content area
        with dpg.child_window(height=-1, border=False):
            # Export Section
            _create_export_section()

            dpg.add_spacer(height=PADDING_LARGE * 2)

            # Import Section
            _create_import_section()

            dpg.add_spacer(height=PADDING_LARGE)

            # Result/Status Section
            with dpg.group(tag=_RESULT_SECTION, show=False):
                dpg.add_separator()
                dpg.add_spacer(height=PADDING_SMALL)
                dpg.add_text(
                    "",
                    tag=_STATUS_TEXT,
                    color=COLORS["text_primary"],
                    wrap=500,
                )

    # Create file dialogs
    _create_file_dialogs()

    logger.debug("Import/export view created")
    return view


def _create_export_section() -> None:
    """Create the export section of the view."""
    dpg.add_text(
        "EXPORT PROFILES",
        color=COLORS["accent_cyan"],
    )
    dpg.add_separator()
    dpg.add_spacer(height=PADDING_SMALL)

    dpg.add_text(
        "Export your profiles to an encrypted backup file (.gps).",
        color=COLORS["text_secondary"],
    )
    dpg.add_spacer(height=PADDING_MEDIUM)

    # Archive password
    dpg.add_text(
        "Archive Password *",
        color=COLORS["text_primary"],
    )
    dpg.add_input_text(
        tag=_EXPORT_PASSWORD,
        width=300,
        password=True,
        hint="Password to encrypt the archive",
    )

    dpg.add_spacer(height=PADDING_SMALL)

    # Confirm password
    dpg.add_text(
        "Confirm Password *",
        color=COLORS["text_primary"],
    )
    dpg.add_input_text(
        tag=_EXPORT_CONFIRM_PASSWORD,
        width=300,
        password=True,
        hint="Confirm the archive password",
    )

    dpg.add_spacer(height=PADDING_MEDIUM)

    # Include repositories option
    dpg.add_checkbox(
        tag=_EXPORT_INCLUDE_REPOS,
        label="Include repository assignments",
        default_value=True,
    )
    dpg.add_text(
        "Export which profiles are assigned to which repositories",
        color=COLORS["text_disabled"],
    )

    dpg.add_spacer(height=PADDING_MEDIUM)

    # Export button
    dpg.add_button(
        label="Export Profiles",
        callback=_on_export_click,
        width=150,
    )


def _create_import_section() -> None:
    """Create the import section of the view."""
    dpg.add_text(
        "IMPORT PROFILES",
        color=COLORS["accent_cyan"],
    )
    dpg.add_separator()
    dpg.add_spacer(height=PADDING_SMALL)

    dpg.add_text(
        "Import profiles from a backup file (.gps).",
        color=COLORS["text_secondary"],
    )
    dpg.add_spacer(height=PADDING_MEDIUM)

    # Archive password
    dpg.add_text(
        "Archive Password *",
        color=COLORS["text_primary"],
    )
    dpg.add_input_text(
        tag=_IMPORT_PASSWORD,
        width=300,
        password=True,
        hint="Password used when exporting",
    )

    dpg.add_spacer(height=PADDING_MEDIUM)

    # Import mode
    with dpg.group(horizontal=True):
        dpg.add_text(
            "Import Mode:",
            color=COLORS["text_primary"],
        )
        dpg.add_combo(
            tag=_IMPORT_MODE,
            items=["Merge", "Replace"],
            default_value="Merge",
            width=150,
        )

    dpg.add_text(
        "Merge: Add to existing profiles. Replace: Delete all existing first.",
        color=COLORS["text_disabled"],
    )

    dpg.add_spacer(height=PADDING_SMALL)

    # Conflict resolution
    with dpg.group(horizontal=True):
        dpg.add_text(
            "On Conflict:",
            color=COLORS["text_primary"],
        )
        dpg.add_combo(
            tag=_IMPORT_CONFLICT,
            items=["Rename", "Skip", "Overwrite"],
            default_value="Rename",
            width=150,
        )

    dpg.add_text(
        "How to handle profiles with the same name as existing ones",
        color=COLORS["text_disabled"],
    )

    dpg.add_spacer(height=PADDING_MEDIUM)

    # Import button
    dpg.add_button(
        label="Import Profiles",
        callback=_on_import_click,
        width=150,
    )


def _create_file_dialogs() -> None:
    """Create file browser dialogs for export and import."""
    # Export file save dialog
    if dpg.does_item_exist(_EXPORT_FILE_DIALOG):
        dpg.delete_item(_EXPORT_FILE_DIALOG)

    with dpg.file_dialog(
        tag=_EXPORT_FILE_DIALOG,
        directory_selector=False,
        show=False,
        callback=_on_export_file_selected,
        cancel_callback=lambda: None,
        width=500,
        height=400,
        default_filename="git-switch-profiles.gps",
        default_path=str(Path.home() / "Documents"),
    ):
        dpg.add_file_extension(".gps", color=COLORS["accent_cyan"])

    # Import file open dialog
    if dpg.does_item_exist(_IMPORT_FILE_DIALOG):
        dpg.delete_item(_IMPORT_FILE_DIALOG)

    with dpg.file_dialog(
        tag=_IMPORT_FILE_DIALOG,
        directory_selector=False,
        show=False,
        callback=_on_import_file_selected,
        cancel_callback=lambda: None,
        width=500,
        height=400,
        default_path=str(Path.home() / "Documents"),
    ):
        dpg.add_file_extension(".gps", color=COLORS["accent_cyan"])
        dpg.add_file_extension(".*", color=COLORS["text_secondary"])


def _on_export_click() -> None:
    """Handle Export Profiles button click."""
    logger.debug("Export button clicked")

    # Validate passwords
    password = ""
    confirm = ""

    if dpg.does_item_exist(_EXPORT_PASSWORD):
        password = dpg.get_value(_EXPORT_PASSWORD)

    if dpg.does_item_exist(_EXPORT_CONFIRM_PASSWORD):
        confirm = dpg.get_value(_EXPORT_CONFIRM_PASSWORD)

    if not password:
        _show_status("Please enter an archive password.", success=False)
        return

    if len(password) < 8:
        _show_status("Password must be at least 8 characters.", success=False)
        return

    if password != confirm:
        _show_status("Passwords do not match.", success=False)
        return

    # Show file save dialog
    if dpg.does_item_exist(_EXPORT_FILE_DIALOG):
        dpg.show_item(_EXPORT_FILE_DIALOG)


def _on_export_file_selected(_sender: int, app_data: dict[str, Any]) -> None:
    """Handle export file path selection.

    Args:
        _sender: Sender ID (unused).
        app_data: Contains 'file_path_name' key with selected path.
    """
    global _pending_export_path

    if not app_data or "file_path_name" not in app_data:
        return

    file_path = app_data["file_path_name"]
    _pending_export_path = Path(file_path)

    # Ensure .gps extension
    if _pending_export_path.suffix.lower() != ".gps":
        _pending_export_path = _pending_export_path.with_suffix(".gps")

    logger.debug(f"Export path selected: {_pending_export_path}")

    # Perform export
    _perform_export()


def _perform_export() -> None:
    """Perform the export operation."""
    global _container, _pending_export_path

    if _container is None:
        _show_status("Export failed: Service not available.", success=False)
        return

    if _pending_export_path is None:
        _show_status("Export failed: No file path selected.", success=False)
        return

    try:
        # Get password
        password = dpg.get_value(_EXPORT_PASSWORD) if dpg.does_item_exist(_EXPORT_PASSWORD) else ""

        # Get include repos option
        include_repos = (
            dpg.get_value(_EXPORT_INCLUDE_REPOS)
            if dpg.does_item_exist(_EXPORT_INCLUDE_REPOS)
            else True
        )

        # Create import/export service
        from src.core.import_export import ImportExportService

        service = ImportExportService(
            session_manager=_container.session_manager,
            crypto_service=_container.crypto_service,
            profile_manager=_container.profile_manager,
            repository_manager=_container.repository_manager,
        )

        # Perform export
        result = service.export_profiles(
            file_path=_pending_export_path,
            archive_password=password,
            profile_ids=None,  # Export all profiles
            include_repositories=include_repos,
        )

        # Clear password fields
        if dpg.does_item_exist(_EXPORT_PASSWORD):
            dpg.set_value(_EXPORT_PASSWORD, "")
        if dpg.does_item_exist(_EXPORT_CONFIRM_PASSWORD):
            dpg.set_value(_EXPORT_CONFIRM_PASSWORD, "")

        # Show success
        _show_status(
            f"Export successful!\n"
            f"Exported {result.profile_count} profiles and "
            f"{result.repository_count} repository assignments.\n"
            f"File: {result.file_path}",
            success=True,
        )

        logger.info(f"Exported {result.profile_count} profiles to {result.file_path}")

    except Exception as e:
        logger.exception("Export failed")
        _show_status(f"Export failed: {e}", success=False)

    finally:
        _pending_export_path = None


def _on_import_click() -> None:
    """Handle Import Profiles button click."""
    logger.debug("Import button clicked")

    # Validate password entered
    password = ""
    if dpg.does_item_exist(_IMPORT_PASSWORD):
        password = dpg.get_value(_IMPORT_PASSWORD)

    if not password:
        _show_status("Please enter the archive password.", success=False)
        return

    # Show file open dialog
    if dpg.does_item_exist(_IMPORT_FILE_DIALOG):
        dpg.show_item(_IMPORT_FILE_DIALOG)


def _on_import_file_selected(_sender: int, app_data: dict[str, Any]) -> None:
    """Handle import file path selection.

    Args:
        _sender: Sender ID (unused).
        app_data: Contains 'file_path_name' key with selected path.
    """
    global _pending_import_path

    if not app_data or "file_path_name" not in app_data:
        return

    file_path = app_data["file_path_name"]
    _pending_import_path = Path(file_path)

    logger.debug(f"Import path selected: {_pending_import_path}")

    # Perform import
    _perform_import()


def _perform_import() -> None:
    """Perform the import operation."""
    global _container, _pending_import_path

    if _container is None:
        _show_status("Import failed: Service not available.", success=False)
        return

    if _pending_import_path is None:
        _show_status("Import failed: No file path selected.", success=False)
        return

    if not _pending_import_path.exists():
        _show_status(f"Import failed: File not found: {_pending_import_path}", success=False)
        _pending_import_path = None
        return

    try:
        # Get password
        password = dpg.get_value(_IMPORT_PASSWORD) if dpg.does_item_exist(_IMPORT_PASSWORD) else ""

        # Get import mode
        mode_value = dpg.get_value(_IMPORT_MODE) if dpg.does_item_exist(_IMPORT_MODE) else "Merge"
        mode = "merge" if mode_value == "Merge" else "replace"

        # Get conflict resolution
        conflict_value = (
            dpg.get_value(_IMPORT_CONFLICT) if dpg.does_item_exist(_IMPORT_CONFLICT) else "Rename"
        )
        conflict_map = {"Rename": "rename", "Skip": "skip", "Overwrite": "overwrite"}
        conflict = conflict_map.get(conflict_value, "rename")

        # Create import/export service
        from src.core.import_export import ImportExportService

        service = ImportExportService(
            session_manager=_container.session_manager,
            crypto_service=_container.crypto_service,
            profile_manager=_container.profile_manager,
            repository_manager=_container.repository_manager,
        )

        # Perform import
        result = service.import_profiles(
            file_path=_pending_import_path,
            archive_password=password,
            mode=mode,
            conflict_resolution=conflict,
        )

        # Clear password field
        if dpg.does_item_exist(_IMPORT_PASSWORD):
            dpg.set_value(_IMPORT_PASSWORD, "")

        # Build result message
        messages = ["Import successful!"]
        messages.append(f"Imported {len(result.imported_profiles)} profiles.")

        if result.skipped_profiles:
            messages.append(f"Skipped: {', '.join(result.skipped_profiles)}")

        if result.renamed_profiles:
            renamed = [f"{old} -> {new}" for old, new in result.renamed_profiles.items()]
            messages.append(f"Renamed: {', '.join(renamed)}")

        if result.imported_repositories > 0:
            messages.append(f"Imported {result.imported_repositories} repository assignments.")

        _show_status("\n".join(messages), success=True)

        logger.info(f"Imported {len(result.imported_profiles)} profiles")

        # Refresh profiles view
        try:
            from src.ui.views.profiles_view import refresh_profiles

            refresh_profiles()
        except Exception:
            logger.debug("Could not refresh profiles view")

    except Exception as e:
        logger.exception("Import failed")
        error_msg = str(e)
        if "password" in error_msg.lower():
            _show_status("Import failed: Incorrect password or corrupted archive.", success=False)
        else:
            _show_status(f"Import failed: {e}", success=False)

    finally:
        _pending_import_path = None


def _show_status(message: str, success: bool = True) -> None:
    """Show status message in the result section.

    Args:
        message: Status message to display.
        success: True for success styling, False for error.
    """
    if dpg.does_item_exist(_RESULT_SECTION):
        dpg.configure_item(_RESULT_SECTION, show=True)

    if dpg.does_item_exist(_STATUS_TEXT):
        dpg.set_value(_STATUS_TEXT, message)
        color = COLORS["success"] if success else COLORS["error"]
        dpg.configure_item(_STATUS_TEXT, color=color)


def _clear_status() -> None:
    """Clear the status message."""
    if dpg.does_item_exist(_RESULT_SECTION):
        dpg.configure_item(_RESULT_SECTION, show=False)

    if dpg.does_item_exist(_STATUS_TEXT):
        dpg.set_value(_STATUS_TEXT, "")


__all__ = [
    "create_import_export_view",
]
