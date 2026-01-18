"""System tray integration for Git-Switch.

Provides quick access to profile switching via system tray icon.
Uses pystray library for Windows system tray functionality.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pystray
from PIL import Image, ImageDraw

from src.models.exceptions import ProfileNotFoundError, SessionExpiredError
from src.utils.notifications import (
    show_error_notification,
    show_lock_notification,
    show_profile_switch_notification,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from uuid import UUID

    from src.core.protocols import ProfileManagerProtocol, SessionManagerProtocol

logger = logging.getLogger(__name__)

# Application name for tray icon
APP_NAME = "Git-Switch"


class SystemTrayIcon:
    """Manages the system tray icon and context menu.

    This class provides:
    - System tray icon with context menu
    - Quick profile switching from the tray
    - Lock/unlock session management
    - Open main application window
    - Proper cleanup on exit

    Attributes:
        _session: Session manager for lock state.
        _profile_manager: Profile manager for profile operations.
        _icon: The pystray Icon instance.
    """

    def __init__(
        self,
        session_manager: SessionManagerProtocol,
        profile_manager: ProfileManagerProtocol,
        icon_path: Path | None = None,
        on_restore: Callable[[], None] | None = None,
        on_exit: Callable[[], None] | None = None,
    ) -> None:
        """Initialize system tray icon.

        Args:
            session_manager: Session manager for lock state.
            profile_manager: Profile manager for profile operations.
            icon_path: Path to tray icon file (.ico).
            on_restore: Callback when "Open Application" clicked.
            on_exit: Callback when "Exit" clicked.
        """
        self._session = session_manager
        self._profile_manager = profile_manager
        self._icon_path = icon_path
        self._on_restore_callback = on_restore
        self._on_exit_callback = on_exit

        # Load or create icon image
        icon_image = self._load_icon(icon_path)

        # Create the tray icon
        self._icon = pystray.Icon(
            name=APP_NAME,
            icon=icon_image,
            title=APP_NAME,
            menu=self._build_menu(),
        )

        # Register for auto-lock notifications
        self._session.set_lock_callback(self._on_session_locked)

        logger.debug("System tray icon initialized")

    def _load_icon(self, icon_path: Path | None) -> Image.Image:
        """Load icon from file or create a fallback icon.

        Args:
            icon_path: Path to icon file, or None for fallback.

        Returns:
            PIL Image for the tray icon.
        """
        if icon_path is not None:
            try:
                return Image.open(icon_path)
            except (FileNotFoundError, OSError) as e:
                logger.warning(f"Failed to load icon from {icon_path}: {e}")

        # Create a simple fallback icon (16x16 blue square with "G")
        return self._create_fallback_icon()

    def _create_fallback_icon(self) -> Image.Image:
        """Create a simple fallback icon.

        Returns:
            A simple 64x64 icon image.
        """
        # Create a 64x64 image with a blue background
        size = 64
        image = Image.new("RGB", (size, size), color=(66, 133, 244))

        # Draw a simple "G" letter
        draw = ImageDraw.Draw(image)
        # Draw a white circle outline
        margin = 8
        draw.ellipse(
            [margin, margin, size - margin, size - margin],
            outline="white",
            width=4,
        )
        # Draw a horizontal line for the "G"
        mid_y = size // 2
        draw.line(
            [(size // 2, mid_y), (size - margin, mid_y)],
            fill="white",
            width=4,
        )

        return image

    def _build_menu(self) -> pystray.Menu:
        """Build the context menu for the tray icon.

        Returns:
            pystray Menu with profile list and actions.
        """
        items: list[pystray.MenuItem] = []

        # Add profile submenu if session is unlocked
        if self._session.is_unlocked:
            try:
                profiles = self._profile_manager.list_profiles()

                if profiles:
                    # Add "Switch Profile" submenu header
                    items.append(
                        pystray.MenuItem(
                            "Switch Profile",
                            pystray.Menu(
                                *[
                                    pystray.MenuItem(
                                        self._format_profile_label(profile),
                                        self._make_switch_callback(profile.id),
                                        checked=lambda _item, p=profile: p.is_active,
                                    )
                                    for profile in profiles
                                ]
                            ),
                        )
                    )
                else:
                    items.append(
                        pystray.MenuItem(
                            "No profiles configured",
                            None,
                            enabled=False,
                        )
                    )

                items.append(pystray.Menu.SEPARATOR)

            except SessionExpiredError:
                logger.debug("Session expired while building menu")
                # Fall through to locked state handling
        else:
            # Session is locked
            items.append(
                pystray.MenuItem(
                    "Session Locked",
                    None,
                    enabled=False,
                )
            )
            items.append(pystray.Menu.SEPARATOR)

        # Add standard menu items
        items.append(
            pystray.MenuItem(
                "Open Application",
                self._on_open_application,
            )
        )

        # Add lock option if unlocked
        if self._session.is_unlocked:
            items.append(
                pystray.MenuItem(
                    "Lock Session",
                    lambda: self._on_lock_session(),
                )
            )

        items.append(pystray.Menu.SEPARATOR)

        items.append(
            pystray.MenuItem(
                "Exit",
                lambda: self._on_exit(),
            )
        )

        return pystray.Menu(*items)

    def _format_profile_label(self, profile: object) -> str:
        """Format a profile for menu display.

        Args:
            profile: Profile object with name and organization attributes.

        Returns:
            Formatted string for menu display.
        """
        name = getattr(profile, "name", "Unknown")
        org = getattr(profile, "organization", None)

        if org:
            return f"{name} ({org})"
        return name

    def _make_switch_callback(self, profile_id: UUID) -> Callable[[], None]:
        """Create a callback for switching to a specific profile.

        Args:
            profile_id: The profile ID to switch to.

        Returns:
            Callback function for the menu item.
        """

        def callback() -> None:
            self._on_switch_profile(profile_id)

        return callback

    def start(self) -> None:
        """Start the tray icon (runs in background thread)."""
        logger.info("Starting system tray icon")
        self._icon.run_detached()

    def stop(self) -> None:
        """Stop the tray icon."""
        if self._icon is not None:
            logger.info("Stopping system tray icon")
            try:
                self._icon.stop()
            except Exception as e:
                logger.warning(f"Error stopping tray icon: {e}")

    def update_menu(self) -> None:
        """Rebuild menu with current profile list."""
        logger.debug("Updating tray menu")
        try:
            self._icon.menu = self._build_menu()
            self._icon.update_menu()
        except Exception as e:
            logger.warning(f"Failed to update menu: {e}")

    def _on_session_locked(self) -> None:
        """Handle auto-lock callback from SessionManager."""
        logger.info("Session auto-locked, updating tray menu")
        show_lock_notification()
        self.update_menu()

    def _on_switch_profile(self, profile_id: UUID) -> None:
        """Switch to specified profile.

        Args:
            profile_id: UUID of the profile to switch to.
        """
        logger.info(f"Switching to profile {profile_id}")

        try:
            self._profile_manager.switch_profile(profile_id, scope="global")

            # Get profile details for notification
            profile = self._profile_manager.get_profile(profile_id)
            if profile is not None:
                show_profile_switch_notification(
                    profile_name=profile.name,
                    organization=getattr(profile, "organization", None),
                )

            # Refresh menu to update active checkmark
            self.update_menu()

        except SessionExpiredError as e:
            logger.warning(f"Session expired during profile switch: {e}")
            show_error_notification("Session has expired. Please unlock to continue.")
            self.update_menu()

        except ProfileNotFoundError as e:
            logger.exception("Profile not found")
            show_error_notification(f"Profile not found: {e}")

        except Exception as e:
            logger.exception("Failed to switch profile")
            show_error_notification(f"Failed to switch profile: {e}")

    def _on_open_application(self) -> None:
        """Restore main application window."""
        logger.debug("Open application requested")
        if self._on_restore_callback is not None:
            self._on_restore_callback()

    def _on_lock_session(self) -> None:
        """Lock the session."""
        logger.info("Locking session from tray")
        self._session.lock()
        self.update_menu()

    def _on_exit(self) -> None:
        """Exit the application."""
        logger.info("Exit requested from tray")
        self.stop()
        if self._on_exit_callback is not None:
            self._on_exit_callback()


__all__ = [
    "SystemTrayIcon",
]
